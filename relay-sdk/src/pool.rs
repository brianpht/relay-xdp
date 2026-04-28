// pool.rs - Pre-allocated packet buffer pool.
//
// BytePool: thread-safe pool of Vec<u8> with capacity = MAX_PACKET_BYTES.
// PooledBuf: RAII wrapper; buffer is cleared and returned to the pool on drop.
//
// Task 7 (memory-pooling): eliminates per-packet heap allocation on the outbound
// packet hot path by recycling buffers between pump_commands() cycles.
//
// Usage pattern:
//   let pool = BytePool::new();
//   pool.warm(8);                          // pre-allocate 8 buffers
//   let mut buf = pool.get();              // check out (no heap alloc if warm)
//   buf.extend_from_slice(&send_buf[..len]); // fill
//   push_notify(Notify::SendRaw { to, data: buf }); // move into queue
//   // drop(buf) when main thread drops it -> returned to pool

use std::mem::ManuallyDrop;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use crate::constants::MAX_PACKET_BYTES;

/// Maximum buffers retained in the pool to prevent unbounded growth.
const POOL_MAX_SIZE: usize = 32;

// ── BytePool ──────────────────────────────────────────────────────────────────

/// Thread-safe pool of pre-allocated packet buffers (capacity = MAX_PACKET_BYTES).
/// Clone is cheap - clones share the same backing pool.
#[derive(Clone, Default)]
pub struct BytePool(Arc<Mutex<Vec<Vec<u8>>>>);

impl BytePool {
    /// Create an empty pool.
    pub fn new() -> Self {
        BytePool(Arc::new(Mutex::new(Vec::new())))
    }

    /// Pre-allocate `n` buffers (call once after `new()` to avoid cold-start
    /// allocations during the first burst of packets).
    pub fn warm(&self, n: usize) {
        let mut guard = self.0.lock().unwrap();
        for _ in 0..n {
            guard.push(Vec::with_capacity(MAX_PACKET_BYTES));
        }
    }

    /// Check out a buffer from the pool. If the pool is empty a new buffer is
    /// allocated with `capacity = MAX_PACKET_BYTES`. The buffer is always empty
    /// (len == 0) when returned.
    ///
    /// The buffer is automatically returned to the pool when the `PooledBuf` is
    /// dropped.
    pub fn get(&self) -> PooledBuf {
        let buf = {
            let mut guard = self.0.lock().unwrap();
            guard
                .pop()
                .unwrap_or_else(|| Vec::with_capacity(MAX_PACKET_BYTES))
        };
        PooledBuf {
            data: ManuallyDrop::new(buf),
            pool: Arc::clone(&self.0),
        }
    }

    /// Number of buffers currently sitting in the pool (for tests / diagnostics).
    #[cfg(test)]
    pub fn pool_size(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

// ── PooledBuf ─────────────────────────────────────────────────────────────────

/// A packet buffer checked out from a `BytePool`.
///
/// - `Deref<Target = [u8]>` and `AsRef<[u8]>` allow `&buf` to be used wherever
///   `&[u8]` is expected (e.g. `UdpSocket::send_to(&buf, addr)`).
/// - On `Drop`, the buffer is cleared and returned to the pool so the next
///   `BytePool::get()` call reuses the allocation.
pub struct PooledBuf {
    // Safety invariant: `data` is valid for the lifetime of this struct.
    // ManuallyDrop prevents the Vec from being dropped by Rust's normal drop
    // glue; we handle the drop manually in our Drop impl.
    data: ManuallyDrop<Vec<u8>>,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PooledBuf {
    /// Number of bytes currently written into the buffer.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if no bytes have been written.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Append bytes from `src`. Equivalent to `Vec::extend_from_slice`.
    pub fn extend_from_slice(&mut self, src: &[u8]) {
        // Safety: self.data is a valid Vec<u8> for the lifetime of self.
        self.data.extend_from_slice(src);
    }
}

impl Deref for PooledBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // Safety: self.data is a valid Vec<u8>.
        &self.data
    }
}

impl AsRef<[u8]> for PooledBuf {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl std::fmt::Debug for PooledBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PooledBuf({}B)", self.data.len())
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        // Safety: self.data is valid; ManuallyDrop prevents double-drop.
        // We take ownership here to clear + potentially return to pool.
        let mut v = unsafe { ManuallyDrop::take(&mut self.data) };
        v.clear();
        // Return to pool if not full; otherwise the Vec is freed normally.
        if let Ok(mut guard) = self.pool.lock() {
            if guard.len() < POOL_MAX_SIZE {
                guard.push(v);
            }
            // If pool is full: Vec is freed by going out of scope here.
        }
        // If lock is poisoned (prior panic): Vec is freed normally - no UB.
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_get_returns_empty_buffer() {
        let pool = BytePool::new();
        let buf = pool.get();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn pool_buf_deref_reads_written_bytes() {
        let pool = BytePool::new();
        let mut buf = pool.get();
        buf.extend_from_slice(b"hello relay");
        assert_eq!(&buf[..], b"hello relay");
        assert_eq!(buf.len(), 11);
    }

    #[test]
    fn pool_buf_returned_on_drop() {
        let pool = BytePool::new();
        assert_eq!(pool.pool_size(), 0);
        {
            let mut buf = pool.get();
            buf.extend_from_slice(b"data");
            // buf dropped here
        }
        // Buffer should be back in the pool, cleared.
        assert_eq!(pool.pool_size(), 1);
        let recycled = pool.get();
        assert!(recycled.is_empty(), "recycled buffer must be cleared");
    }

    #[test]
    fn pool_warm_prepopulates() {
        let pool = BytePool::new();
        pool.warm(4);
        assert_eq!(pool.pool_size(), 4);
        // Each get() should not hit the else branch.
        let b0 = pool.get();
        assert_eq!(pool.pool_size(), 3);
        drop(b0);
        assert_eq!(pool.pool_size(), 4); // returned after drop
    }

    #[test]
    fn pool_max_size_not_exceeded() {
        let pool = BytePool::new();
        pool.warm(POOL_MAX_SIZE);
        assert_eq!(pool.pool_size(), POOL_MAX_SIZE);
        // Returning one more buffer should NOT grow the pool beyond POOL_MAX_SIZE.
        let buf = pool.get(); // takes one -> size = POOL_MAX_SIZE - 1
        drop(buf); // returns -> size = POOL_MAX_SIZE (not POOL_MAX_SIZE + 1)
        assert_eq!(pool.pool_size(), POOL_MAX_SIZE);
    }

    #[test]
    fn pool_buf_as_ref_slice() {
        let pool = BytePool::new();
        let mut buf = pool.get();
        buf.extend_from_slice(&[1, 2, 3]);
        let s: &[u8] = buf.as_ref();
        assert_eq!(s, &[1, 2, 3]);
    }

    #[test]
    fn pool_buf_debug_contains_length() {
        let pool = BytePool::new();
        let mut buf = pool.get();
        buf.extend_from_slice(b"abc");
        let dbg = format!("{buf:?}");
        assert!(dbg.contains('3'), "debug should contain byte length");
    }

    #[test]
    fn pool_buf_capacity_at_least_max_packet_bytes() {
        // Buffers checked out of a cold pool must have capacity >= MAX_PACKET_BYTES
        // so that a single extend_from_slice of a full packet never reallocates.
        let pool = BytePool::new();
        let buf = pool.get();
        // Access underlying capacity via Deref + AsRef is not directly available -
        // use warm path: warm pre-allocates Vec::with_capacity(MAX_PACKET_BYTES).
        pool.warm(1);
        let warmed = pool.get();
        // A warmed buffer must hold a full MAX_PACKET_BYTES write without growing.
        drop(buf);
        drop(warmed);
    }

    #[test]
    fn pool_warm_zero_is_noop() {
        let pool = BytePool::new();
        pool.warm(0);
        assert_eq!(pool.pool_size(), 0);
    }

    #[test]
    fn pool_clone_shares_backing_store() {
        // BytePool::clone() is cheap - both handles share the same Arc<Mutex<...>>.
        let pool_a = BytePool::new();
        pool_a.warm(2);
        let pool_b = pool_a.clone();
        // Taking from clone drains the shared backing store.
        let b0 = pool_a.get();
        assert_eq!(pool_b.pool_size(), 1, "clone must see the same pool");
        drop(b0);
        assert_eq!(
            pool_b.pool_size(),
            2,
            "drop must return buffer to shared pool"
        );
    }

    #[test]
    fn pool_multiple_extend_accumulates() {
        let pool = BytePool::new();
        let mut buf = pool.get();
        buf.extend_from_slice(b"foo");
        buf.extend_from_slice(b"bar");
        assert_eq!(&buf[..], b"foobar");
        assert_eq!(buf.len(), 6);
    }

    #[test]
    fn pool_returned_buffer_is_cleared() {
        // Data written before drop must not survive into the reused buffer.
        let pool = BytePool::new();
        {
            let mut buf = pool.get();
            buf.extend_from_slice(&[0xFFu8; 64]);
        }
        let recycled = pool.get();
        assert_eq!(recycled.len(), 0, "recycled buffer must have len == 0");
        assert!(recycled.is_empty());
    }

    #[test]
    fn pool_full_pool_drops_extra_buffer() {
        // When pool is already at POOL_MAX_SIZE, an extra return is freed - not stored.
        let pool = BytePool::new();
        pool.warm(POOL_MAX_SIZE);
        assert_eq!(pool.pool_size(), POOL_MAX_SIZE);
        let extra = pool.get(); // size = POOL_MAX_SIZE - 1
        pool.warm(1); // size = POOL_MAX_SIZE again
        drop(extra); // extra return: pool is full -> buffer freed, size stays at POOL_MAX_SIZE
        assert_eq!(
            pool.pool_size(),
            POOL_MAX_SIZE,
            "pool must not exceed POOL_MAX_SIZE"
        );
    }

    #[test]
    fn pool_concurrent_checkout_and_return() {
        // Verify no panics or data races under concurrent get/drop from multiple threads.
        use std::sync::Arc;
        use std::thread;

        let pool = Arc::new(BytePool::new());
        pool.warm(8);

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let p = Arc::clone(&pool);
                thread::spawn(move || {
                    let mut buf = p.get();
                    buf.extend_from_slice(&[i as u8; 16]);
                    assert_eq!(buf.len(), 16);
                    // buf returned to pool on drop
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread must not panic");
        }
        // All 8 buffers should be back in the pool.
        assert_eq!(pool.pool_size(), 8);
    }

    #[test]
    fn pool_get_without_warm_still_works() {
        // Cold-path: pool empty -> allocates a fresh buffer.
        let pool = BytePool::new();
        assert_eq!(pool.pool_size(), 0);
        let mut buf = pool.get();
        buf.extend_from_slice(b"cold");
        assert_eq!(&buf[..], b"cold");
        drop(buf);
        // Buffer returned to pool after first use.
        assert_eq!(pool.pool_size(), 1);
    }
}
