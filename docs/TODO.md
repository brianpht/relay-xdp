# Performance TODO

> Full-stack performance audit of the relay-xdp codebase.
> Items ordered by impact: eBPF hot path (per-packet) first, then userspace (per-second).
>
> **Legend**: 🔴 High impact · 🟡 Medium impact · 🟢 Low impact · ⚪ Needs profiling first

---

## Table of Contents

- [A. eBPF Data Plane (Per-Packet Hot Path)](#a-ebpf-data-plane-per-packet-hot-path)
- [B. Userspace Control Plane (Per-Second)](#b-userspace-control-plane-per-second)
- [C. Kernel Module](#c-kernel-module)
- [D. Cross-Cutting / Structural](#d-cross-cutting--structural)
- [Priority Matrix](#priority-matrix)
- [Recommended Execution Order](#recommended-execution-order)

---

## A. eBPF Data Plane (Per-Packet Hot Path)

### A1. 🔴 Eliminate redundant SHA-256 in `verify_ping_token`

- **File**: `relay-xdp-ebpf/src/main.rs` lines 514–558
- **Savings**: ~500ns per ping packet from internal relays
- **Difficulty**: Low
- **Risk**: Low

Currently always tries `relay_public_address` first, then falls back to
`relay_internal_address` on failure. Each `bpf_relay_sha256` kfunc call
costs ~200–500ns. When the ping arrives on the internal address, the first
SHA-256 always fails - wasting one full kfunc call.

**Fix**: Check `(*ip).daddr` against `(*config).relay_internal_address`
before choosing which address to try first. Most packets will verify on the
first attempt.

```
Before: always public → internal (2 SHA-256 on internal miss)
After:  match daddr → try matching first (1 SHA-256 in common case)
```

---

### A2. 🟡 Widen `bytes_equal` to u64-word comparison

- **File**: `relay-xdp-ebpf/src/main.rs` lines 186–195
- **Savings**: ~20ns per packet with crypto verify (8× fewer iterations)
- **Difficulty**: Low
- **Risk**: Low

The 32-byte SHA-256 hash comparison currently runs byte-by-byte (32
iterations). Since both buffers are stack-allocated and naturally aligned,
compare as `*const u64` - 4 word comparisons instead of 32 byte
comparisons.

```rust
// Before: 32 iterations
while i < n { if *a.add(i) != *b.add(i) { return false; } i += 1; }

// After: 4 iterations for 32-byte compare
unsafe fn bytes_equal_32(a: *const u8, b: *const u8) -> bool {
    let a = a as *const u64;
    let b = b as *const u64;
    (*a.add(0) == *b.add(0))
        && (*a.add(1) == *b.add(1))
        && (*a.add(2) == *b.add(2))
        && (*a.add(3) == *b.add(3))
}
```

Keep the original `bytes_equal` for the 8-byte comparison in
`verify_session_header`.

---

### A3. 🟡 Widen `copy_bytes` for 32-byte key copies

- **File**: `relay-xdp-ebpf/src/main.rs` lines 199–205
- **Savings**: ~15ns per packet with crypto (8× fewer iterations for 32B)
- **Difficulty**: Low
- **Risk**: Low

`copy_bytes` is used for both 6-byte MAC addresses (fine as-is) and 32-byte
keys (`session_private_key`, `ping_key`, `nonce`). Add a specialized
`copy_bytes_32` that writes 4 × u64 words.

```rust
#[inline(always)]
unsafe fn copy_bytes_32(src: *const u8, dst: *mut u8) {
    let s = src as *const u64;
    let d = dst as *mut u64;
    *d.add(0) = *s.add(0);
    *d.add(1) = *s.add(1);
    *d.add(2) = *s.add(2);
    *d.add(3) = *s.add(3);
}
```

---

### A4. 🟢 Use `get_ptr` instead of `get` for `relay_map` presence checks

- **File**: `relay-xdp-ebpf/src/main.rs` lines 661, 868
- **Savings**: Avoids copying u64 value on each relay ping/pong lookup
- **Difficulty**: Low
- **Risk**: Low

`relay_map.get(&relay_key)` returns an owned copy of the value. The code
only checks `.is_none()` and never reads the value. Switch to
`relay_map.get_ptr(&relay_key)` to avoid the unnecessary copy.

---

### A5. 🟢 Remove redundant bounds check in exact-size validation

- **File**: `relay-xdp-ebpf/src/main.rs` - 8 occurrences
- **Lines**: 646, 720, 798, 862, 1001, 1283, 1349, 1413
- **Savings**: 1 fewer comparison per packet handler entry
- **Difficulty**: Low
- **Risk**: Low

The pattern `expected_end > data_end || expected_end != data_end` is
logically equivalent to `expected_end != data_end`. The `>` check is
redundant when combined with `!=`.

```rust
// Before (8 occurrences)
if expected_end > data_end || expected_end != data_end {

// After
if expected_end != data_end {
```

---

### A6. 🟢 Optimize MAC swap in `relay_reflect_packet`

- **File**: `relay-xdp-ebpf/src/main.rs` lines 376–379
- **Savings**: ~6 bytes less copy per reflected packet
- **Difficulty**: Low
- **Risk**: Low

Currently does a 3-way swap with a temp buffer:
```
h_source → tmp (6B copy)
h_dest   → h_source (6B copy)
tmp      → h_dest (6B copy)
```

Can be reduced to 2 copies with a 12-byte stack buffer:
```rust
let mut tmp = [0u8; 12];
copy_bytes(eth.h_dest.as_ptr(), tmp.as_mut_ptr(), 12);  // save both
copy_bytes(tmp.as_ptr().add(6), eth.h_source.as_mut_ptr(), 6); // old h_source → h_dest
// actually: just copy the original dest(6B) first, then source
```

Or better: read both as two u32+u16 pairs and swap via registers.

---

### A7. ⚪ Cache destination MAC in `SessionData` to skip `whitelist_map` lookup

- **File**: `relay-xdp-ebpf/src/main.rs` lines 424–432
- **Savings**: ~100ns per forwarded session packet (eliminates 1 hash map lookup)
- **Difficulty**: High
- **Risk**: High (schema change across all 3 layers)

Every `relay_redirect_packet` does a `whitelist_map.get_ptr()` lookup to
find the destination MAC address. For session packets (types 2–8) that are
already past the whitelist check, this is an extra ~100ns map lookup on the
hot path.

**Potential fix**: Store `dest_mac: [u8; 6]` and `source_mac: [u8; 6]` in
`SessionData`. Populate from whitelist at session creation. Eliminates the
per-packet whitelist lookup for forwarded packets.

**Trade-off**: Increases `SessionData` by 12 bytes (104B → 116B), affects
BPF map schema, and MAC addresses could become stale if the remote host
changes network path. **Only implement after profiling confirms this lookup
is a bottleneck.**

---

## B. Userspace Control Plane (Per-Second)

### B1. 🔴 Reduce BPF mutex hold time in `update_timeouts`

- **File**: `relay-xdp/src/main_thread.rs` lines 537–589
- **Savings**: Eliminates ping thread stalls during session scan
- **Difficulty**: Medium
- **Risk**: Medium

`bpf.lock().unwrap()` holds the mutex while iterating up to 200K sessions +
200K whitelist entries. During this time the ping thread is **completely
blocked** - it cannot send pings, receive pongs, or update `relay_map`.
This causes periodic jitter spikes in RTT measurements.

**Fix option 1** - Split lock acquisition:
```
Phase 1: lock → iterate session_map → collect expired keys → unlock
Phase 2: lock → batch delete expired sessions → unlock
Phase 3: lock → iterate whitelist_map → collect expired keys → unlock
Phase 4: lock → batch delete expired whitelist → unlock
```

**Fix option 2** - Separate mutexes per map:
Replace single `Arc<Mutex<BpfContext>>` with per-map accessors that don't
require the global lock. The ping thread only needs `relay_map`; the main
thread needs `state_map`, `stats_map`, `session_map`, `whitelist_map`.

---

### B2. 🔴 Eliminate per-ping heap allocation in `send_ping`

- **File**: `relay-xdp/src/ping_thread.rs` line 228
- **Savings**: ~10,240 alloc+free/sec → 0 (with 1024 relays at 10 Hz)
- **Difficulty**: Low
- **Risk**: Low

`Vec::with_capacity(256)` allocates heap memory on every ping sent. With
1024 relays at 10 Hz, this is ~10K malloc/free pairs per second.

**Fix**: Use a stack buffer `[u8; 256]` and track length manually, or keep
a single `Vec` as a field on `PingThread` and `.clear()` + reuse each call.

```rust
// Option A: stack buffer
let mut packet_data = [0u8; 256];
let mut len = 0usize;
packet_data[len] = RELAY_PING_PACKET;
len += 1;
// ... fill packet_data[1..18] with zeros, etc.

// Option B: reusable field
// In PingThread struct: ping_buf: Vec<u8>
self.ping_buf.clear();
self.ping_buf.push(RELAY_PING_PACKET);
```

---

### B3. 🟡 Replace O(N) linear scan in `process_pong` with HashMap

- **File**: `relay-xdp/src/manager.rs` lines 141–148
- **Savings**: O(1) lookup instead of O(N) per pong (N = up to 1024 relays)
- **Difficulty**: Low
- **Risk**: Low

Every received pong triggers a linear scan through all relay addresses and
ports to find the matching relay index. With 1024 relays receiving pongs at
10 Hz, this is ~10K × 1024 comparisons/sec.

**Fix**: Maintain a `HashMap<(u32, u16), usize>` mapping `(address, port)`
→ relay index. Rebuild on relay set changes (which happen rarely).

```rust
pub struct RelayManager {
    // ...existing fields...
    relay_index: HashMap<(u32, u16), usize>,
}

pub fn process_pong(&mut self, from_address: u32, from_port: u16, sequence: u64) -> bool {
    if let Some(&idx) = self.relay_index.get(&(from_address, from_port)) {
        self.relay_ping_history[idx].pong_received(sequence, platform::time());
        return true;
    }
    false
}
```

---

### B4. 🟡 Combine 3 passes into 1 in `PingHistory::get_stats`

- **File**: `relay-xdp/src/ping_history.rs` lines 65–123
- **Savings**: 3× fewer cache traversals of the 64-entry ring buffer
- **Difficulty**: Low
- **Risk**: Low

Currently iterates the ring buffer 3 separate times: once for packet loss,
once for min RTT, once for jitter. These can be combined into a single pass.

```rust
pub fn get_stats(&self, start: f64, end: f64, ping_safety: f64) -> PingHistoryStats {
    let mut num_sent = 0u32;
    let mut num_recv = 0u32;
    let mut min_rtt = f64::MAX;
    let mut rtt_sum = 0.0f64;
    let mut rtt_count = 0u32;

    for entry in &self.entries {
        if entry.time_ping_sent < start || entry.time_ping_sent > end {
            continue;
        }
        let has_pong = entry.time_pong_received > entry.time_ping_sent;
        if entry.time_ping_sent <= end - ping_safety {
            num_sent += 1;
            if has_pong { num_recv += 1; }
        }
        if has_pong {
            let rtt = entry.time_pong_received - entry.time_ping_sent;
            if rtt < min_rtt { min_rtt = rtt; }
            rtt_sum += rtt;
            rtt_count += 1;
        }
    }

    // Jitter = avg(rtt - min_rtt) = avg(rtt) - min_rtt
    let packet_loss = if num_sent > 0 { 100.0 * (1.0 - num_recv as f64 / num_sent as f64) } else { 100.0 };
    let rtt_ms = if min_rtt < f64::MAX { 1000.0 * min_rtt } else { 0.0 };
    let jitter_ms = if rtt_count > 0 && min_rtt < f64::MAX {
        1000.0 * (rtt_sum / rtt_count as f64 - min_rtt)
    } else { 0.0 };

    PingHistoryStats { rtt: rtt_ms as f32, jitter: jitter_ms as f32, packet_loss: packet_loss as f32 }
}
```

---

### B5. 🟡 Reuse `PingStats` vectors across calls

- **File**: `relay-xdp/src/manager.rs` lines 152–171
- **Savings**: Eliminates 4 Vec allocations × 10 calls/sec
- **Difficulty**: Low
- **Risk**: Low

`get_ping_stats()` allocates 4 new `Vec`s (ids, rtt, jitter, loss) on every
call (10 times/second). Store a pre-allocated `PingStats` in
`RelayManager` and `.clear()` + reuse.

---

### B6. 🟡 Replace O(n²) relay delta with HashSet

- **File**: `relay-xdp/src/main_thread.rs` lines 486–516
- **Savings**: O(n) instead of O(n²) for relay set diff (n = up to 1024)
- **Difficulty**: Low
- **Risk**: Low

Current code uses nested `iter().any()` to compute new/deleted relays.
With 1024 relays this is ~1M comparisons worst case.

```rust
// Before: O(n²)
for i in 0..relay_ping_set.num_relays {
    let found = self.relay_ping_set.id.iter().any(|&id| id == relay_ping_set.id[i]);
    // ...
}

// After: O(n)
let old_ids: HashSet<u64> = self.relay_ping_set.id.iter().copied().collect();
for i in 0..relay_ping_set.num_relays {
    if !old_ids.contains(&relay_ping_set.id[i]) {
        new_relays.push(/* ... */);
    }
}
```

---

### B7. 🟢 Reuse `update_data` Vec across update cycles

- **File**: `relay-xdp/src/main_thread.rs` line 271
- **Savings**: 1 fewer heap allocation per second
- **Difficulty**: Low
- **Risk**: Low

`Vec::with_capacity(4096)` is allocated every 1 Hz update cycle. Store as a
field on `MainThread`, `.clear()` and reuse.

---

### B8. 🟢 Add `Reader::skip(n)` to avoid allocating discarded data

- **File**: `relay-xdp/src/encoding.rs`
- **Savings**: 1 fewer Vec allocation per update cycle (111 bytes)
- **Difficulty**: Low
- **Risk**: Low

`read_bytes(RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES)` at line 456 of
`main_thread.rs` allocates a `Vec` for a dummy route token that is
immediately discarded.

```rust
// Add to Reader:
pub fn skip(&mut self, n: usize) -> Result<(), ReadError> {
    self.ensure(n)?;
    self.pos += n;
    Ok(())
}

// Usage:
r.skip(RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES).context("failed to skip dummy route token")?;
```

---

### B9. 🟢 Increase ping socket buffer sizes

- **File**: `relay-xdp/src/ping_thread.rs` lines 53–54
- **Savings**: Prevents kernel packet drops at high relay counts
- **Difficulty**: Low
- **Risk**: Low

Current: `100 * 1024` (100 KB) send + receive buffers. At 1024 relays ×
10 Hz × ~80 bytes/packet ≈ 800 KB/sec of ping traffic. Recommend
increasing to `512 * 1024` or `1024 * 1024` to handle burst scenarios.

---

### B10. 🟢 Verify HTTP connection reuse with `ureq`

- **File**: `relay-xdp/src/main_thread.rs` line 360
- **Savings**: ~1 TCP RTT + possible TLS handshake per update cycle
- **Difficulty**: Low
- **Risk**: Low

`ureq::post()` may create a new TCP connection on each 1 Hz update. Use a
persistent `ureq::Agent` stored as a field to ensure connection keep-alive.

```rust
// In MainThread::new():
let http_agent = ureq::Agent::new_with_config(
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
);

// In update():
let response = self.http_agent.post(&update_url)
    .header("Content-Type", "application/octet-stream")
    .send(&update_data)?;
```

---

## C. Kernel Module

### C1. ⚪ Consider per-CPU pre-allocated `shash_desc`

- **File**: `module/relay_module.c` lines 140–146
- **Savings**: Eliminates stack allocation of `shash_desc` per kfunc call (~10ns)
- **Difficulty**: Medium
- **Risk**: Low

`SHASH_DESC_ON_STACK` allocates the shash descriptor on the kernel stack
every time `sha256_hash()` is called. Pre-allocating per-CPU descriptors
would eliminate this overhead.

This is a standard kernel pattern and the savings are minimal (~10ns per
call). **Only implement if profiling with `bpf_ktime_get_ns()` shows
SHA-256 kfunc latency exceeding the 500ns budget.**

---

## D. Cross-Cutting / Structural

### D1. ⚪ Split `RelayStats` into hot/cold counter arrays

- **File**: `relay-xdp-common/src/lib.rs` lines 219–223
- **Savings**: Reduces per-CPU stats read from 1200B to ~160B per second
- **Difficulty**: High
- **Risk**: High (BPF map schema change → rebuild all 3 layers)

`RelayStats` holds 150 × u64 = 1200 bytes. Userspace reads this per-CPU
array every second (1200B × num_CPUs). Only ~20 counters are actively used
for reporting.

**Potential fix**: Split into `RelayStatsHot` (~20 counters, 160B) and
`RelayStatsCold` (~130 counters, 1040B). Read hot counters every second,
cold counters on demand.

**Only implement if profiling shows stats_map read is a bottleneck.** The
schema change affects `relay-xdp-common`, `relay-xdp-ebpf`, and
`relay-xdp` - all three must be rebuilt and tested.

---

### D2. 🟢 Add `bpf_ktime_get_ns()` instrumentation for profiling

- **File**: `relay-xdp-ebpf/src/main.rs`
- **Purpose**: Measure actual per-packet latency to prioritize optimizations
- **Difficulty**: Low (behind a compile-time feature flag)
- **Risk**: Low (only enabled during profiling)

Add optional timing around the hot path stages:
```
t0 = bpf_ktime_get_ns()  // after parse
t1 = bpf_ktime_get_ns()  // after DDoS filter
t2 = bpf_ktime_get_ns()  // after map lookup
t3 = bpf_ktime_get_ns()  // after crypto
t4 = bpf_ktime_get_ns()  // after header rewrite
```

Store deltas in spare `stats_map` counter slots. This enables data-driven
decisions on which optimizations to prioritize.

---

## Priority Matrix

| ID | Location | Est. Savings | Difficulty | Risk | Batch |
|----|----------|-------------|------------|------|-------|
| A1 | eBPF `verify_ping_token` | ~500ns/ping pkt | Low | Low | 1 |
| A2 | eBPF `bytes_equal` | ~20ns/crypto pkt | Low | Low | 1 |
| A3 | eBPF `copy_bytes` | ~15ns/crypto pkt | Low | Low | 1 |
| A4 | eBPF `relay_map.get` | minor copy avoid | Low | Low | 1 |
| A5 | eBPF bounds check | 1 cmp × 8 handlers | Low | Low | 1 |
| A6 | eBPF MAC swap | ~6B less copy | Low | Low | 1 |
| A7 | eBPF whitelist cache | ~100ns/fwd pkt | High | High | 3 |
| B1 | Userspace mutex hold | ping jitter fix | Medium | Medium | 2 |
| B2 | Ping thread alloc | ~10K alloc/s → 0 | Low | Low | 1 |
| B3 | `process_pong` O(N) | O(1) lookup | Low | Low | 1 |
| B4 | `get_stats` 3-pass | 3× less iteration | Low | Low | 1 |
| B5 | `PingStats` reuse | 40 Vec alloc/s → 0 | Low | Low | 1 |
| B6 | Relay delta O(n²) | O(n) diff | Low | Low | 1 |
| B7 | `update_data` reuse | 1 alloc/s → 0 | Low | Low | 1 |
| B8 | `Reader::skip` | 1 alloc/s → 0 | Low | Low | 1 |
| B9 | Socket buffer size | prevent drops | Low | Low | 2 |
| B10 | HTTP keep-alive | ~1 RTT/s saved | Low | Low | 2 |
| C1 | Kernel shash_desc | ~10ns/crypto call | Medium | Low | 3 |
| D1 | Stats hot/cold split | 1200B → 160B read | High | High | 3 |
| D2 | BPF timing probes | enables profiling | Low | Low | 1 |

---

## Recommended Execution Order

### Batch 1 - Low-hanging fruit (no schema changes, low risk)

All items are independent and can be done in any order.

- [x] A1 - Smart address selection in `verify_ping_token`
- [x] A2 - `bytes_equal_32` u64-word comparison
- [x] A3 - `copy_bytes_32` u64-word copy
- [x] A4 - `relay_map.get_ptr` instead of `.get`
- [x] A5 - Remove redundant bounds checks (8 sites)
- [x] A6 - Optimize MAC swap in reflect
- [x] B2 - Stack buffer or reusable Vec in `send_ping`
- [x] B3 - HashMap index in `process_pong`
- [x] B4 - Single-pass `PingHistory::get_stats`
- [x] B5 - Reuse `PingStats` vectors
- [x] B6 - HashSet relay delta
- [x] B7 - Reuse `update_data` Vec
- [x] B8 - Add `Reader::skip`
- [x] D2 - Add profiling instrumentation

### Batch 2 - Medium effort, needs testing

- [x] B1 - Split BPF mutex hold time
- [x] B9 - Increase socket buffer sizes
- [x] B10 - HTTP connection reuse with `ureq::Agent`

### Batch 3 - Only after profiling data confirms need

- [ ] A7 - Cache MAC in SessionData (schema change)
- [ ] C1 - Per-CPU shash_desc in kernel module
- [ ] D1 - Split RelayStats hot/cold (schema change)

