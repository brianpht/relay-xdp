//! Replay protection for `/relay_update`.
//!
//! crypto_box AEAD provides integrity but not freshness. Without an
//! additional check, an attacker who captures one valid request can replay
//! it indefinitely. We defend on two axes:
//!
//!   1. Per-relay nonce LRU - reject `(relay_index, nonce_bytes)` tuples we
//!      have already accepted. The 24-byte AEAD nonce is unforgeable
//!      (tampering with it invalidates the MAC), so seeing the same nonce
//!      twice is by itself a strong replay signal.
//!   2. Payload-timestamp freshness - reject when the relay's `current_time`
//!      diverges from our wall clock by more than `CLOCK_SKEW_WINDOW_SECS`.
//!
//! See `docs/decisions/ADR-004-replay-protection-window-for-relay-update.md`
//! and `docs/sessions/2026-05-04-project-audit-plan-v2.md` P1-01.
//!
//! Memory bound: at `MAX_RELAYS = 1024` relays and `NONCE_CACHE_PER_RELAY =
//! 1024` entries, worst case is ~50-60 MB of LRU node state.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;

/// Per-relay nonce-cache capacity. At the 1 Hz `/relay_update` cadence this
/// covers ~17 minutes of traffic; an attacker would need to replay an
/// older-than-17-minutes request **after** that relay has gone silent for
/// the same window for the eviction window to open. The ADR-004 risk model
/// accepts this.
pub const NONCE_CACHE_PER_RELAY: usize = 1024;

/// Maximum allowed difference between the relay's `current_time` (inside
/// the encrypted payload) and the backend's wall clock. NTP-synced hosts
/// drift well under one second; 30 s leaves room for transient skew during
/// time-source switches.
pub const CLOCK_SKEW_WINDOW_SECS: i64 = 30;

/// Per-relay LRU keyed by the 24-byte AEAD nonce. Wrapped in a single
/// `Mutex` because the hot path is per-request and the lock is held only
/// for an O(1) LRU put/get; profiling at 1 Hz x N-relay traffic shows no
/// contention.
pub struct NonceCache {
    inner: Mutex<HashMap<usize, LruCache<[u8; 24], ()>>>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Insert `(relay_index, nonce)`. Returns `true` if the nonce was new
    /// (insert succeeded), `false` if it was already present (replay).
    pub fn insert(&self, relay_index: usize, nonce: [u8; 24]) -> bool {
        let mut map = self.inner.lock().expect("nonce cache lock poisoned");
        let cache = map.entry(relay_index).or_insert_with(|| {
            LruCache::new(NonZeroUsize::new(NONCE_CACHE_PER_RELAY).expect("non-zero const"))
        });
        if cache.contains(&nonce) {
            // Already present: refresh recency so a retry storm cannot
            // evict a legitimate older nonce.
            cache.get(&nonce);
            return false;
        }
        cache.put(nonce, ());
        true
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true if the relay-reported `current_time` is within the
/// freshness window of `now`.
pub fn is_clock_fresh(relay_current_time_secs: u64, now_secs: i64) -> bool {
    let skew = (relay_current_time_secs as i64) - now_secs;
    skew.abs() <= CLOCK_SKEW_WINDOW_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_first_insert_is_new() {
        let cache = NonceCache::new();
        assert!(cache.insert(0, [1u8; 24]));
    }

    #[test]
    fn nonce_second_insert_is_replay() {
        let cache = NonceCache::new();
        assert!(cache.insert(0, [1u8; 24]));
        assert!(!cache.insert(0, [1u8; 24]));
    }

    #[test]
    fn nonce_different_relay_does_not_collide() {
        let cache = NonceCache::new();
        assert!(cache.insert(0, [1u8; 24]));
        // Same nonce, different relay - new insert.
        assert!(cache.insert(1, [1u8; 24]));
    }

    #[test]
    fn nonce_eviction_past_capacity_allows_old_nonce() {
        let cache = NonceCache::new();
        // Fill capacity with distinct nonces.
        for i in 0..NONCE_CACHE_PER_RELAY {
            let mut nonce = [0u8; 24];
            nonce[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(cache.insert(0, nonce), "fresh nonce {} rejected", i);
        }
        // The first nonce is still in the cache (just barely).
        let first = {
            let mut n = [0u8; 24];
            n[0..8].copy_from_slice(&0u64.to_le_bytes());
            n
        };
        assert!(!cache.insert(0, first), "in-cache nonce should be replay");
        // Push one more distinct nonce; now `first` should be evicted, so a
        // re-insert succeeds. Note: `cache.insert(0, first)` above also
        // touched `first`, refreshing its position; we need a *fresh* slot
        // to push and then test a different evictee.
        let mut nonce_evicting = [0u8; 24];
        nonce_evicting[0..8].copy_from_slice(&(NONCE_CACHE_PER_RELAY as u64).to_le_bytes());
        cache.insert(0, nonce_evicting);
        // The least-recently-used entry (which is now nonce 1, since 0 was
        // refreshed by the failed re-insert) should be gone.
        let mut second_oldest = [0u8; 24];
        second_oldest[0..8].copy_from_slice(&1u64.to_le_bytes());
        assert!(
            cache.insert(0, second_oldest),
            "post-eviction old nonce should be acceptable again"
        );
    }

    #[test]
    fn clock_fresh_within_window() {
        assert!(is_clock_fresh(1_000_000, 1_000_000));
        assert!(is_clock_fresh(1_000_000, 1_000_010));
        assert!(is_clock_fresh(1_000_000 + 30, 1_000_000));
        assert!(is_clock_fresh(1_000_000 - 30, 1_000_000));
    }

    #[test]
    fn clock_stale_outside_window() {
        assert!(!is_clock_fresh(1_000_000, 1_000_031));
        assert!(!is_clock_fresh(1_000_031, 1_000_000));
        assert!(!is_clock_fresh(1_000_000, 1_000_100));
    }
}
