//! Magic bytes and ping key rotation.
//!
//! Generates and rotates shared secrets used for DDoS filtering (magic bytes)
//! and relay-to-relay ping authentication (ping key). All relays receive the
//! same values via the RelayUpdateResponse.
//!
//! Magic bytes use a 3-value window (upcoming/current/previous) to allow
//! smooth transitions during rotation.

use std::sync::RwLock;

use crate::constants::{MAGIC_BYTES, PING_KEY_BYTES};

/// Rotation interval in seconds. Magic bytes rotate every 10 seconds;
/// the 3-value window gives relays up to 20 seconds of overlap.
const MAGIC_ROTATION_SECONDS: u64 = 10;

struct MagicState {
    upcoming_magic: [u8; MAGIC_BYTES],
    current_magic: [u8; MAGIC_BYTES],
    previous_magic: [u8; MAGIC_BYTES],
    ping_key: [u8; PING_KEY_BYTES],
    last_rotation: u64,
}

/// Thread-safe rotating magic bytes and ping key.
pub struct MagicRotator {
    inner: RwLock<MagicState>,
}

/// Snapshot of current magic state (cheaply copyable).
#[derive(Clone, Copy)]
pub struct MagicSnapshot {
    pub upcoming_magic: [u8; MAGIC_BYTES],
    pub current_magic: [u8; MAGIC_BYTES],
    pub previous_magic: [u8; MAGIC_BYTES],
    pub ping_key: [u8; PING_KEY_BYTES],
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

impl MagicRotator {
    pub fn new() -> Self {
        MagicRotator {
            inner: RwLock::new(MagicState {
                upcoming_magic: random_bytes(),
                current_magic: random_bytes(),
                previous_magic: random_bytes(),
                ping_key: random_bytes(),
                last_rotation: now_secs(),
            }),
        }
    }

    /// Rotate magic bytes if enough time has elapsed. Called from the
    /// background update loop (every 1 second).
    pub fn rotate_if_needed(&self) {
        let now = now_secs();
        let mut inner = self.inner.write().expect("magic lock poisoned");
        if now - inner.last_rotation >= MAGIC_ROTATION_SECONDS {
            inner.previous_magic = inner.current_magic;
            inner.current_magic = inner.upcoming_magic;
            inner.upcoming_magic = random_bytes();
            inner.ping_key = random_bytes();
            inner.last_rotation = now;
            log::debug!("rotated magic bytes and ping key");
        }
    }

    /// Get a snapshot of the current magic state.
    pub fn get(&self) -> MagicSnapshot {
        let inner = self.inner.read().expect("magic lock poisoned");
        MagicSnapshot {
            upcoming_magic: inner.upcoming_magic,
            current_magic: inner.current_magic,
            previous_magic: inner.previous_magic,
            ping_key: inner.ping_key,
        }
    }
}

