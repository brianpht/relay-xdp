//! relay-sdk - Pure Rust SDK for game client/server connecting to relay-xdp network.
//!
//! Crate layout:
//!   mod pool      - BytePool / PooledBuf (pre-allocated packet buffer pool)
//!   mod stats     - ClientStats / ServerStats (event counters, observability)
//!   mod bitpacker  - BitWriter / BitReader (low-level bit I/O) [copied from rust-sdk]
//!   mod stream     - WriteStream / ReadStream + serialize macros [copied from rust-sdk]
//!   mod read_write - WriteBuf / ReadBuf (byte-level helpers) [copied from rust-sdk]
//!   mod platform   - OS abstractions (time, connection type, socket buffers)
//!   mod address    - Address enum (None / V4 / V6) + LE byte encoding [rewritten]
//!   mod crypto     - SHA-256 + XChaCha20-Poly1305 only [rewritten, subset of rust-sdk]
//!   mod tokens     - RouteToken, ContinueToken encrypt/decrypt [rewritten]
//!   mod packets    - 14 packet types (ID 1-14) encode/decode [rewritten]
//!   mod route      - RouteManager state machine [rewritten; pittle/chonkle copied]
//!     mod route::trackers - ReplayProtection, PingHistory, BandwidthLimiter [copied]
//!   mod client     - Client: game client relay session [new]
//!   mod server     - Server: game server as final relay destination [new]
//!   mod ffi        - #[no_mangle] C-ABI exports

#![allow(dead_code)]

pub mod constants;
pub mod pool;
pub mod stats;

// Copied from rust-sdk unchanged
pub mod bitpacker;
pub mod platform;
pub mod read_write;
pub mod stream;

pub mod route;

// Stub - will be rewritten in step 3
pub mod address;
pub mod client;
pub mod crypto;
pub mod packets;
pub mod server;
pub mod tokens;

// Placeholder mods - to be implemented in subsequent steps
pub mod ffi;
