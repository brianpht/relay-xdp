//! Network Next XDP Relay — library crate for testing.
//!
//! Re-exports all modules so integration tests can access them.

pub const RELAY_VERSION: &str = "relay-rust";

pub mod bpf;
pub mod config;
pub mod encoding;
pub mod main_thread;
pub mod manager;
pub mod packet_filter;
pub mod ping_history;
pub mod ping_thread;
pub mod platform;

