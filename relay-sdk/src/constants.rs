// Constants used by relay-sdk modules.
// Values match relay-xdp-common and rust-sdk constants.
// Tracker constants (used by route/trackers.rs)
pub const REPLAY_PROTECTION_BUFFER_SIZE: usize = 1024;
pub const PING_HISTORY_ENTRY_COUNT: usize = 1024;
pub const PING_SAFETY: f64 = 1.0;
pub const BANDWIDTH_LIMITER_INTERVAL: f64 = 1.0;
pub const PACKET_LOSS_TRACKER_HISTORY: usize = 1024;
pub const PACKET_LOSS_TRACKER_SAFETY: u64 = 30;
// Address type bytes - match relay-xdp-common RELAY_ADDRESS_* constants
pub const ADDRESS_NONE: u8 = 0;
pub const ADDRESS_IPV4: u8 = 1;
pub const ADDRESS_IPV6: u8 = 2;
pub const ADDRESS_BYTES_IPV4: usize = 6;
pub const ADDRESS_BYTES: usize = 19;
// Wire layout
pub const IPV4_HEADER_BYTES: usize = 20;
pub const UDP_HEADER_BYTES: usize = 8;
/// Relay packet header (sequence + session_id + session_version + SHA-256 prefix).
pub const HEADER_BYTES: usize = 25;
/// Maximum packet buffer size.
pub const MAX_PACKET_BYTES: usize = 1384;
/// Maximum relay payload (MTU).
pub const MTU: usize = 1200;
/// Byte offset of packet body (after type + pittle + chonkle = 18 bytes).
pub const PACKET_BODY_OFFSET: usize = 18;
// Token sizes (match relay-xdp-common)
pub const SESSION_PRIVATE_KEY_BYTES: usize = 32;
pub const ENCRYPTED_ROUTE_TOKEN_BYTES: usize = 111; // nonce(24) + plaintext(71) + tag(16)
pub const ENCRYPTED_CONTINUE_TOKEN_BYTES: usize = 57; // nonce(24) + plaintext(17) + tag(16)
pub const MAX_TOKENS: usize = 7;
// Route update types
pub const UPDATE_TYPE_DIRECT: u8 = 0;
pub const UPDATE_TYPE_ROUTE: u8 = 1;
pub const UPDATE_TYPE_CONTINUE: u8 = 2;
// Timing constants
pub const SLICE_SECONDS: f64 = 10.0;
pub const CLIENT_ROUTE_TIMEOUT: f64 = 20.0;
pub const ROUTE_REQUEST_TIMEOUT: f64 = 10.0;
pub const ROUTE_REQUEST_SEND_TIME: f64 = 0.25;
pub const CONTINUE_REQUEST_TIMEOUT: f64 = 10.0;
pub const CONTINUE_REQUEST_SEND_TIME: f64 = 0.25;
// Fallback flags
pub const FLAGS_BAD_ROUTE_TOKEN: u32 = 1 << 0;
pub const FLAGS_NO_ROUTE_TO_CONTINUE: u32 = 1 << 1;
pub const FLAGS_PREVIOUS_UPDATE_STILL_PENDING: u32 = 1 << 2;
pub const FLAGS_BAD_CONTINUE_TOKEN: u32 = 1 << 3;
pub const FLAGS_ROUTE_EXPIRED: u32 = 1 << 4;
pub const FLAGS_ROUTE_REQUEST_TIMED_OUT: u32 = 1 << 5;
pub const FLAGS_CONTINUE_REQUEST_TIMED_OUT: u32 = 1 << 6;
pub const FLAGS_ROUTE_TIMED_OUT: u32 = 1 << 7;
// Packet type IDs (match relay-xdp-common RELAY_*_PACKET constants)
pub const PACKET_TYPE_ROUTE_REQUEST: u8 = 1;
pub const PACKET_TYPE_ROUTE_RESPONSE: u8 = 2;
pub const PACKET_TYPE_CLIENT_TO_SERVER: u8 = 3;
pub const PACKET_TYPE_SERVER_TO_CLIENT: u8 = 4;
pub const PACKET_TYPE_SESSION_PING: u8 = 5;
pub const PACKET_TYPE_SESSION_PONG: u8 = 6;
pub const PACKET_TYPE_CONTINUE_REQUEST: u8 = 7;
pub const PACKET_TYPE_CONTINUE_RESPONSE: u8 = 8;
pub const PACKET_TYPE_CLIENT_PING: u8 = 9;
pub const PACKET_TYPE_CLIENT_PONG: u8 = 10;
pub const PACKET_TYPE_RELAY_PING: u8 = 11;
pub const PACKET_TYPE_RELAY_PONG: u8 = 12;
pub const PACKET_TYPE_SERVER_PING: u8 = 13;
pub const PACKET_TYPE_SERVER_PONG: u8 = 14;
pub const RELAY_PING_TOKEN_BYTES: usize = 32;
pub const RELAY_PING_KEY_BYTES: usize = 32;
