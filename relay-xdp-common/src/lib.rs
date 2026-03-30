//! Shared types and constants between eBPF and userspace.
//!
//! All structs are `#[repr(C)]` to match the C layout in `relay_shared.h`.
//! Field byte order comments match the C originals.

#![no_std]

// -------------------------------------------------------
// Constants from relay_constants.h
// -------------------------------------------------------

pub const MAX_RELAYS: usize = 1024;
pub const MAX_SESSIONS: usize = 100_000;

pub const RELAY_HEADER_BYTES: usize = 25;
pub const RELAY_MTU: usize = 1200;
pub const RELAY_MAX_PACKET_BYTES: usize = 1384;

pub const RELAY_ADDRESS_NONE: u8 = 0;
pub const RELAY_ADDRESS_IPV4: u8 = 1;
pub const RELAY_ADDRESS_IPV6: u8 = 2;

pub const RELAY_OK: i32 = 0;
pub const RELAY_ERROR: i32 = -1;

pub const RELAY_MAX_UPDATE_ATTEMPTS: i32 = 30;
pub const RELAY_RESPONSE_MAX_BYTES: usize = 10 * 1024 * 1024;

pub const RELAY_PING_STATS_WINDOW: f64 = 10.0;
pub const RELAY_PING_HISTORY_SIZE: usize = 64;
pub const RELAY_PING_SAFETY: f64 = 1.0;
pub const RELAY_PING_TIME: f64 = 0.1;

pub const RELAY_PING_TOKEN_BYTES: usize = 32;
pub const RELAY_PING_KEY_BYTES: usize = 32;
pub const RELAY_SESSION_PRIVATE_KEY_BYTES: usize = 32;
pub const RELAY_ROUTE_TOKEN_BYTES: usize = 71;
pub const RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES: usize = 111;
pub const RELAY_CONTINUE_TOKEN_BYTES: usize = 17;
pub const RELAY_ENCRYPTED_CONTINUE_TOKEN_BYTES: usize = 57;
pub const RELAY_PUBLIC_KEY_BYTES: usize = 32;
pub const RELAY_PRIVATE_KEY_BYTES: usize = 32;
pub const RELAY_SECRET_KEY_BYTES: usize = 32;
pub const RELAY_BACKEND_PUBLIC_KEY_BYTES: usize = 32;

pub const RELAY_VERSION_LENGTH: usize = 32;
pub const WHITELIST_TIMEOUT: u64 = 1000;
pub const RELAY_ETHERNET_ADDRESS_BYTES: usize = 6;

// Crypto constants (from relay_xdp.c / relay_module.c)
pub const XCHACHA20POLY1305_NONCE_SIZE: usize = 24;
pub const CHACHA20POLY1305_KEY_SIZE: usize = 32;

// Packet types
pub const RELAY_ROUTE_REQUEST_PACKET: u8 = 1;
pub const RELAY_ROUTE_RESPONSE_PACKET: u8 = 2;
pub const RELAY_CLIENT_TO_SERVER_PACKET: u8 = 3;
pub const RELAY_SERVER_TO_CLIENT_PACKET: u8 = 4;
pub const RELAY_SESSION_PING_PACKET: u8 = 5;
pub const RELAY_SESSION_PONG_PACKET: u8 = 6;
pub const RELAY_CONTINUE_REQUEST_PACKET: u8 = 7;
pub const RELAY_CONTINUE_RESPONSE_PACKET: u8 = 8;
pub const RELAY_CLIENT_PING_PACKET: u8 = 9;
pub const RELAY_CLIENT_PONG_PACKET: u8 = 10;
pub const RELAY_PING_PACKET: u8 = 11;
pub const RELAY_PONG_PACKET: u8 = 12;
pub const RELAY_SERVER_PING_PACKET: u8 = 13;
pub const RELAY_SERVER_PONG_PACKET: u8 = 14;

// Counter indices
pub const RELAY_COUNTER_PACKETS_SENT: usize = 0;
pub const RELAY_COUNTER_PACKETS_RECEIVED: usize = 1;
pub const RELAY_COUNTER_BYTES_SENT: usize = 2;
pub const RELAY_COUNTER_BYTES_RECEIVED: usize = 3;
pub const RELAY_COUNTER_BASIC_PACKET_FILTER_DROPPED_PACKET: usize = 4;
pub const RELAY_COUNTER_ADVANCED_PACKET_FILTER_DROPPED_PACKET: usize = 5;
pub const RELAY_COUNTER_SESSION_CREATED: usize = 6;
pub const RELAY_COUNTER_SESSION_CONTINUED: usize = 7;
pub const RELAY_COUNTER_SESSION_DESTROYED: usize = 8;

pub const RELAY_COUNTER_RELAY_PING_PACKET_SENT: usize = 10;
pub const RELAY_COUNTER_RELAY_PING_PACKET_RECEIVED: usize = 11;
pub const RELAY_COUNTER_RELAY_PING_PACKET_DID_NOT_VERIFY: usize = 12;
pub const RELAY_COUNTER_RELAY_PING_PACKET_EXPIRED: usize = 13;
pub const RELAY_COUNTER_RELAY_PING_PACKET_WRONG_SIZE: usize = 14;
pub const RELAY_COUNTER_RELAY_PING_PACKET_UNKNOWN_RELAY: usize = 15;

pub const RELAY_COUNTER_RELAY_PONG_PACKET_SENT: usize = 16;
pub const RELAY_COUNTER_RELAY_PONG_PACKET_RECEIVED: usize = 17;
pub const RELAY_COUNTER_RELAY_PONG_PACKET_WRONG_SIZE: usize = 18;
pub const RELAY_COUNTER_RELAY_PONG_PACKET_UNKNOWN_RELAY: usize = 19;

pub const RELAY_COUNTER_CLIENT_PING_PACKET_RECEIVED: usize = 20;
pub const RELAY_COUNTER_CLIENT_PING_PACKET_WRONG_SIZE: usize = 21;
pub const RELAY_COUNTER_CLIENT_PING_PACKET_RESPONDED_WITH_PONG: usize = 22;
pub const RELAY_COUNTER_CLIENT_PING_PACKET_DID_NOT_VERIFY: usize = 23;
pub const RELAY_COUNTER_CLIENT_PING_PACKET_EXPIRED: usize = 24;

pub const RELAY_COUNTER_ROUTE_REQUEST_PACKET_RECEIVED: usize = 30;
pub const RELAY_COUNTER_ROUTE_REQUEST_PACKET_WRONG_SIZE: usize = 31;
pub const RELAY_COUNTER_ROUTE_REQUEST_PACKET_COULD_NOT_DECRYPT_ROUTE_TOKEN: usize = 32;
pub const RELAY_COUNTER_ROUTE_REQUEST_PACKET_TOKEN_EXPIRED: usize = 33;
pub const RELAY_COUNTER_ROUTE_REQUEST_PACKET_FORWARD_TO_NEXT_HOP: usize = 34;

pub const RELAY_COUNTER_ROUTE_RESPONSE_PACKET_RECEIVED: usize = 40;
pub const RELAY_COUNTER_ROUTE_RESPONSE_PACKET_WRONG_SIZE: usize = 41;
pub const RELAY_COUNTER_ROUTE_RESPONSE_PACKET_COULD_NOT_FIND_SESSION: usize = 42;
pub const RELAY_COUNTER_ROUTE_RESPONSE_PACKET_SESSION_EXPIRED: usize = 43;
pub const RELAY_COUNTER_ROUTE_RESPONSE_PACKET_ALREADY_RECEIVED: usize = 44;
pub const RELAY_COUNTER_ROUTE_RESPONSE_PACKET_HEADER_DID_NOT_VERIFY: usize = 45;
pub const RELAY_COUNTER_ROUTE_RESPONSE_PACKET_FORWARD_TO_PREVIOUS_HOP: usize = 46;

pub const RELAY_COUNTER_CONTINUE_REQUEST_PACKET_RECEIVED: usize = 50;
pub const RELAY_COUNTER_CONTINUE_REQUEST_PACKET_WRONG_SIZE: usize = 51;
pub const RELAY_COUNTER_CONTINUE_REQUEST_PACKET_COULD_NOT_DECRYPT_CONTINUE_TOKEN: usize = 52;
pub const RELAY_COUNTER_CONTINUE_REQUEST_PACKET_TOKEN_EXPIRED: usize = 53;
pub const RELAY_COUNTER_CONTINUE_REQUEST_PACKET_COULD_NOT_FIND_SESSION: usize = 54;
pub const RELAY_COUNTER_CONTINUE_REQUEST_PACKET_SESSION_EXPIRED: usize = 55;
pub const RELAY_COUNTER_CONTINUE_REQUEST_PACKET_FORWARD_TO_NEXT_HOP: usize = 56;

pub const RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_RECEIVED: usize = 60;
pub const RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_WRONG_SIZE: usize = 61;
pub const RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_ALREADY_RECEIVED: usize = 62;
pub const RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_COULD_NOT_FIND_SESSION: usize = 63;
pub const RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_SESSION_EXPIRED: usize = 64;
pub const RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_HEADER_DID_NOT_VERIFY: usize = 65;
pub const RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_FORWARD_TO_PREVIOUS_HOP: usize = 66;

pub const RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_RECEIVED: usize = 70;
pub const RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_TOO_SMALL: usize = 71;
pub const RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_TOO_BIG: usize = 72;
pub const RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_COULD_NOT_FIND_SESSION: usize = 73;
pub const RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_SESSION_EXPIRED: usize = 74;
pub const RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_ALREADY_RECEIVED: usize = 75;
pub const RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_HEADER_DID_NOT_VERIFY: usize = 76;
pub const RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_FORWARD_TO_NEXT_HOP: usize = 77;

pub const RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_RECEIVED: usize = 80;
pub const RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_TOO_SMALL: usize = 81;
pub const RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_TOO_BIG: usize = 82;
pub const RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_COULD_NOT_FIND_SESSION: usize = 83;
pub const RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_SESSION_EXPIRED: usize = 84;
pub const RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_ALREADY_RECEIVED: usize = 85;
pub const RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_HEADER_DID_NOT_VERIFY: usize = 86;
pub const RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_FORWARD_TO_PREVIOUS_HOP: usize = 87;

pub const RELAY_COUNTER_SESSION_PING_PACKET_RECEIVED: usize = 90;
pub const RELAY_COUNTER_SESSION_PING_PACKET_WRONG_SIZE: usize = 91;
pub const RELAY_COUNTER_SESSION_PING_PACKET_COULD_NOT_FIND_SESSION: usize = 92;
pub const RELAY_COUNTER_SESSION_PING_PACKET_SESSION_EXPIRED: usize = 93;
pub const RELAY_COUNTER_SESSION_PING_PACKET_ALREADY_RECEIVED: usize = 94;
pub const RELAY_COUNTER_SESSION_PING_PACKET_HEADER_DID_NOT_VERIFY: usize = 95;
pub const RELAY_COUNTER_SESSION_PING_PACKET_FORWARD_TO_NEXT_HOP: usize = 96;

pub const RELAY_COUNTER_SESSION_PONG_PACKET_RECEIVED: usize = 100;
pub const RELAY_COUNTER_SESSION_PONG_PACKET_WRONG_SIZE: usize = 101;
pub const RELAY_COUNTER_SESSION_PONG_PACKET_COULD_NOT_FIND_SESSION: usize = 102;
pub const RELAY_COUNTER_SESSION_PONG_PACKET_SESSION_EXPIRED: usize = 103;
pub const RELAY_COUNTER_SESSION_PONG_PACKET_ALREADY_RECEIVED: usize = 104;
pub const RELAY_COUNTER_SESSION_PONG_PACKET_HEADER_DID_NOT_VERIFY: usize = 105;
pub const RELAY_COUNTER_SESSION_PONG_PACKET_FORWARD_TO_PREVIOUS_HOP: usize = 106;

pub const RELAY_COUNTER_SERVER_PING_PACKET_RECEIVED: usize = 110;
pub const RELAY_COUNTER_SERVER_PING_PACKET_WRONG_SIZE: usize = 111;
pub const RELAY_COUNTER_SERVER_PING_PACKET_RESPONDED_WITH_PONG: usize = 112;
pub const RELAY_COUNTER_SERVER_PING_PACKET_DID_NOT_VERIFY: usize = 113;
pub const RELAY_COUNTER_SERVER_PING_PACKET_EXPIRED: usize = 114;

pub const RELAY_COUNTER_PACKET_TOO_LARGE: usize = 120;
pub const RELAY_COUNTER_PACKET_TOO_SMALL: usize = 121;
pub const RELAY_COUNTER_DROP_FRAGMENT: usize = 122;
pub const RELAY_COUNTER_DROP_LARGE_IP_HEADER: usize = 123;
pub const RELAY_COUNTER_REDIRECT_NOT_IN_WHITELIST: usize = 124;
pub const RELAY_COUNTER_DROPPED_PACKETS: usize = 125;
pub const RELAY_COUNTER_DROPPED_BYTES: usize = 126;
pub const RELAY_COUNTER_NOT_IN_WHITELIST: usize = 127;
pub const RELAY_COUNTER_WHITELIST_ENTRY_EXPIRED: usize = 128;

pub const RELAY_COUNTER_SESSIONS: usize = 130;
pub const RELAY_COUNTER_ENVELOPE_KBPS_UP: usize = 131;
pub const RELAY_COUNTER_ENVELOPE_KBPS_DOWN: usize = 132;

// Profiling counters (D2) — cumulative nanoseconds per hot-path stage.
// Written by eBPF only when profiling is enabled (`--features profiling`).
pub const RELAY_COUNTER_PROFILE_PARSE_NS: usize = 133;
pub const RELAY_COUNTER_PROFILE_FILTER_NS: usize = 134;
pub const RELAY_COUNTER_PROFILE_MAP_LOOKUP_NS: usize = 135;
pub const RELAY_COUNTER_PROFILE_CRYPTO_NS: usize = 136;
pub const RELAY_COUNTER_PROFILE_REWRITE_NS: usize = 137;
pub const RELAY_COUNTER_PROFILE_TOTAL_NS: usize = 138;
pub const RELAY_COUNTER_PROFILE_SAMPLES: usize = 139;

pub const RELAY_NUM_COUNTERS: usize = 150;

// -------------------------------------------------------
// Shared structs from relay_shared.h
// -------------------------------------------------------

/// Relay configuration — written by userspace into config_map (BPF_MAP_TYPE_ARRAY, 1 entry).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RelayConfig {
    pub dedicated: u32,
    /// Big endian
    pub relay_public_address: u32,
    /// Big endian
    pub relay_internal_address: u32,
    /// Big endian
    pub relay_port: u16,
    pub relay_secret_key: [u8; RELAY_SECRET_KEY_BYTES],
    pub relay_backend_public_key: [u8; RELAY_BACKEND_PUBLIC_KEY_BYTES],
    pub gateway_ethernet_address: [u8; RELAY_ETHERNET_ADDRESS_BYTES],
    pub use_gateway_ethernet_address: u8,
}

/// Relay runtime state — written by userspace into state_map (BPF_MAP_TYPE_ARRAY, 1 entry).
/// Updated every second with magic values, timestamp, and ping key from relay_backend response.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RelayState {
    pub current_timestamp: u64,
    pub current_magic: [u8; 8],
    pub previous_magic: [u8; 8],
    pub next_magic: [u8; 8],
    pub ping_key: [u8; RELAY_PING_KEY_BYTES],
}

/// Per-CPU statistics counters.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RelayStats {
    pub counters: [u64; RELAY_NUM_COUNTERS],
}

/// Session data stored in session_map (BPF_MAP_TYPE_LRU_HASH).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SessionData {
    pub session_private_key: [u8; RELAY_SESSION_PRIVATE_KEY_BYTES],
    pub expire_timestamp: u64,
    pub session_id: u64,
    pub payload_client_to_server_sequence: u64,
    pub payload_server_to_client_sequence: u64,
    pub special_client_to_server_sequence: u64,
    pub special_server_to_client_sequence: u64,
    pub envelope_kbps_up: u32,
    pub envelope_kbps_down: u32,
    /// Big endian
    pub next_address: u32,
    /// Big endian
    pub prev_address: u32,
    /// Big endian
    pub next_port: u16,
    /// Big endian
    pub prev_port: u16,
    pub session_version: u8,
    pub next_internal: u8,
    pub prev_internal: u8,
    pub first_hop: u8,
}

/// Ping token input for SHA-256 verification.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct PingTokenData {
    pub ping_key: [u8; RELAY_PING_KEY_BYTES],
    /// Native byte order (NOT big endian — C code stores this directly without htonl)
    pub expire_timestamp: u64,
    /// Big endian
    pub source_address: u32,
    /// Big endian
    pub dest_address: u32,
    /// Big endian
    pub source_port: u16,
    /// Big endian
    pub dest_port: u16,
}

/// Header verification input for SHA-256.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct HeaderData {
    pub session_private_key: [u8; RELAY_SESSION_PRIVATE_KEY_BYTES],
    pub packet_type: u8,
    pub packet_sequence: u64,
    pub session_id: u64,
    pub session_version: u8,
}

/// Decrypted route token.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct RouteToken {
    pub session_private_key: [u8; RELAY_SESSION_PRIVATE_KEY_BYTES],
    pub expire_timestamp: u64,
    pub session_id: u64,
    pub envelope_kbps_up: u32,
    pub envelope_kbps_down: u32,
    /// Big endian
    pub next_address: u32,
    /// Big endian
    pub prev_address: u32,
    /// Big endian
    pub next_port: u16,
    /// Big endian
    pub prev_port: u16,
    pub session_version: u8,
    pub next_internal: u8,
    pub prev_internal: u8,
}

/// Decrypted continue token.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ContinueToken {
    pub expire_timestamp: u64,
    pub session_id: u64,
    pub session_version: u8,
}

/// Session map key.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub session_id: u64,
    /// IMPORTANT: must be u64 or weird stuff happens (per C comment)
    pub session_version: u64,
}

/// Whitelist map key.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WhitelistKey {
    /// Big endian
    pub address: u32,
    /// Big endian. IMPORTANT: Must be u32 or alignment issues cause failed lookups (per C comment).
    pub port: u32,
}

/// Whitelist map value.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct WhitelistValue {
    pub expire_timestamp: u64,
    pub source_address: [u8; 6],
    pub dest_address: [u8; 6],
}

// -------------------------------------------------------
// Unsafe impl for aya map compatibility
// -------------------------------------------------------

/// Crypto parameter struct for xchacha20poly1305 decryption kfunc.
/// Matches `struct chacha20poly1305_crypto` in `relay_module.c`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Chacha20Poly1305Crypto {
    pub nonce: [u8; XCHACHA20POLY1305_NONCE_SIZE],
    pub key: [u8; CHACHA20POLY1305_KEY_SIZE],
}


#[cfg(feature = "user")]
unsafe impl aya::Pod for RelayConfig {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RelayState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RelayStats {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionData {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for WhitelistKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for WhitelistValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PingTokenData {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for HeaderData {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RouteToken {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ContinueToken {}

