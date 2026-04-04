//! Constants ported from `modules/constants/constants.go`.

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 0;
pub const PATCH_VERSION: u32 = 0;

pub const MAX_PACKET_BYTES: usize = 1384;

pub const MAX_BUYERS: usize = 1024;

pub const MAX_RELAYS: usize = 1000;
pub const NUM_RELAY_COUNTERS: usize = 150;
pub const RELAY_TIMEOUT: i64 = 30;
pub const RELAY_HISTORY_SIZE: usize = 300;

pub const MAX_ROUTE_RELAYS: usize = 5;
pub const MAX_CLIENT_RELAYS: usize = 16;
pub const MAX_SERVER_RELAYS: usize = 8;
pub const MAX_DEST_RELAYS: usize = MAX_SERVER_RELAYS;

pub const MAX_RELAY_NAME_LENGTH: usize = 63;
pub const MAX_RELAY_VERSION_LENGTH: usize = 32;
pub const MAX_DATACENTER_NAME_LENGTH: usize = 256;

pub const MAGIC_BYTES: usize = 8;

pub const MAX_CONNECTION_TYPE: usize = 3;
pub const MAX_PLATFORM_TYPE: usize = 10;

pub const COST_BIAS: i32 = 3;
pub const MAX_INDIRECTS: usize = 8;
pub const MAX_ROUTES_PER_ENTRY: usize = 16;

pub const MAX_ROUTE_COST: i32 = 255;

pub const NEXT_MAX_NODES: usize = MAX_ROUTE_RELAYS + 2;
pub const NEXT_ADDRESS_BYTES: usize = 19;
pub const NEXT_ADDRESS_BYTES_IPV4: usize = 6;

pub const ROUTE_TOKEN_BYTES: usize = 71;
pub const ENCRYPTED_ROUTE_TOKEN_BYTES: usize = 111;

pub const CONTINUE_TOKEN_BYTES: usize = 17;
pub const ENCRYPTED_CONTINUE_TOKEN_BYTES: usize = 57;

pub const RELAY_FLAGS_SHUTTING_DOWN: u64 = 1;

pub const RELAY_STATUS_OFFLINE: i32 = 0;
pub const RELAY_STATUS_ONLINE: i32 = 1;
pub const RELAY_STATUS_SHUTTING_DOWN: i32 = 2;

pub const PING_KEY_BYTES: usize = 32;
pub const PING_TOKEN_BYTES: usize = 32;
pub const SECRET_KEY_BYTES: usize = 32;

pub const MAX_DATABASE_SIZE: i32 = 1024 * 1024;

pub const MAX_SCORE: usize = 999;
pub const NUM_BUCKETS: usize = MAX_SCORE + 1;

// Address type constants (from encoding module)
pub const IP_ADDRESS_NONE: u32 = 0;
pub const IP_ADDRESS_IPV4: u32 = 1;
pub const IP_ADDRESS_IPV6: u32 = 2;

