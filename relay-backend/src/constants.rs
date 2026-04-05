//! Relay protocol constants.

#![allow(dead_code)]

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

// Counter names indexed by counter ID. Empty string = unused index.
// Used by /relay_counters HTML handler and /metrics Prometheus handler.
pub const COUNTER_NAMES: [&str; NUM_RELAY_COUNTERS] = {
    let mut names = [""; NUM_RELAY_COUNTERS];
    names[0] = "packets_sent";
    names[1] = "packets_received";
    names[2] = "bytes_sent";
    names[3] = "bytes_received";
    names[4] = "basic_packet_filter_dropped_packet";
    names[5] = "advanced_packet_filter_dropped_packet";
    names[6] = "session_created";
    names[7] = "session_continued";
    names[8] = "session_destroyed";
    names[10] = "relay_ping_packet_sent";
    names[11] = "relay_ping_packet_received";
    names[12] = "relay_ping_packet_did_not_verify";
    names[13] = "relay_ping_packet_expired";
    names[14] = "relay_ping_packet_wrong_size";
    names[15] = "relay_ping_packet_unknown_relay";
    names[16] = "relay_pong_packet_sent";
    names[17] = "relay_pong_packet_received";
    names[18] = "relay_pong_packet_wrong_size";
    names[19] = "relay_pong_packet_unknown_relay";
    names[20] = "client_ping_packet_received";
    names[21] = "client_ping_packet_wrong_size";
    names[22] = "client_ping_packet_responded_with_pong";
    names[23] = "client_ping_packet_did_not_verify";
    names[24] = "client_ping_packet_expired";
    names[30] = "route_request_packet_received";
    names[31] = "route_request_packet_wrong_size";
    names[32] = "route_request_packet_could_not_decrypt_route_token";
    names[33] = "route_request_packet_token_expired";
    names[34] = "route_request_packet_forward_to_next_hop";
    names[40] = "route_response_packet_received";
    names[41] = "route_response_packet_wrong_size";
    names[42] = "route_response_packet_could_not_find_session";
    names[43] = "route_response_packet_session_expired";
    names[44] = "route_response_packet_already_received";
    names[45] = "route_response_packet_header_did_not_verify";
    names[46] = "route_response_packet_forward_to_previous_hop";
    names[50] = "continue_request_packet_received";
    names[51] = "continue_request_packet_wrong_size";
    names[52] = "continue_request_packet_could_not_decrypt_continue_token";
    names[53] = "continue_request_packet_token_expired";
    names[54] = "continue_request_packet_could_not_find_session";
    names[55] = "continue_request_packet_session_expired";
    names[56] = "continue_request_packet_forward_to_next_hop";
    names[60] = "continue_response_packet_received";
    names[61] = "continue_response_packet_wrong_size";
    names[62] = "continue_response_packet_already_received";
    names[63] = "continue_response_packet_could_not_find_session";
    names[64] = "continue_response_packet_session_expired";
    names[65] = "continue_response_packet_header_did_not_verify";
    names[66] = "continue_response_packet_forward_to_previous_hop";
    names[70] = "client_to_server_packet_received";
    names[71] = "client_to_server_packet_too_small";
    names[72] = "client_to_server_packet_too_big";
    names[73] = "client_to_server_packet_could_not_find_session";
    names[74] = "client_to_server_packet_session_expired";
    names[75] = "client_to_server_packet_already_received";
    names[76] = "client_to_server_packet_header_did_not_verify";
    names[77] = "client_to_server_packet_forward_to_next_hop";
    names[80] = "server_to_client_packet_received";
    names[81] = "server_to_client_packet_too_small";
    names[82] = "server_to_client_packet_too_big";
    names[83] = "server_to_client_packet_could_not_find_session";
    names[84] = "server_to_client_packet_session_expired";
    names[85] = "server_to_client_packet_already_received";
    names[86] = "server_to_client_packet_header_did_not_verify";
    names[87] = "server_to_client_packet_forward_to_previous_hop";
    names[90] = "session_ping_packet_received";
    names[91] = "session_ping_packet_wrong_size";
    names[92] = "session_ping_packet_could_not_find_session";
    names[93] = "session_ping_packet_session_expired";
    names[94] = "session_ping_packet_already_received";
    names[95] = "session_ping_packet_header_did_not_verify";
    names[96] = "session_ping_packet_forward_to_next_hop";
    names[100] = "session_pong_packet_received";
    names[101] = "session_pong_packet_wrong_size";
    names[102] = "session_pong_packet_could_not_find_session";
    names[103] = "session_pong_packet_session_expired";
    names[104] = "session_pong_packet_already_received";
    names[105] = "session_pong_packet_header_did_not_verify";
    names[106] = "session_pong_packet_forward_to_previous_hop";
    names[110] = "server_ping_packet_received";
    names[111] = "server_ping_packet_wrong_size";
    names[112] = "server_ping_packet_responded_with_pong";
    names[113] = "server_ping_packet_did_not_verify";
    names[114] = "server_ping_packet_expired";
    names[120] = "packet_too_large";
    names[121] = "packet_too_small";
    names[122] = "drop_fragment";
    names[123] = "drop_large_ip_header";
    names[124] = "redirect_not_in_whitelist";
    names[125] = "dropped_packets";
    names[126] = "dropped_bytes";
    names[127] = "not_in_whitelist";
    names[128] = "whitelist_entry_expired";
    names[130] = "sessions";
    names[131] = "envelope_kbps_up";
    names[132] = "envelope_kbps_down";
    names[133] = "profile_parse_ns";
    names[134] = "profile_filter_ns";
    names[135] = "profile_map_lookup_ns";
    names[136] = "profile_crypto_ns";
    names[137] = "profile_rewrite_ns";
    names[138] = "profile_total_ns";
    names[139] = "profile_samples";
    names
};

// Display names for HTML counter page (RELAY_COUNTER_* prefix style).
// Used by /relay_counters/{name} handler.
pub const COUNTER_DISPLAY_NAMES: [&str; NUM_RELAY_COUNTERS] = {
    let mut names = [""; NUM_RELAY_COUNTERS];
    names[0] = "RELAY_COUNTER_PACKETS_SENT";
    names[1] = "RELAY_COUNTER_PACKETS_RECEIVED";
    names[2] = "RELAY_COUNTER_BYTES_SENT";
    names[3] = "RELAY_COUNTER_BYTES_RECEIVED";
    names[4] = "RELAY_COUNTER_BASIC_PACKET_FILTER_DROPPED_PACKET";
    names[5] = "RELAY_COUNTER_ADVANCED_PACKET_FILTER_DROPPED_PACKET";
    names[6] = "RELAY_COUNTER_SESSION_CREATED";
    names[7] = "RELAY_COUNTER_SESSION_CONTINUED";
    names[8] = "RELAY_COUNTER_SESSION_DESTROYED";
    names[10] = "RELAY_COUNTER_RELAY_PING_PACKET_SENT";
    names[11] = "RELAY_COUNTER_RELAY_PING_PACKET_RECEIVED";
    names[12] = "RELAY_COUNTER_RELAY_PING_PACKET_DID_NOT_VERIFY";
    names[13] = "RELAY_COUNTER_RELAY_PING_PACKET_EXPIRED";
    names[14] = "RELAY_COUNTER_RELAY_PING_PACKET_WRONG_SIZE";
    names[15] = "RELAY_COUNTER_RELAY_PING_PACKET_UNKNOWN_RELAY";
    names[16] = "RELAY_COUNTER_RELAY_PONG_PACKET_SENT";
    names[17] = "RELAY_COUNTER_RELAY_PONG_PACKET_RECEIVED";
    names[18] = "RELAY_COUNTER_RELAY_PONG_PACKET_WRONG_SIZE";
    names[19] = "RELAY_COUNTER_RELAY_PONG_PACKET_UNKNOWN_RELAY";
    names[20] = "RELAY_COUNTER_CLIENT_PING_PACKET_RECEIVED";
    names[21] = "RELAY_COUNTER_CLIENT_PING_PACKET_WRONG_SIZE";
    names[22] = "RELAY_COUNTER_CLIENT_PING_PACKET_RESPONDED_WITH_PONG";
    names[23] = "RELAY_COUNTER_CLIENT_PING_PACKET_DID_NOT_VERIFY";
    names[24] = "RELAY_COUNTER_CLIENT_PING_PACKET_EXPIRED";
    names[30] = "RELAY_COUNTER_ROUTE_REQUEST_PACKET_RECEIVED";
    names[31] = "RELAY_COUNTER_ROUTE_REQUEST_PACKET_WRONG_SIZE";
    names[32] = "RELAY_COUNTER_ROUTE_REQUEST_PACKET_COULD_NOT_DECRYPT_ROUTE_TOKEN";
    names[33] = "RELAY_COUNTER_ROUTE_REQUEST_PACKET_TOKEN_EXPIRED";
    names[34] = "RELAY_COUNTER_ROUTE_REQUEST_PACKET_FORWARD_TO_NEXT_HOP";
    names[40] = "RELAY_COUNTER_ROUTE_RESPONSE_PACKET_RECEIVED";
    names[41] = "RELAY_COUNTER_ROUTE_RESPONSE_PACKET_WRONG_SIZE";
    names[42] = "RELAY_COUNTER_ROUTE_RESPONSE_PACKET_COULD_NOT_FIND_SESSION";
    names[43] = "RELAY_COUNTER_ROUTE_RESPONSE_PACKET_SESSION_EXPIRED";
    names[44] = "RELAY_COUNTER_ROUTE_RESPONSE_PACKET_ALREADY_RECEIVED";
    names[45] = "RELAY_COUNTER_ROUTE_RESPONSE_PACKET_HEADER_DID_NOT_VERIFY";
    names[46] = "RELAY_COUNTER_ROUTE_RESPONSE_PACKET_FORWARD_TO_PREVIOUS_HOP";
    names[50] = "RELAY_COUNTER_CONTINUE_REQUEST_PACKET_RECEIVED";
    names[51] = "RELAY_COUNTER_CONTINUE_REQUEST_PACKET_WRONG_SIZE";
    names[52] = "RELAY_COUNTER_CONTINUE_REQUEST_PACKET_COULD_NOT_DECRYPT_CONTINUE_TOKEN";
    names[53] = "RELAY_COUNTER_CONTINUE_REQUEST_PACKET_TOKEN_EXPIRED";
    names[54] = "RELAY_COUNTER_CONTINUE_REQUEST_PACKET_COULD_NOT_FIND_SESSION";
    names[55] = "RELAY_COUNTER_CONTINUE_REQUEST_PACKET_SESSION_EXPIRED";
    names[56] = "RELAY_COUNTER_CONTINUE_REQUEST_PACKET_FORWARD_TO_NEXT_HOP";
    names[60] = "RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_RECEIVED";
    names[61] = "RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_WRONG_SIZE";
    names[62] = "RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_ALREADY_RECEIVED";
    names[63] = "RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_COULD_NOT_FIND_SESSION";
    names[64] = "RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_SESSION_EXPIRED";
    names[65] = "RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_HEADER_DID_NOT_VERIFY";
    names[66] = "RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_FORWARD_TO_PREVIOUS_HOP";
    names[70] = "RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_RECEIVED";
    names[71] = "RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_TOO_SMALL";
    names[72] = "RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_TOO_BIG";
    names[73] = "RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_COULD_NOT_FIND_SESSION";
    names[74] = "RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_SESSION_EXPIRED";
    names[75] = "RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_ALREADY_RECEIVED";
    names[76] = "RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_HEADER_DID_NOT_VERIFY";
    names[77] = "RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_FORWARD_TO_NEXT_HOP";
    names[80] = "RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_RECEIVED";
    names[81] = "RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_TOO_SMALL";
    names[82] = "RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_TOO_BIG";
    names[83] = "RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_COULD_NOT_FIND_SESSION";
    names[84] = "RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_SESSION_EXPIRED";
    names[85] = "RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_ALREADY_RECEIVED";
    names[86] = "RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_HEADER_DID_NOT_VERIFY";
    names[87] = "RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_FORWARD_TO_PREVIOUS_HOP";
    names[90] = "RELAY_COUNTER_SESSION_PING_PACKET_RECEIVED";
    names[91] = "RELAY_COUNTER_SESSION_PING_PACKET_WRONG_SIZE";
    names[92] = "RELAY_COUNTER_SESSION_PING_PACKET_COULD_NOT_FIND_SESSION";
    names[93] = "RELAY_COUNTER_SESSION_PING_PACKET_SESSION_EXPIRED";
    names[94] = "RELAY_COUNTER_SESSION_PING_PACKET_ALREADY_RECEIVED";
    names[95] = "RELAY_COUNTER_SESSION_PING_PACKET_HEADER_DID_NOT_VERIFY";
    names[96] = "RELAY_COUNTER_SESSION_PING_PACKET_FORWARD_TO_NEXT_HOP";
    names[100] = "RELAY_COUNTER_SESSION_PONG_PACKET_RECEIVED";
    names[101] = "RELAY_COUNTER_SESSION_PONG_PACKET_WRONG_SIZE";
    names[102] = "RELAY_COUNTER_SESSION_PONG_PACKET_COULD_NOT_FIND_SESSION";
    names[103] = "RELAY_COUNTER_SESSION_PONG_PACKET_SESSION_EXPIRED";
    names[104] = "RELAY_COUNTER_SESSION_PONG_PACKET_ALREADY_RECEIVED";
    names[105] = "RELAY_COUNTER_SESSION_PONG_PACKET_HEADER_DID_NOT_VERIFY";
    names[106] = "RELAY_COUNTER_SESSION_PONG_PACKET_FORWARD_TO_PREVIOUS_HOP";
    names[110] = "RELAY_COUNTER_SERVER_PING_PACKET_RECEIVED";
    names[111] = "RELAY_COUNTER_SERVER_PING_PACKET_WRONG_SIZE";
    names[112] = "RELAY_COUNTER_SERVER_PING_PACKET_RESPONDED_WITH_PONG";
    names[113] = "RELAY_COUNTER_SERVER_PING_PACKET_DID_NOT_VERIFY";
    names[114] = "RELAY_COUNTER_SERVER_PING_PACKET_EXPIRED";
    names[120] = "RELAY_COUNTER_PACKET_TOO_LARGE";
    names[121] = "RELAY_COUNTER_PACKET_TOO_SMALL";
    names[122] = "RELAY_COUNTER_DROP_FRAGMENT";
    names[123] = "RELAY_COUNTER_DROP_LARGE_IP_HEADER";
    names[124] = "RELAY_COUNTER_REDIRECT_NOT_IN_WHITELIST";
    names[125] = "RELAY_COUNTER_DROPPED_PACKETS";
    names[126] = "RELAY_COUNTER_DROPPED_BYTES";
    names[127] = "RELAY_COUNTER_NOT_IN_WHITELIST";
    names[128] = "RELAY_COUNTER_WHITELIST_ENTRY_EXPIRED";
    names[130] = "RELAY_COUNTER_SESSIONS";
    names[131] = "RELAY_COUNTER_ENVELOPE_KBPS_UP";
    names[132] = "RELAY_COUNTER_ENVELOPE_KBPS_DOWN";
    names[133] = "RELAY_COUNTER_PROFILE_PARSE_NS";
    names[134] = "RELAY_COUNTER_PROFILE_FILTER_NS";
    names[135] = "RELAY_COUNTER_PROFILE_MAP_LOOKUP_NS";
    names[136] = "RELAY_COUNTER_PROFILE_CRYPTO_NS";
    names[137] = "RELAY_COUNTER_PROFILE_REWRITE_NS";
    names[138] = "RELAY_COUNTER_PROFILE_TOTAL_NS";
    names[139] = "RELAY_COUNTER_PROFILE_SAMPLES";
    names
};

