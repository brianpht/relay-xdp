//! HTTP handler integration tests.
//!
//! These tests validate the actual axum handler processes requests correctly
//! using tower::ServiceExt::oneshot() for in-process HTTP testing (no TCP socket).
//! Tests use a populated AppState with known relay data.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use relay_backend::config::Config;
use relay_backend::constants::*;
use relay_backend::database::RelayData;
use relay_backend::handlers::create_router;
use relay_backend::magic::MagicRotator;
use relay_backend::redis_client::RedisLeaderElection;
use relay_backend::relay_manager::RelayManager;
use relay_backend::relay_update::relay_id;
use relay_backend::state::AppState;

// -------------------------------------------------------
// Test helpers
// -------------------------------------------------------

/// Create a test Config with sensible defaults (no env vars required).
fn test_config() -> Config {
    Config {
        max_jitter: 1000,
        max_packet_loss: 100.0,
        route_matrix_interval_ms: 1000,
        initial_delay: 0,
        http_port: 0,
        admin_http_port: 0,
        admin_bind_address: "127.0.0.1".to_string(),
        enable_relay_history: false,
        redis_hostname: "127.0.0.1:6379".to_string(),
        internal_address: "127.0.0.1".to_string(),
        internal_port: "0".to_string(),
        relay_backend_public_key: vec![],
        relay_backend_private_key: vec![],
        relay_data_file: None,
    }
}

/// Create a RelayData with known test relays.
fn test_relay_data() -> RelayData {
    let addresses = vec![
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40000),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 40000),
    ];

    let ids: Vec<u64> = addresses
        .iter()
        .map(|a| relay_id(&format!("{}", a)))
        .collect();

    let mut id_to_index = HashMap::new();
    for (i, &id) in ids.iter().enumerate() {
        id_to_index.insert(id, i);
    }

    RelayData {
        num_relays: 3,
        relay_ids: ids,
        relay_addresses: addresses,
        relay_names: vec![
            "relay-a".to_string(),
            "relay-b".to_string(),
            "relay-c".to_string(),
        ],
        relay_latitudes: vec![0.0; 3],
        relay_longitudes: vec![0.0; 3],
        relay_datacenter_ids: vec![1, 2, 3],
        relay_price: vec![0; 3],
        relay_id_to_index: id_to_index,
        dest_relays: vec![true; 3],
        database_bin_file: vec![],
        relay_public_keys: vec![[0u8; 32]; 3],
        relay_internal_addresses: vec![None; 3],
    }
}

/// Create a test AppState with known relays.
fn test_app_state() -> Arc<AppState> {
    Arc::new(AppState {
        config: Arc::new(test_config()),
        relay_data: Arc::new(test_relay_data()),
        relay_manager: Arc::new(RelayManager::new(false)),
        relays_csv: RwLock::new(vec![]),
        cost_matrix_data: RwLock::new(vec![]),
        route_matrix_data: RwLock::new(vec![]),
        start_time: SystemTime::now(),
        delay_completed: AtomicBool::new(true),
        leader_election: Arc::new(RedisLeaderElection::new("127.0.0.1:6379", "test", 0)),
        magic_rotator: Arc::new(MagicRotator::new()),
        last_optimize_ms: AtomicU64::new(0),
        nonce_cache: relay_backend::replay::NonceCache::new(),
        relay_update_replay_rejected: AtomicU64::new(0),
        relay_update_clock_skew_rejected: AtomicU64::new(0),
    })
}

/// Build a valid relay update request body for a known relay address.
/// Uses raw byte construction matching relay-backend's SimpleReader format.
fn build_valid_request_body(addr: SocketAddrV4) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2048);

    // version
    buf.push(1u8);

    // address: type(1) + ip octets(4) + port(2 LE)
    buf.push(1u8); // IPv4
    buf.extend_from_slice(&addr.ip().octets());
    buf.extend_from_slice(&addr.port().to_le_bytes());

    // current_time, start_time
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    buf.extend_from_slice(&now.to_le_bytes());
    buf.extend_from_slice(&(now - 1000).to_le_bytes());

    // num_samples = 0
    buf.extend_from_slice(&0u32.to_le_bytes());

    // session_count, envelope_bw_up, envelope_bw_down
    buf.extend_from_slice(&10u32.to_le_bytes());
    buf.extend_from_slice(&100u32.to_le_bytes());
    buf.extend_from_slice(&200u32.to_le_bytes());

    // 7 float32 fields (all zero)
    for _ in 0..7 {
        buf.extend_from_slice(&0.0f32.to_bits().to_le_bytes());
    }

    // relay_flags
    buf.extend_from_slice(&0u64.to_le_bytes());

    // relay_version
    let ver = b"test-relay";
    buf.extend_from_slice(&(ver.len() as u32).to_le_bytes());
    buf.extend_from_slice(ver);

    // num_relay_counters + counters
    buf.extend_from_slice(&(NUM_RELAY_COUNTERS as u32).to_le_bytes());
    for _ in 0..NUM_RELAY_COUNTERS {
        buf.extend_from_slice(&0u64.to_le_bytes());
    }

    buf
}

// ===================================================================
// Test 1: Valid request returns 200 OK
// ===================================================================

#[tokio::test]
async fn test_relay_update_valid_request_returns_ok() {
    let state = test_app_state();
    let app = create_router(state.clone());

    let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let body = build_valid_request_body(addr);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/relay_update")
                .header("content-type", "application/octet-stream")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ===================================================================
// Test 2: Unknown relay returns 404
// ===================================================================

#[tokio::test]
async fn test_relay_update_unknown_relay_returns_not_found() {
    let state = test_app_state();
    let app = create_router(state);

    // Use an address not in our test relay data
    let addr = SocketAddrV4::new(Ipv4Addr::new(99, 99, 99, 99), 12345);
    let body = build_valid_request_body(addr);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/relay_update")
                .header("content-type", "application/octet-stream")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ===================================================================
// Test 3: Too-small body returns 400
// ===================================================================

#[tokio::test]
async fn test_relay_update_too_small_returns_bad_request() {
    let state = test_app_state();
    let app = create_router(state);

    // Body smaller than 64 bytes
    let body = vec![0u8; 32];

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/relay_update")
                .header("content-type", "application/octet-stream")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ===================================================================
// Test 4: Too-large body returns error (413 from axum or 400 from handler)
// ===================================================================

#[tokio::test]
async fn test_relay_update_too_large_returns_error() {
    let state = test_app_state();
    let app = create_router(state);

    // Body larger than 2MB - axum may reject this with 413 Payload Too Large
    // before the handler's own 2MB check runs (returns 400).
    let body = vec![0u8; 3 * 1024 * 1024];

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/relay_update")
                .header("content-type", "application/octet-stream")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status().is_client_error(),
        "oversized body should return 4xx, got {}",
        response.status()
    );
}

// ===================================================================
// Test 5: Invalid format (valid size but garbage) returns 400
// ===================================================================

#[tokio::test]
async fn test_relay_update_invalid_format_returns_bad_request() {
    let state = test_app_state();
    let app = create_router(state);

    // 128 bytes of garbage - version byte 0xFF is invalid
    let body = vec![0xFF; 128];

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/relay_update")
                .header("content-type", "application/octet-stream")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ===================================================================
// Test 6: Valid request updates RelayManager state
// ===================================================================

#[tokio::test]
async fn test_relay_update_updates_relay_manager_state() {
    let state = test_app_state();
    let app = create_router(state.clone());

    let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let body = build_valid_request_body(addr);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/relay_update")
                .header("content-type", "application/octet-stream")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify relay manager now has this relay as active
    let current_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let active = state.relay_manager.get_active_relays(current_time);
    assert_eq!(active.len(), 1, "should have 1 active relay after update");
    assert_eq!(active[0].name, "relay-a");
    assert_eq!(active[0].sessions, 10);
}

// ===================================================================
// Test 7: GET /bench_token returns 200 with correct JSON shape
// ===================================================================

#[tokio::test]
async fn test_bench_token_returns_ok_with_correct_shape() {
    let state = test_app_state();
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/bench_token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Verify all required fields are present.
    assert!(json.get("session_id").is_some(), "missing session_id");
    assert!(
        json.get("session_version").is_some(),
        "missing session_version"
    );
    assert!(
        json.get("session_private_key").is_some(),
        "missing session_private_key"
    );
    assert!(
        json.get("relay_backend_public_key").is_some(),
        "missing relay_backend_public_key"
    );
    assert!(json.get("relay_address").is_some(), "missing relay_address");
    assert!(json.get("current_magic").is_some(), "missing current_magic");

    // session_version must be 1.
    assert_eq!(json["session_version"].as_u64().unwrap(), 1);

    // session_private_key must be 64 hex chars (32 bytes).
    let priv_key_hex = json["session_private_key"].as_str().unwrap();
    assert_eq!(
        priv_key_hex.len(),
        64,
        "session_private_key must be 64 hex chars"
    );
    assert!(
        priv_key_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "session_private_key must be valid hex"
    );

    // relay_backend_public_key must be 64 hex chars (32 bytes).
    let pk_hex = json["relay_backend_public_key"].as_str().unwrap();
    assert_eq!(
        pk_hex.len(),
        64,
        "relay_backend_public_key must be 64 hex chars"
    );
    assert!(
        pk_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "relay_backend_public_key must be valid hex"
    );

    // current_magic must be 16 hex chars (8 bytes).
    let magic_hex = json["current_magic"].as_str().unwrap();
    assert_eq!(magic_hex.len(), 16, "current_magic must be 16 hex chars");
    assert!(
        magic_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "current_magic must be valid hex"
    );
}

// ===================================================================
// Test 8: GET /bench_token?relay_addr=IP:PORT echoes relay_address
// ===================================================================

#[tokio::test]
async fn test_bench_token_relay_addr_query_param_echoed() {
    let state = test_app_state();
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/bench_token?relay_addr=10.0.0.1:40000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(
        json["relay_address"].as_str().unwrap(),
        "10.0.0.1:40000",
        "relay_address must echo the relay_addr query param"
    );
}

// ===================================================================
// Test 9: GET /bench_token without relay_addr returns empty relay_address
// ===================================================================

#[tokio::test]
async fn test_bench_token_no_relay_addr_returns_empty() {
    let state = test_app_state();
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/bench_token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(
        json["relay_address"].as_str().unwrap(),
        "",
        "relay_address must be empty when relay_addr is not provided"
    );
}

// ===================================================================
// Test 10: GET /bench_token reflects known relay_backend_public_key
// ===================================================================

#[tokio::test]
async fn test_bench_token_reflects_configured_public_key() {
    // Use a known 32-byte public key in config.
    let known_pk = [0xABu8; 32];
    let expected_hex = known_pk
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let mut config = test_config();
    config.relay_backend_public_key = known_pk.to_vec();

    let state = Arc::new(AppState {
        config: Arc::new(config),
        relay_data: Arc::new(test_relay_data()),
        relay_manager: Arc::new(RelayManager::new(false)),
        relays_csv: RwLock::new(vec![]),
        cost_matrix_data: RwLock::new(vec![]),
        route_matrix_data: RwLock::new(vec![]),
        start_time: SystemTime::now(),
        delay_completed: AtomicBool::new(true),
        leader_election: Arc::new(RedisLeaderElection::new("127.0.0.1:6379", "test", 0)),
        magic_rotator: Arc::new(MagicRotator::new()),
        last_optimize_ms: AtomicU64::new(0),
        nonce_cache: relay_backend::replay::NonceCache::new(),
        relay_update_replay_rejected: AtomicU64::new(0),
        relay_update_clock_skew_rejected: AtomicU64::new(0),
    });

    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/bench_token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(
        json["relay_backend_public_key"].as_str().unwrap(),
        expected_hex,
        "relay_backend_public_key must match the configured key"
    );
}

// ===================================================================
// Test 11: GET /bench_token returns unique session_id on each call
// ===================================================================

#[tokio::test]
async fn test_bench_token_unique_session_ids() {
    let state = test_app_state();

    async fn get_session_id(state: Arc<AppState>) -> u64 {
        let app = create_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/bench_token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        json["session_id"].as_u64().unwrap()
    }

    let id1 = get_session_id(state.clone()).await;
    let id2 = get_session_id(state.clone()).await;

    assert_ne!(
        id1, id2,
        "each /bench_token call must return a unique session_id"
    );
}

// ===================================================================
// Test 12: /bench_token two-token wire-compat test
//
// Verifies that:
//   1. relay_secret_key = BLAKE2b-512(X25519(backend_sk, relay_pk)
//                                     || relay_pk || backend_pk)[..32]
//   2. client_route_token (Token[0]) decrypts via relay_sdk::tokens::decrypt_route_token
//      and carries next_address = relay IP:port, prev_address = 0 (no ConnectInfo)
//   3. wire_route_token (Token[1]) decrypts via relay_sdk::tokens::decrypt_route_token
//      and carries next_address = bench_server IP:port, prev_address = 0 (no ConnectInfo)
//
// Uses relay_sdk::tokens::decrypt_route_token (the same function the SDK uses on wire
// traffic) to prove end-to-end compatibility across the backend -> eBPF -> client path.
// ===================================================================

#[tokio::test]
async fn test_bench_token_two_token_wire_compat() {
    use relay_sdk::crypto::derive_relay_session_key;
    use relay_sdk::tokens::decrypt_route_token;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Relay public key stored in relay_data (index 0 = "10.0.0.1:40000").
    let relay_pk_bytes = [0x42u8; 32];

    // Backend key pair (deterministic for this test).
    let backend_sk_bytes = [0x01u8; 32];
    let backend_pk_bytes: [u8; 32] = {
        let sk = StaticSecret::from(backend_sk_bytes);
        PublicKey::from(&sk).to_bytes()
    };

    // Expected relay_secret_key via shared derive_relay_session_key
    // (backend side: my_sk=backend_sk, their_pk=relay_pk, relay_pk=relay_pk, backend_pk=backend_pk).
    let expected_key: [u8; 32] = derive_relay_session_key(
        &backend_sk_bytes,
        &relay_pk_bytes,
        &relay_pk_bytes,
        &backend_pk_bytes,
    );

    // Relay data with known public key at index 0.
    let mut rd = test_relay_data();
    rd.relay_public_keys[0] = relay_pk_bytes;

    let state = Arc::new(AppState {
        config: Arc::new(Config {
            relay_backend_private_key: backend_sk_bytes.to_vec(),
            relay_backend_public_key: backend_pk_bytes.to_vec(),
            ..test_config()
        }),
        relay_data: Arc::new(rd),
        relay_manager: Arc::new(RelayManager::new(false)),
        relays_csv: RwLock::new(vec![]),
        cost_matrix_data: RwLock::new(vec![]),
        route_matrix_data: RwLock::new(vec![]),
        start_time: SystemTime::now(),
        delay_completed: AtomicBool::new(true),
        leader_election: Arc::new(RedisLeaderElection::new("127.0.0.1:6379", "test", 0)),
        magic_rotator: Arc::new(MagicRotator::new()),
        last_optimize_ms: AtomicU64::new(0),
        nonce_cache: relay_backend::replay::NonceCache::new(),
        relay_update_replay_rejected: AtomicU64::new(0),
        relay_update_clock_skew_rejected: AtomicU64::new(0),
    });

    let app = create_router(state);

    // relay = "10.0.0.1:40000", bench_server = "10.0.0.2:7777"
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/bench_token?relay_addr=10.0.0.1:40000&bench_server_addr=10.0.0.2:7777")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // --- 1. Verify relay_secret_key matches X25519 + BLAKE2b derivation -------

    let relay_secret_key_hex = json["relay_secret_key"].as_str().unwrap();
    assert!(
        !relay_secret_key_hex.is_empty(),
        "relay_secret_key must be present when relay_addr + bench_server_addr given"
    );
    let relay_secret_key: [u8; 32] = hex::decode(relay_secret_key_hex)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        relay_secret_key, expected_key,
        "relay_secret_key must equal BLAKE2b-512(X25519(backend_sk, relay_pk) \
         || relay_pk || backend_pk)[..32]"
    );

    // Helper: hex-decode a token blob and call relay_sdk::tokens::decrypt_route_token.
    // Returns the typed RouteToken struct (fields accessed as packed - copy out before use).
    let sdk_decrypt = |hex_str: &str, key: &[u8; 32]| -> relay_xdp_common::RouteToken {
        let blob: [u8; 111] = hex::decode(hex_str)
            .expect("token hex decode failed")
            .try_into()
            .expect("encrypted token must be 111 bytes");
        decrypt_route_token(&blob, key).expect("relay_sdk::tokens::decrypt_route_token failed")
    };

    // --- 2. Token[0]: client view -> next = relay (10.0.0.1:40000) -----------
    // prev_address = 0 because tower::oneshot does not provide ConnectInfo;
    // the handler falls back to empty string -> 0.0.0.0.

    let client_token = sdk_decrypt(
        json["client_route_token"].as_str().unwrap(),
        &relay_secret_key,
    );

    // next_address is stored as ip.to_be() in the packed struct.
    // u32::from_be() reverses that to get host-order; compare with u32::from_be_bytes(octets).
    let next_addr_0: u32 = client_token.next_address;
    assert_eq!(
        u32::from_be(next_addr_0),
        u32::from_be_bytes([10u8, 0, 0, 1]),
        "Token[0].next_address must be relay IP 10.0.0.1"
    );
    let next_port_0: u16 = client_token.next_port;
    assert_eq!(
        u16::from_be(next_port_0),
        40000u16,
        "Token[0].next_port must be relay port 40000"
    );
    // No ConnectInfo in oneshot -> prev_address = 0 (0.0.0.0).
    let prev_addr_0: u32 = client_token.prev_address;
    assert_eq!(
        prev_addr_0, 0,
        "Token[0].prev_address must be 0 when no ConnectInfo is present"
    );

    // --- 3. Token[1]: wire view -> next = bench_server (10.0.0.2:7777) -------
    // prev_address = 0 for the same reason (no ConnectInfo in oneshot).
    // In production the handler sets prev_address = client public IPv4 so that
    // the relay's eBPF can use it as the ROUTE_RESPONSE redirect target.

    let wire_token = sdk_decrypt(
        json["wire_route_token"].as_str().unwrap(),
        &relay_secret_key,
    );

    let next_addr_1: u32 = wire_token.next_address;
    assert_eq!(
        u32::from_be(next_addr_1),
        u32::from_be_bytes([10u8, 0, 0, 2]),
        "Token[1].next_address must be bench_server IP 10.0.0.2"
    );
    let next_port_1: u16 = wire_token.next_port;
    assert_eq!(
        u16::from_be(next_port_1),
        7777u16,
        "Token[1].next_port must be bench_server port 7777"
    );
    // prev_address = 0 (no ConnectInfo). In a live run this is the client public IPv4
    // extracted from the TCP connection - not reproducible in an in-process oneshot test.
    let prev_addr_1: u32 = wire_token.prev_address;
    assert_eq!(
        prev_addr_1, 0,
        "Token[1].prev_address must be 0 when no ConnectInfo is present"
    );
}

// ===================================================================
// Test 13: GET /bench_token with relay_chain builds N-hop token chain
//
// Verifies two-relay chain (relay_chain=10.0.0.1:40000,10.0.0.2:40000
// &bench_server_addr=10.0.0.3:7777):
//   relay_secret_key  = key for relay-a (index 0)
//   client_route_token (Token[0]):
//     - decryptable with key_a
//     - next_address = relay-a (10.0.0.1:40000)
//   relay_chain_tokens[0] (Token[1]):
//     - decryptable with key_a (relay-a decrypts this)
//     - next_address = relay-b (10.0.0.2:40000)
//     - prev_address = 0 (no ConnectInfo in oneshot)
//   relay_chain_tokens[1] (Token[2]):
//     - decryptable with key_b (relay-b decrypts this)
//     - next_address = bench_server (10.0.0.3:7777)
//     - prev_address = relay-a.ip (10.0.0.1) from relay_data
// ===================================================================

#[tokio::test]
async fn test_bench_token_chain_two_relays() {
    use relay_sdk::crypto::derive_relay_session_key;
    use relay_sdk::tokens::decrypt_route_token;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Known relay public keys for relay-a (index 0) and relay-b (index 1).
    let relay_a_pk = [0x42u8; 32];
    let relay_b_pk = [0x43u8; 32];

    // Backend key pair (deterministic for this test).
    let backend_sk_bytes = [0x01u8; 32];
    let backend_pk_bytes: [u8; 32] = {
        let sk = StaticSecret::from(backend_sk_bytes);
        PublicKey::from(&sk).to_bytes()
    };

    // Expected per-relay symmetric keys.
    let key_a: [u8; 32] = derive_relay_session_key(
        &backend_sk_bytes,
        &relay_a_pk,
        &relay_a_pk,
        &backend_pk_bytes,
    );
    let key_b: [u8; 32] = derive_relay_session_key(
        &backend_sk_bytes,
        &relay_b_pk,
        &relay_b_pk,
        &backend_pk_bytes,
    );

    // Relay data with known public keys at index 0 and 1.
    let mut rd = test_relay_data();
    rd.relay_public_keys[0] = relay_a_pk;
    rd.relay_public_keys[1] = relay_b_pk;

    let state = Arc::new(AppState {
        config: Arc::new(Config {
            relay_backend_private_key: backend_sk_bytes.to_vec(),
            relay_backend_public_key: backend_pk_bytes.to_vec(),
            ..test_config()
        }),
        relay_data: Arc::new(rd),
        relay_manager: Arc::new(RelayManager::new(false)),
        relays_csv: RwLock::new(vec![]),
        cost_matrix_data: RwLock::new(vec![]),
        route_matrix_data: RwLock::new(vec![]),
        start_time: SystemTime::now(),
        delay_completed: AtomicBool::new(true),
        leader_election: Arc::new(RedisLeaderElection::new("127.0.0.1:6379", "test", 0)),
        magic_rotator: Arc::new(MagicRotator::new()),
        last_optimize_ms: AtomicU64::new(0),
        nonce_cache: relay_backend::replay::NonceCache::new(),
        relay_update_replay_rejected: AtomicU64::new(0),
        relay_update_clock_skew_rejected: AtomicU64::new(0),
    });

    let app = create_router(state);

    // relay_chain = relay-a, relay-b (2 hops)
    // bench_server = 10.0.0.3:7777
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/bench_token?relay_chain=10.0.0.1:40000,10.0.0.2:40000&bench_server_addr=10.0.0.3:7777")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Helper: hex-decode + decrypt a RouteToken.
    let sdk_decrypt = |hex_str: &str, key: &[u8; 32]| -> relay_xdp_common::RouteToken {
        let blob: [u8; 111] = hex::decode(hex_str)
            .expect("token hex decode failed")
            .try_into()
            .expect("encrypted token must be 111 bytes");
        decrypt_route_token(&blob, key).expect("decrypt_route_token failed")
    };

    // relay_secret_key must equal key_a.
    let relay_secret_key_hex = json["relay_secret_key"].as_str().unwrap();
    assert!(
        !relay_secret_key_hex.is_empty(),
        "relay_secret_key must be present"
    );
    let relay_secret_key: [u8; 32] = hex::decode(relay_secret_key_hex)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(relay_secret_key, key_a, "relay_secret_key must equal key_a");

    // Token[0] (client_route_token): decryptable with key_a, next = relay-a.
    let client_token = sdk_decrypt(json["client_route_token"].as_str().unwrap(), &key_a);
    let ct_next_addr: u32 = client_token.next_address;
    let ct_next_port: u16 = client_token.next_port;
    assert_eq!(
        u32::from_be(ct_next_addr),
        u32::from_be_bytes([10, 0, 0, 1]),
        "Token[0].next_address must be relay-a 10.0.0.1"
    );
    assert_eq!(
        u16::from_be(ct_next_port),
        40000u16,
        "Token[0].next_port must be 40000"
    );

    // relay_chain_tokens must have exactly 2 entries for a 2-relay chain.
    // Token[1] = relay-a wire token (decrypted by relay-a, encrypted with key_a).
    // Token[2] = relay-b wire token (decrypted by relay-b, encrypted with key_b).
    let chain_tokens = json["relay_chain_tokens"]
        .as_array()
        .expect("relay_chain_tokens must be an array");
    assert_eq!(
        chain_tokens.len(),
        2,
        "relay_chain_tokens must have 2 entries for a 2-relay chain"
    );

    // Token[1] (chain_tokens[0]): relay-a wire token.
    // Decryptable with key_a. next = relay-b (10.0.0.2:40000). prev = 0 (no ConnectInfo).
    let wire_1 = sdk_decrypt(chain_tokens[0].as_str().unwrap(), &key_a);
    let w1_next_addr: u32 = wire_1.next_address;
    let w1_next_port: u16 = wire_1.next_port;
    let w1_prev_addr: u32 = wire_1.prev_address;
    assert_eq!(
        u32::from_be(w1_next_addr),
        u32::from_be_bytes([10, 0, 0, 2]),
        "relay_chain_tokens[0].next_address must be relay-b 10.0.0.2"
    );
    assert_eq!(
        u16::from_be(w1_next_port),
        40000u16,
        "relay_chain_tokens[0].next_port must be 40000"
    );
    assert_eq!(
        w1_prev_addr, 0,
        "relay_chain_tokens[0].prev_address must be 0 (no ConnectInfo)"
    );

    // Token[2] (chain_tokens[1]): relay-b wire token.
    // Decryptable with key_b. next = bench_server (10.0.0.3:7777).
    // prev = relay-a public IP = 10.0.0.1 (from relay_data.relay_addresses[0]).
    let wire_2 = sdk_decrypt(chain_tokens[1].as_str().unwrap(), &key_b);
    let w2_next_addr: u32 = wire_2.next_address;
    let w2_next_port: u16 = wire_2.next_port;
    let w2_prev_addr: u32 = wire_2.prev_address;
    assert_eq!(
        u32::from_be(w2_next_addr),
        u32::from_be_bytes([10, 0, 0, 3]),
        "relay_chain_tokens[1].next_address must be bench_server 10.0.0.3"
    );
    assert_eq!(
        u16::from_be(w2_next_port),
        7777u16,
        "relay_chain_tokens[1].next_port must be 7777"
    );
    assert_eq!(
        u32::from_be(w2_prev_addr),
        u32::from_be_bytes([10, 0, 0, 1]),
        "relay_chain_tokens[1].prev_address must be relay-a IP 10.0.0.1"
    );
}

// ===================================================================
// Test 14: 3-relay chain hit the MAX_RELAY_HOPS bound (upper bound test).
/// relay_chain = relay-a, relay-b, relay-c (10.0.0.1, .2, .3 all :40000)
/// Expected: HTTP 200, relay_chain_tokens has 3 entries.
/// Token[1]: encrypted with key_a, next = relay-b, prev = 0 (no ConnectInfo)
/// Token[2]: encrypted with key_b, next = relay-c, prev = relay-a IP (10.0.0.1)
/// Token[3]: encrypted with key_c, next = bench_server, prev = relay-b IP (10.0.0.2)
#[tokio::test]
async fn test_bench_token_chain_three_relays() {
    use relay_sdk::crypto::derive_relay_session_key;
    use relay_sdk::tokens::decrypt_route_token;
    use x25519_dalek::{PublicKey, StaticSecret};

    let relay_a_pk = [0x42u8; 32];
    let relay_b_pk = [0x43u8; 32];
    let relay_c_pk = [0x44u8; 32];

    let backend_sk_bytes = [0x01u8; 32];
    let backend_pk_bytes: [u8; 32] = {
        let sk = StaticSecret::from(backend_sk_bytes);
        PublicKey::from(&sk).to_bytes()
    };

    let key_a: [u8; 32] = derive_relay_session_key(
        &backend_sk_bytes,
        &relay_a_pk,
        &relay_a_pk,
        &backend_pk_bytes,
    );
    let key_b: [u8; 32] = derive_relay_session_key(
        &backend_sk_bytes,
        &relay_b_pk,
        &relay_b_pk,
        &backend_pk_bytes,
    );
    let key_c: [u8; 32] = derive_relay_session_key(
        &backend_sk_bytes,
        &relay_c_pk,
        &relay_c_pk,
        &backend_pk_bytes,
    );

    let mut rd = test_relay_data();
    rd.relay_public_keys[0] = relay_a_pk;
    rd.relay_public_keys[1] = relay_b_pk;
    rd.relay_public_keys[2] = relay_c_pk;

    let state = Arc::new(AppState {
        config: Arc::new(Config {
            relay_backend_private_key: backend_sk_bytes.to_vec(),
            relay_backend_public_key: backend_pk_bytes.to_vec(),
            ..test_config()
        }),
        relay_data: Arc::new(rd),
        relay_manager: Arc::new(RelayManager::new(false)),
        relays_csv: RwLock::new(vec![]),
        cost_matrix_data: RwLock::new(vec![]),
        route_matrix_data: RwLock::new(vec![]),
        start_time: SystemTime::now(),
        delay_completed: AtomicBool::new(true),
        leader_election: Arc::new(RedisLeaderElection::new("127.0.0.1:6379", "test", 0)),
        magic_rotator: Arc::new(MagicRotator::new()),
        last_optimize_ms: AtomicU64::new(0),
        nonce_cache: relay_backend::replay::NonceCache::new(),
        relay_update_replay_rejected: AtomicU64::new(0),
        relay_update_clock_skew_rejected: AtomicU64::new(0),
    });

    let app = create_router(state);

    // relay_chain = relay-a, relay-b, relay-c (3 hops = MAX_RELAY_HOPS)
    // bench_server = 10.0.0.4:8888
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/bench_token?relay_chain=10.0.0.1:40000,10.0.0.2:40000,10.0.0.3:40000&bench_server_addr=10.0.0.4:8888")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "3-relay chain must return HTTP 200"
    );

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let sdk_decrypt = |hex_str: &str, key: &[u8; 32]| -> relay_xdp_common::RouteToken {
        let blob: [u8; 111] = hex::decode(hex_str)
            .expect("token hex decode failed")
            .try_into()
            .expect("encrypted token must be 111 bytes");
        decrypt_route_token(&blob, key).expect("decrypt_route_token failed")
    };

    // relay_secret_key must equal key_a (first relay's key).
    let relay_secret_key_hex = json["relay_secret_key"].as_str().unwrap();
    let relay_secret_key: [u8; 32] = hex::decode(relay_secret_key_hex)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(relay_secret_key, key_a, "relay_secret_key must equal key_a");

    // Token[0] (client_route_token): next = relay-a (10.0.0.1:40000).
    let client_token = sdk_decrypt(json["client_route_token"].as_str().unwrap(), &key_a);
    assert_eq!(
        u32::from_be(client_token.next_address),
        u32::from_be_bytes([10, 0, 0, 1]),
        "Token[0].next_address must be relay-a 10.0.0.1"
    );
    assert_eq!(
        u16::from_be(client_token.next_port),
        40000u16,
        "Token[0].next_port must be 40000"
    );

    // relay_chain_tokens must have exactly 3 entries for a 3-relay chain.
    let chain_tokens = json["relay_chain_tokens"]
        .as_array()
        .expect("relay_chain_tokens must be an array");
    assert_eq!(
        chain_tokens.len(),
        3,
        "relay_chain_tokens must have 3 entries for a 3-relay chain"
    );

    // Token[1] (chain_tokens[0]): relay-a wire token.
    // Decryptable with key_a. next = relay-b (10.0.0.2:40000). prev = 0 (no ConnectInfo).
    let wire_1 = sdk_decrypt(chain_tokens[0].as_str().unwrap(), &key_a);
    let w1_next_addr: u32 = wire_1.next_address;
    let w1_next_port: u16 = wire_1.next_port;
    let w1_prev_addr: u32 = wire_1.prev_address;
    assert_eq!(
        u32::from_be(w1_next_addr),
        u32::from_be_bytes([10, 0, 0, 2]),
        "Token[1].next_address must be relay-b 10.0.0.2"
    );
    assert_eq!(
        u16::from_be(w1_next_port),
        40000u16,
        "Token[1].next_port must be 40000"
    );
    assert_eq!(
        w1_prev_addr, 0,
        "Token[1].prev_address must be 0 (no ConnectInfo)"
    );

    // Token[2] (chain_tokens[1]): relay-b wire token.
    // Decryptable with key_b. next = relay-c (10.0.0.3:40000).
    // prev = relay-a public IP (10.0.0.1 from relay_data.relay_addresses[0]).
    let wire_2 = sdk_decrypt(chain_tokens[1].as_str().unwrap(), &key_b);
    let w2_next_addr: u32 = wire_2.next_address;
    let w2_next_port: u16 = wire_2.next_port;
    let w2_prev_addr: u32 = wire_2.prev_address;
    assert_eq!(
        u32::from_be(w2_next_addr),
        u32::from_be_bytes([10, 0, 0, 3]),
        "Token[2].next_address must be relay-c 10.0.0.3"
    );
    assert_eq!(
        u16::from_be(w2_next_port),
        40000u16,
        "Token[2].next_port must be 40000"
    );
    assert_eq!(
        u32::from_be(w2_prev_addr),
        u32::from_be_bytes([10, 0, 0, 1]),
        "Token[2].prev_address must be relay-a IP 10.0.0.1"
    );

    // Token[3] (chain_tokens[2]): relay-c wire token.
    // Decryptable with key_c. next = bench_server (10.0.0.4:8888).
    // prev = relay-b public IP (10.0.0.2 from relay_data.relay_addresses[1]).
    let wire_3 = sdk_decrypt(chain_tokens[2].as_str().unwrap(), &key_c);
    let w3_next_addr: u32 = wire_3.next_address;
    let w3_next_port: u16 = wire_3.next_port;
    let w3_prev_addr: u32 = wire_3.prev_address;
    assert_eq!(
        u32::from_be(w3_next_addr),
        u32::from_be_bytes([10, 0, 0, 4]),
        "Token[3].next_address must be bench_server 10.0.0.4"
    );
    assert_eq!(
        u16::from_be(w3_next_port),
        8888u16,
        "Token[3].next_port must be 8888"
    );
    assert_eq!(
        u32::from_be(w3_prev_addr),
        u32::from_be_bytes([10, 0, 0, 2]),
        "Token[3].prev_address must be relay-b IP 10.0.0.2"
    );
}

/// Test 15: relay chain that exceeds MAX_RELAY_HOPS must be rejected
/// (clamp enforcement test). MAX_RELAY_HOPS = 5, so 6-relay chain must HTTP 400.
#[tokio::test]
async fn test_bench_token_chain_exceeds_max_relays_rejected() {
    let state = Arc::new(AppState {
        config: Arc::new(Config {
            relay_backend_private_key: vec![0x01u8; 32],
            relay_backend_public_key: vec![0x02u8; 32],
            ..test_config()
        }),
        relay_data: Arc::new(test_relay_data()),
        relay_manager: Arc::new(RelayManager::new(false)),
        relays_csv: RwLock::new(vec![]),
        cost_matrix_data: RwLock::new(vec![]),
        route_matrix_data: RwLock::new(vec![]),
        start_time: SystemTime::now(),
        delay_completed: AtomicBool::new(true),
        leader_election: Arc::new(RedisLeaderElection::new("127.0.0.1:6379", "test", 0)),
        magic_rotator: Arc::new(MagicRotator::new()),
        last_optimize_ms: AtomicU64::new(0),
        nonce_cache: relay_backend::replay::NonceCache::new(),
        relay_update_replay_rejected: AtomicU64::new(0),
        relay_update_clock_skew_rejected: AtomicU64::new(0),
    });

    let app = create_router(state);

    // 6 relays in chain: exceeds MAX_RELAY_HOPS = 5.
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/bench_token?relay_chain=10.0.0.1:40000,10.0.0.2:40000,10.0.0.3:40000,10.0.0.4:40000,10.0.0.5:40000,10.0.0.6:40000&bench_server_addr=10.0.0.7:7777")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "6-relay chain (> MAX_RELAY_HOPS=5) must return HTTP 400"
    );
}
