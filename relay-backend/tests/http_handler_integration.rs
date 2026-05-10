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
//   2. client_route_token (Token[0]) decrypts to RouteToken with
//      next_address = relay IP:port
//   3. wire_route_token (Token[1]) decrypts to RouteToken with
//      next_address = bench_server IP:port
//
// Encryption uses XChaCha20-Poly1305 with the derived relay_secret_key.
// Verifying the decrypted plaintext at the wire level proves the bench
// path (backend -> relay -> bench_client) carries the correct routing.
// ===================================================================

#[tokio::test]
async fn test_bench_token_two_token_wire_compat() {
    use blake2::{Blake2b512, Digest};
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
    use x25519_dalek::{PublicKey, StaticSecret};

    // Relay public key stored in relay_data (index 0 = "10.0.0.1:40000").
    let relay_pk_bytes = [0x42u8; 32];

    // Backend key pair (deterministic for this test).
    let backend_sk_bytes = [0x01u8; 32];
    let backend_pk_bytes: [u8; 32] = {
        let sk = StaticSecret::from(backend_sk_bytes);
        PublicKey::from(&sk).to_bytes()
    };

    // Expected relay_secret_key: BLAKE2b-512(q || relay_pk || backend_pk)[..32]
    // where q = X25519(backend_sk, relay_pk).
    let expected_key: [u8; 32] = {
        let backend_sk = StaticSecret::from(backend_sk_bytes);
        let relay_pk = PublicKey::from(relay_pk_bytes);
        let q = backend_sk.diffie_hellman(&relay_pk);
        let mut h = Blake2b512::new();
        h.update(q.as_bytes());
        h.update(relay_pk_bytes);
        h.update(backend_pk_bytes);
        let out = h.finalize();
        let mut k = [0u8; 32];
        k.copy_from_slice(&out[..32]);
        k
    };

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

    // Helper: decrypt a 111-byte XChaCha20-Poly1305 blob with the derived key.
    // Layout: [nonce 24B][ciphertext+tag 87B] -> plaintext 71B.
    let xchacha_decrypt = |blob: &[u8], key: &[u8; 32]| -> Vec<u8> {
        assert_eq!(blob.len(), 111, "encrypted token must be 111 bytes");
        let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
        let nonce = chacha20poly1305::XNonce::from_slice(&blob[..24]);
        cipher
            .decrypt(nonce, &blob[24..])
            .expect("XChaCha20Poly1305 decryption failed")
    };

    // RouteToken plaintext layout (relay-xdp-common, #[repr(C, packed)]):
    //   [0..32]  session_private_key
    //   [32..40] expire_timestamp (LE u64)
    //   [40..48] session_id       (LE u64)
    //   [48..52] envelope_kbps_up (LE u32)
    //   [52..56] envelope_kbps_down
    //   [56..60] next_address     (BE u32  = IP octets)
    //   [60..64] prev_address
    //   [64..66] next_port        (BE u16)
    //   [66..68] prev_port
    //   [68]     session_version
    //   [69]     next_internal
    //   [70]     prev_internal
    const NEXT_ADDR_OFF: usize = 56;
    const NEXT_PORT_OFF: usize = 64;

    // --- 2. Token[0]: client view -> next = relay (10.0.0.1:40000) -----------

    let client_token_blob = hex::decode(json["client_route_token"].as_str().unwrap()).unwrap();
    let client_plain = xchacha_decrypt(&client_token_blob, &relay_secret_key);
    assert_eq!(
        client_plain.len(),
        71,
        "decrypted RouteToken must be 71 bytes"
    );

    assert_eq!(
        &client_plain[NEXT_ADDR_OFF..NEXT_ADDR_OFF + 4],
        &[10u8, 0, 0, 1],
        "Token[0].next_address must be relay IP 10.0.0.1"
    );
    assert_eq!(
        u16::from_be_bytes(
            client_plain[NEXT_PORT_OFF..NEXT_PORT_OFF + 2]
                .try_into()
                .unwrap()
        ),
        40000u16,
        "Token[0].next_port must be relay port 40000"
    );

    // --- 3. Token[1]: wire view -> next = bench_server (10.0.0.2:7777) -------

    let wire_token_blob = hex::decode(json["wire_route_token"].as_str().unwrap()).unwrap();
    let wire_plain = xchacha_decrypt(&wire_token_blob, &relay_secret_key);
    assert_eq!(
        wire_plain.len(),
        71,
        "decrypted RouteToken must be 71 bytes"
    );

    assert_eq!(
        &wire_plain[NEXT_ADDR_OFF..NEXT_ADDR_OFF + 4],
        &[10u8, 0, 0, 2],
        "Token[1].next_address must be bench_server IP 10.0.0.2"
    );
    assert_eq!(
        u16::from_be_bytes(
            wire_plain[NEXT_PORT_OFF..NEXT_PORT_OFF + 2]
                .try_into()
                .unwrap()
        ),
        7777u16,
        "Token[1].next_port must be bench_server port 7777"
    );
}
