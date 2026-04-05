//! HTTP handler integration tests.
//!
//! These tests validate the actual axum handler processes requests correctly
//! using tower::ServiceExt::oneshot() for in-process HTTP testing (no TCP socket).
//! Tests use a populated AppState with known relay data.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::AtomicBool;
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
        leader_election: Arc::new(RedisLeaderElection::new(
            "127.0.0.1:6379",
            "test",
            0,
        )),
        magic_rotator: Arc::new(MagicRotator::new()),
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

