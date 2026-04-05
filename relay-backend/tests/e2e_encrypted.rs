//! End-to-end encrypted relay update tests.
//!
//! These tests exercise the full crypto path:
//!   relay-xdp encrypts request (SalsaBox) -> relay-backend decrypts -> processes -> 200 OK
//!
//! The encryption matches relay-xdp's main_thread.rs::update() wire format:
//!   [header 8B plaintext] + [MAC 16B] + [ciphertext] + [nonce 24B]
//!
//! Header: version(1) + addr_type(1) + ip(4) + port(2)

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crypto_box::aead::AeadInPlace;

use relay_backend::config::Config;
use relay_backend::constants::*;
use relay_backend::database::RelayData;
use relay_backend::handlers::create_router;
use relay_backend::magic::MagicRotator;
use relay_backend::redis_client::RedisLeaderElection;
use relay_backend::relay_manager::RelayManager;
use relay_backend::relay_update::relay_id;
use relay_backend::state::AppState;

use relay_xdp::encoding::Writer as XdpWriter;
use relay_xdp_common::{RELAY_ADDRESS_IPV4, RELAY_NUM_COUNTERS, RELAY_VERSION_LENGTH};

// -------------------------------------------------------
// Crypto helpers
// -------------------------------------------------------

const HEADER_SIZE: usize = 8; // version(1) + addr_type(1) + ip(4) + port(2)
const NONCE_SIZE: usize = 24;

/// Generate a fresh X25519 keypair for crypto_box (SalsaBox).
fn generate_keypair() -> (crypto_box::SecretKey, crypto_box::PublicKey) {
    let sk = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
    let pk = sk.public_key();
    (sk, pk)
}

// -------------------------------------------------------
// Request builder (mimics relay-xdp main_thread.rs::update)
// -------------------------------------------------------

/// Build a plaintext relay update request using relay-xdp's Writer,
/// matching the exact wire format that main_thread.rs produces.
fn build_plaintext_request(
    relay_public_address: u32, // host byte order
    relay_port: u16,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    let mut w = XdpWriter::new(&mut buf);

    // Header (8 bytes - stays plaintext in encrypted mode)
    w.write_uint8(1); // version
    w.write_uint8(RELAY_ADDRESS_IPV4);
    w.write_uint32(relay_public_address.to_be());
    w.write_uint16(relay_port);

    // Body (gets encrypted)
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    w.write_uint64(now);
    w.write_uint64(now - 1000); // start_time

    w.write_uint32(0); // num_samples

    w.write_uint32(5); // session_count
    w.write_uint32(100); // envelope_bw_up
    w.write_uint32(200); // envelope_bw_down
    for _ in 0..7 {
        w.write_float32(0.0);
    }

    w.write_uint64(0); // relay_flags
    w.write_string("relay-rust-e2e", RELAY_VERSION_LENGTH);
    w.write_uint32(RELAY_NUM_COUNTERS as u32);
    for _ in 0..RELAY_NUM_COUNTERS {
        w.write_uint64(0);
    }

    buf
}

/// Encrypt a plaintext request exactly as relay-xdp main_thread.rs does:
///   wire = header(8B) + MAC(16B) + ciphertext + nonce(24B)
fn encrypt_request(
    plaintext: &[u8],
    relay_sk: &crypto_box::SecretKey,
    backend_pk: &crypto_box::PublicKey,
) -> Vec<u8> {
    let header = &plaintext[..HEADER_SIZE];
    let body = &plaintext[HEADER_SIZE..];

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce_bytes).expect("getrandom failed");
    let nonce = crypto_box::Nonce::from(nonce_bytes);

    // Build SalsaBox: relay encrypts using backend's public key
    let salsa_box = crypto_box::SalsaBox::new(backend_pk, relay_sk);

    let mut ciphertext = body.to_vec();
    let tag = salsa_box
        .encrypt_in_place_detached(&nonce, b"", &mut ciphertext)
        .expect("encrypt failed");

    // Assemble: header + MAC(16) + ciphertext + nonce(24)
    let mut out = Vec::with_capacity(HEADER_SIZE + 16 + ciphertext.len() + NONCE_SIZE);
    out.extend_from_slice(header);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&nonce_bytes);
    out
}

// -------------------------------------------------------
// AppState builder with crypto keys
// -------------------------------------------------------

fn test_app_state_with_crypto(
    backend_sk: &crypto_box::SecretKey,
    backend_pk: &crypto_box::PublicKey,
    relay_pk_bytes: [u8; 32],
) -> Arc<AppState> {
    let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let rid = relay_id(&format!("{}", addr));

    let mut id_to_index = HashMap::new();
    id_to_index.insert(rid, 0);

    let relay_data = RelayData {
        num_relays: 1,
        relay_ids: vec![rid],
        relay_addresses: vec![addr],
        relay_names: vec!["relay-test".to_string()],
        relay_latitudes: vec![0.0],
        relay_longitudes: vec![0.0],
        relay_datacenter_ids: vec![1],
        relay_price: vec![0],
        relay_id_to_index: id_to_index,
        dest_relays: vec![true],
        database_bin_file: vec![],
        relay_public_keys: vec![relay_pk_bytes],
        relay_internal_addresses: vec![None],
    };

    let config = Config {
        max_jitter: 1000,
        max_packet_loss: 100.0,
        route_matrix_interval_ms: 1000,
        initial_delay: 0,
        http_port: 0,
        enable_relay_history: false,
        redis_hostname: "127.0.0.1:6379".to_string(),
        internal_address: "127.0.0.1".to_string(),
        internal_port: "0".to_string(),
        relay_backend_public_key: backend_pk.as_bytes().to_vec(),
        relay_backend_private_key: backend_sk.to_bytes().to_vec(),
        relay_data_file: None,
    };

    Arc::new(AppState {
        config: Arc::new(config),
        relay_data: Arc::new(relay_data),
        relay_manager: Arc::new(RelayManager::new(false)),
        relays_csv: RwLock::new(vec![]),
        cost_matrix_data: RwLock::new(vec![]),
        route_matrix_data: RwLock::new(vec![]),
        start_time: SystemTime::now(),
        delay_completed: AtomicBool::new(true),
        leader_election: Arc::new(RedisLeaderElection::new("127.0.0.1:6379", "test", 0)),
        magic_rotator: Arc::new(MagicRotator::new()),
        last_optimize_ms: AtomicU64::new(0),
    })
}

/// POST an encrypted body to /relay_update and return (status, body_bytes).
async fn post_relay_update(state: Arc<AppState>, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let app = create_router(state);
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

    let status = response.status();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, body_bytes)
}

// ===================================================================
// Test 1: Full E2E encrypted request -> decrypt -> 200 OK + valid response
// ===================================================================

#[tokio::test]
async fn test_e2e_encrypted_request_decrypts_and_returns_ok() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk, relay_pk) = generate_keypair();

    let state = test_app_state_with_crypto(&backend_sk, &backend_pk, relay_pk.as_bytes().clone());

    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);
    let plaintext = build_plaintext_request(host_addr, 40000);
    let encrypted = encrypt_request(&plaintext, &relay_sk, &backend_pk);

    let (status, body) = post_relay_update(state, encrypted).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "encrypted request should succeed, got {status}"
    );
    assert!(
        body.len() > 13,
        "response should contain at least version(1) + timestamp(8) + num_relays(4)"
    );

    // Parse response header to verify it's a valid relay update response
    let mut r = relay_xdp::encoding::Reader::new(&body);
    let version = r.read_uint8().unwrap();
    assert_eq!(version, 1, "response version should be 1");

    let timestamp = r.read_uint64().unwrap();
    assert!(timestamp > 0, "response timestamp should be nonzero");

    let num_relays = r.read_uint32().unwrap();
    // No other relays are active, so this should be 0
    assert_eq!(num_relays, 0, "no other relays should be active");
}

// ===================================================================
// Test 2: Encrypted request updates relay manager state
// ===================================================================

#[tokio::test]
async fn test_e2e_encrypted_request_updates_relay_manager() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk, relay_pk) = generate_keypair();

    let state = test_app_state_with_crypto(&backend_sk, &backend_pk, relay_pk.as_bytes().clone());

    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);
    let plaintext = build_plaintext_request(host_addr, 40000);
    let encrypted = encrypt_request(&plaintext, &relay_sk, &backend_pk);

    let (status, _) = post_relay_update(state.clone(), encrypted).await;
    assert_eq!(status, StatusCode::OK);

    // Verify relay manager registered the relay as active
    let current_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let active = state.relay_manager.get_active_relays(current_time);
    assert_eq!(
        active.len(),
        1,
        "relay should be active after encrypted update"
    );
    assert_eq!(active[0].name, "relay-test");
    assert_eq!(active[0].sessions, 5);
}

// ===================================================================
// Test 3: Wrong relay key -> decrypt fails -> 400
// ===================================================================

#[tokio::test]
async fn test_e2e_wrong_relay_key_returns_bad_request() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (_relay_sk, relay_pk) = generate_keypair();
    let (wrong_sk, _wrong_pk) = generate_keypair();

    // Backend has the real relay public key registered
    let state = test_app_state_with_crypto(&backend_sk, &backend_pk, relay_pk.as_bytes().clone());

    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);
    let plaintext = build_plaintext_request(host_addr, 40000);

    // Encrypt with the WRONG relay secret key - backend will try to decrypt
    // with (relay_pk, backend_sk) but the message was encrypted with (backend_pk, wrong_sk)
    let encrypted = encrypt_request(&plaintext, &wrong_sk, &backend_pk);

    let (status, _) = post_relay_update(state, encrypted).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "wrong relay key should fail decryption"
    );
}

// ===================================================================
// Test 4: Tampered MAC -> decrypt fails -> 400
// ===================================================================

#[tokio::test]
async fn test_e2e_tampered_mac_returns_bad_request() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk, relay_pk) = generate_keypair();

    let state = test_app_state_with_crypto(&backend_sk, &backend_pk, relay_pk.as_bytes().clone());

    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);
    let plaintext = build_plaintext_request(host_addr, 40000);
    let mut encrypted = encrypt_request(&plaintext, &relay_sk, &backend_pk);

    // Flip bits in the MAC (bytes 8..24)
    for i in HEADER_SIZE..HEADER_SIZE + 16 {
        encrypted[i] ^= 0xFF;
    }

    let (status, _) = post_relay_update(state, encrypted).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "tampered MAC should fail decryption"
    );
}

// ===================================================================
// Test 5: Tampered ciphertext -> decrypt fails -> 400
// ===================================================================

#[tokio::test]
async fn test_e2e_tampered_ciphertext_returns_bad_request() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk, relay_pk) = generate_keypair();

    let state = test_app_state_with_crypto(&backend_sk, &backend_pk, relay_pk.as_bytes().clone());

    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);
    let plaintext = build_plaintext_request(host_addr, 40000);
    let mut encrypted = encrypt_request(&plaintext, &relay_sk, &backend_pk);

    // Flip bits in the ciphertext (after header + MAC, before nonce)
    let ct_start = HEADER_SIZE + 16;
    let ct_end = encrypted.len() - NONCE_SIZE;
    if ct_end > ct_start {
        encrypted[ct_start] ^= 0xFF;
        encrypted[ct_start + 1] ^= 0xAA;
    }

    let (status, _) = post_relay_update(state, encrypted).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "tampered ciphertext should fail decryption"
    );
}

// ===================================================================
// Test 6: Tampered nonce -> decrypt fails -> 400
// ===================================================================

#[tokio::test]
async fn test_e2e_tampered_nonce_returns_bad_request() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk, relay_pk) = generate_keypair();

    let state = test_app_state_with_crypto(&backend_sk, &backend_pk, relay_pk.as_bytes().clone());

    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);
    let plaintext = build_plaintext_request(host_addr, 40000);
    let mut encrypted = encrypt_request(&plaintext, &relay_sk, &backend_pk);

    // Flip bits in the nonce (last 24 bytes)
    let nonce_start = encrypted.len() - NONCE_SIZE;
    for i in nonce_start..encrypted.len() {
        encrypted[i] ^= 0xFF;
    }

    let (status, _) = post_relay_update(state, encrypted).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "tampered nonce should fail decryption"
    );
}

// ===================================================================
// Test 7: Truncated encrypted body -> 400
// ===================================================================

#[tokio::test]
async fn test_e2e_truncated_encrypted_body_returns_bad_request() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk, relay_pk) = generate_keypair();

    let state = test_app_state_with_crypto(&backend_sk, &backend_pk, relay_pk.as_bytes().clone());

    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);
    let plaintext = build_plaintext_request(host_addr, 40000);
    let encrypted = encrypt_request(&plaintext, &relay_sk, &backend_pk);

    // Truncate to just header + partial MAC (too small for encrypted payload)
    let truncated = encrypted[..HEADER_SIZE + 10].to_vec();

    let (status, _) = post_relay_update(state, truncated).await;
    assert!(
        status.is_client_error(),
        "truncated encrypted body should return 4xx, got {status}"
    );
}

// ===================================================================
// Test 8: Unknown relay address in encrypted header -> 400
// ===================================================================

#[tokio::test]
async fn test_e2e_unknown_relay_in_encrypted_header_returns_error() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk, relay_pk) = generate_keypair();

    let state = test_app_state_with_crypto(&backend_sk, &backend_pk, relay_pk.as_bytes().clone());

    // Build request with an address NOT in the relay database
    let unknown_addr = u32::from_be_bytes([99, 99, 99, 99]);
    let plaintext = build_plaintext_request(unknown_addr, 12345);
    let encrypted = encrypt_request(&plaintext, &relay_sk, &backend_pk);

    let (status, _) = post_relay_update(state, encrypted).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unknown relay in header should fail during decrypt key lookup"
    );
}

// ===================================================================
// Test 9: Response contains expected relay public key and backend key
// ===================================================================

#[tokio::test]
async fn test_e2e_encrypted_response_contains_expected_keys() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk, relay_pk) = generate_keypair();
    let relay_pk_bytes = relay_pk.as_bytes().clone();

    let state = test_app_state_with_crypto(&backend_sk, &backend_pk, relay_pk_bytes);

    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);
    let plaintext = build_plaintext_request(host_addr, 40000);
    let encrypted = encrypt_request(&plaintext, &relay_sk, &backend_pk);

    let (status, body) = post_relay_update(state, encrypted).await;
    assert_eq!(status, StatusCode::OK);

    // Parse response to extract keys
    let mut r = relay_xdp::encoding::Reader::new(&body);
    r.read_uint8().unwrap(); // version
    r.read_uint64().unwrap(); // timestamp
    let num_relays = r.read_uint32().unwrap();
    assert_eq!(num_relays, 0);

    r.read_string(RELAY_VERSION_LENGTH).unwrap(); // target_version
    r.skip(MAGIC_BYTES * 3).unwrap(); // upcoming + current + previous magic

    // Expected public address
    let (addr_host, port) = r.read_address().unwrap();
    assert_eq!(addr_host, u32::from_be_bytes([10, 0, 0, 1]));
    assert_eq!(port, 40000);

    let has_internal = r.read_uint8().unwrap();
    assert_eq!(has_internal, 0);

    // Relay public key echoed back
    let mut read_relay_pk = [0u8; 32];
    r.read_bytes_into(&mut read_relay_pk).unwrap();
    assert_eq!(
        read_relay_pk, relay_pk_bytes,
        "response should echo back the relay's public key"
    );

    // Backend public key
    let mut read_backend_pk = [0u8; 32];
    r.read_bytes_into(&mut read_backend_pk).unwrap();
    assert_eq!(
        read_backend_pk,
        *backend_pk.as_bytes(),
        "response should contain backend's public key"
    );
}

// ===================================================================
// Test 10: Plaintext request still works when crypto is disabled
// ===================================================================

#[tokio::test]
async fn test_e2e_plaintext_mode_when_no_crypto_keys() {
    // Build state with empty crypto keys (legacy mode)
    let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let rid = relay_id(&format!("{}", addr));

    let mut id_to_index = HashMap::new();
    id_to_index.insert(rid, 0);

    let relay_data = RelayData {
        num_relays: 1,
        relay_ids: vec![rid],
        relay_addresses: vec![addr],
        relay_names: vec!["relay-plain".to_string()],
        relay_latitudes: vec![0.0],
        relay_longitudes: vec![0.0],
        relay_datacenter_ids: vec![1],
        relay_price: vec![0],
        relay_id_to_index: id_to_index,
        dest_relays: vec![true],
        database_bin_file: vec![],
        relay_public_keys: vec![[0u8; 32]],
        relay_internal_addresses: vec![None],
    };

    let config = Config {
        max_jitter: 1000,
        max_packet_loss: 100.0,
        route_matrix_interval_ms: 1000,
        initial_delay: 0,
        http_port: 0,
        enable_relay_history: false,
        redis_hostname: "127.0.0.1:6379".to_string(),
        internal_address: "127.0.0.1".to_string(),
        internal_port: "0".to_string(),
        relay_backend_public_key: vec![],  // empty = no crypto
        relay_backend_private_key: vec![], // empty = no crypto
        relay_data_file: None,
    };

    let state = Arc::new(AppState {
        config: Arc::new(config),
        relay_data: Arc::new(relay_data),
        relay_manager: Arc::new(RelayManager::new(false)),
        relays_csv: RwLock::new(vec![]),
        cost_matrix_data: RwLock::new(vec![]),
        route_matrix_data: RwLock::new(vec![]),
        start_time: SystemTime::now(),
        delay_completed: AtomicBool::new(true),
        leader_election: Arc::new(RedisLeaderElection::new("127.0.0.1:6379", "test", 0)),
        magic_rotator: Arc::new(MagicRotator::new()),
        last_optimize_ms: AtomicU64::new(0),
    });

    // Send a plaintext (unencrypted) request
    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);
    let plaintext = build_plaintext_request(host_addr, 40000);

    let (status, _) = post_relay_update(state, plaintext).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "plaintext request should work when crypto is disabled"
    );
}

// ===================================================================
// Test 11: Multiple sequential encrypted requests from same relay
// ===================================================================

#[tokio::test]
async fn test_e2e_multiple_encrypted_requests_succeed() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk, relay_pk) = generate_keypair();

    let state = test_app_state_with_crypto(&backend_sk, &backend_pk, relay_pk.as_bytes().clone());

    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);

    // Send 3 sequential encrypted updates (each with a fresh random nonce)
    for i in 0..3 {
        let plaintext = build_plaintext_request(host_addr, 40000);
        let encrypted = encrypt_request(&plaintext, &relay_sk, &backend_pk);

        let app = create_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/relay_update")
                    .header("content-type", "application/octet-stream")
                    .body(Body::from(encrypted))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "encrypted request {i} should succeed"
        );
    }

    // Verify relay is still active after multiple updates
    let current_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let active = state.relay_manager.get_active_relays(current_time);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].name, "relay-test");
}
