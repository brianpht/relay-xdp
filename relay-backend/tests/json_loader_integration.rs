//! Integration tests: JSON fixture -> AppState -> encrypted request -> 200 OK.
//!
//! Validates the full pipeline from loading relay data via JSON to processing
//! encrypted relay update requests through the HTTP handler. This is the
//! integration test described in step 5 of the relay data loader plan.

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
use relay_backend::state::AppState;

use relay_xdp::encoding::Writer as XdpWriter;
use relay_xdp_common::{RELAY_ADDRESS_IPV4, RELAY_NUM_COUNTERS, RELAY_VERSION_LENGTH};

// -------------------------------------------------------
// Crypto helpers
// -------------------------------------------------------

const HEADER_SIZE: usize = 8; // version(1) + addr_type(1) + ip(4) + port(2)
const NONCE_SIZE: usize = 24;

fn generate_keypair() -> (crypto_box::SecretKey, crypto_box::PublicKey) {
    let sk = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
    let pk = sk.public_key();
    (sk, pk)
}

// -------------------------------------------------------
// JSON fixture with 3 relays, each with a real public key
// -------------------------------------------------------

/// Build a JSON fixture string with the given relay public keys (base64 encoded).
fn json_fixture(relay_keys: &[[u8; 32]; 3]) -> String {
    use base64::Engine;
    let enc = base64::engine::general_purpose::STANDARD;

    format!(
        r#"{{
  "relays": [
    {{
      "name": "relay-amsterdam",
      "address": "10.0.0.2:40000",
      "latitude": 52.37,
      "longitude": 4.90,
      "datacenter_id": 2,
      "price": 0,
      "dest": true,
      "public_key": "{}"
    }},
    {{
      "name": "relay-dallas",
      "address": "10.0.0.1:40000",
      "latitude": 32.78,
      "longitude": -96.80,
      "datacenter_id": 1,
      "price": 0,
      "dest": true,
      "public_key": "{}"
    }},
    {{
      "name": "relay-tokyo",
      "address": "10.0.0.3:40000",
      "latitude": 35.68,
      "longitude": 139.69,
      "datacenter_id": 3,
      "price": 5,
      "dest": false,
      "public_key": "{}"
    }}
  ]
}}"#,
        enc.encode(relay_keys[0]),
        enc.encode(relay_keys[1]),
        enc.encode(relay_keys[2]),
    )
}

// -------------------------------------------------------
// Request builder (matches relay-xdp main_thread.rs::update)
// -------------------------------------------------------

fn build_plaintext_request(relay_public_address: u32, relay_port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    let mut w = XdpWriter::new(&mut buf);

    w.write_uint8(1); // version
    w.write_uint8(RELAY_ADDRESS_IPV4);
    w.write_uint32(relay_public_address.to_be());
    w.write_uint16(relay_port);

    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    w.write_uint64(now);
    w.write_uint64(now - 1000);

    w.write_uint32(0); // num_samples

    w.write_uint32(42); // session_count
    w.write_uint32(100);
    w.write_uint32(200);
    for _ in 0..7 {
        w.write_float32(0.0);
    }

    w.write_uint64(0); // relay_flags
    w.write_string("json-test-v1", RELAY_VERSION_LENGTH);
    w.write_uint32(RELAY_NUM_COUNTERS as u32);
    for _ in 0..RELAY_NUM_COUNTERS {
        w.write_uint64(0);
    }

    buf
}

fn encrypt_request(
    plaintext: &[u8],
    relay_sk: &crypto_box::SecretKey,
    backend_pk: &crypto_box::PublicKey,
) -> Vec<u8> {
    let header = &plaintext[..HEADER_SIZE];
    let body = &plaintext[HEADER_SIZE..];

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::fill(&mut nonce_bytes).expect("getrandom failed");
    let nonce = crypto_box::Nonce::from(nonce_bytes);

    let salsa_box = crypto_box::SalsaBox::new(backend_pk, relay_sk);

    let mut ciphertext = body.to_vec();
    let tag = salsa_box
        .encrypt_in_place_detached(&nonce, b"", &mut ciphertext)
        .expect("encrypt failed");

    let mut out = Vec::with_capacity(HEADER_SIZE + 16 + ciphertext.len() + NONCE_SIZE);
    out.extend_from_slice(header);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&nonce_bytes);
    out
}

// -------------------------------------------------------
// AppState builder from JSON-loaded RelayData
// -------------------------------------------------------

fn build_state_from_json(
    relay_data: RelayData,
    backend_sk: &crypto_box::SecretKey,
    backend_pk: &crypto_box::PublicKey,
) -> Arc<AppState> {
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
// Test 1: JSON fixture -> load -> encrypted request -> 200 OK
// ===================================================================

#[tokio::test]
async fn test_json_loaded_relay_encrypted_request_returns_ok() {
    let (backend_sk, backend_pk) = generate_keypair();

    // Generate 3 relay keypairs
    let (relay_sk_0, relay_pk_0) = generate_keypair();
    let (_relay_sk_1, relay_pk_1) = generate_keypair();
    let (_relay_sk_2, relay_pk_2) = generate_keypair();

    let relay_keys = [
        relay_pk_0.as_bytes().clone(),
        relay_pk_1.as_bytes().clone(),
        relay_pk_2.as_bytes().clone(),
    ];

    let json = json_fixture(&relay_keys);
    let relay_data = RelayData::from_json(&json).expect("failed to parse JSON fixture");

    // Verify sort order: amsterdam < dallas < tokyo
    assert_eq!(relay_data.num_relays, 3);
    assert_eq!(relay_data.relay_names[0], "relay-amsterdam");
    assert_eq!(relay_data.relay_names[1], "relay-dallas");
    assert_eq!(relay_data.relay_names[2], "relay-tokyo");

    let state = build_state_from_json(relay_data, &backend_sk, &backend_pk);

    // Send encrypted request from relay-amsterdam (10.0.0.2:40000)
    // relay_keys[0] is amsterdam's key (first in fixture, sorted to index 0)
    let host_addr = u32::from_be_bytes([10, 0, 0, 2]);
    let plaintext = build_plaintext_request(host_addr, 40000);
    let encrypted = encrypt_request(&plaintext, &relay_sk_0, &backend_pk);

    let (status, body) = post_relay_update(state, encrypted).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "encrypted request for JSON-loaded relay should return 200 OK"
    );
    assert!(
        body.len() > 13,
        "response should contain at least version + timestamp + num_relays"
    );
}

// ===================================================================
// Test 2: JSON fixture -> encrypted request -> relay manager updated
// ===================================================================

#[tokio::test]
async fn test_json_loaded_relay_encrypted_request_updates_relay_manager() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk_0, relay_pk_0) = generate_keypair();
    let (_relay_sk_1, relay_pk_1) = generate_keypair();
    let (_relay_sk_2, relay_pk_2) = generate_keypair();

    let relay_keys = [
        relay_pk_0.as_bytes().clone(),
        relay_pk_1.as_bytes().clone(),
        relay_pk_2.as_bytes().clone(),
    ];

    let json = json_fixture(&relay_keys);
    let relay_data = RelayData::from_json(&json).unwrap();
    let state = build_state_from_json(relay_data, &backend_sk, &backend_pk);

    // Send encrypted update from relay-amsterdam
    let host_addr = u32::from_be_bytes([10, 0, 0, 2]);
    let plaintext = build_plaintext_request(host_addr, 40000);
    let encrypted = encrypt_request(&plaintext, &relay_sk_0, &backend_pk);

    let (status, _) = post_relay_update(state.clone(), encrypted).await;
    assert_eq!(status, StatusCode::OK);

    // Verify relay manager registered it
    let current_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let active = state.relay_manager.get_active_relays(current_time);
    assert_eq!(active.len(), 1, "should have 1 active relay after update");
    assert_eq!(active[0].name, "relay-amsterdam");
    assert_eq!(active[0].sessions, 42);
}

// ===================================================================
// Test 3: JSON fixture -> response echoes correct relay public key
// ===================================================================

#[tokio::test]
async fn test_json_loaded_relay_response_echoes_correct_public_key() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk_0, relay_pk_0) = generate_keypair();
    let (relay_sk_1, relay_pk_1) = generate_keypair();
    let (_relay_sk_2, relay_pk_2) = generate_keypair();

    let relay_pk_0_bytes = relay_pk_0.as_bytes().clone();
    let relay_pk_1_bytes = relay_pk_1.as_bytes().clone();

    let relay_keys = [
        relay_pk_0_bytes,
        relay_pk_1_bytes,
        relay_pk_2.as_bytes().clone(),
    ];

    let json = json_fixture(&relay_keys);
    let relay_data = RelayData::from_json(&json).unwrap();
    let state = build_state_from_json(relay_data, &backend_sk, &backend_pk);

    // Send from relay-amsterdam (index 0 after sort, pk = relay_keys[0])
    let host_addr_ams = u32::from_be_bytes([10, 0, 0, 2]);
    let plaintext = build_plaintext_request(host_addr_ams, 40000);
    let encrypted = encrypt_request(&plaintext, &relay_sk_0, &backend_pk);

    let (status, body) = post_relay_update(state.clone(), encrypted).await;
    assert_eq!(status, StatusCode::OK);

    // Parse response with relay-xdp's Reader to extract the echoed key
    let mut r = relay_xdp::encoding::Reader::new(&body);
    r.read_uint8().unwrap(); // version
    r.read_uint64().unwrap(); // timestamp
    let num_relays = r.read_uint32().unwrap();
    // Skip relay entries
    for _ in 0..num_relays {
        r.read_uint64().unwrap(); // id
        r.read_address().unwrap(); // address
        r.read_uint8().unwrap(); // internal
    }
    r.read_string(RELAY_VERSION_LENGTH).unwrap(); // target_version
    r.skip(MAGIC_BYTES * 3).unwrap(); // magic bytes
    r.read_address().unwrap(); // expected_public_address
    let has_internal = r.read_uint8().unwrap();
    if has_internal != 0 {
        r.read_address().unwrap();
    }

    let mut echoed_relay_pk = [0u8; 32];
    r.read_bytes_into(&mut echoed_relay_pk).unwrap();
    assert_eq!(
        echoed_relay_pk, relay_pk_0_bytes,
        "response should echo amsterdam's public key"
    );

    let mut echoed_backend_pk = [0u8; 32];
    r.read_bytes_into(&mut echoed_backend_pk).unwrap();
    assert_eq!(
        echoed_backend_pk,
        *backend_pk.as_bytes(),
        "response should contain backend's public key"
    );

    // Now send from relay-dallas (index 1 after sort, pk = relay_keys[1])
    let host_addr_dal = u32::from_be_bytes([10, 0, 0, 1]);
    let plaintext2 = build_plaintext_request(host_addr_dal, 40000);
    let encrypted2 = encrypt_request(&plaintext2, &relay_sk_1, &backend_pk);

    let (status2, body2) = post_relay_update(state, encrypted2).await;
    assert_eq!(status2, StatusCode::OK);

    let mut r2 = relay_xdp::encoding::Reader::new(&body2);
    r2.read_uint8().unwrap(); // version
    r2.read_uint64().unwrap(); // timestamp
    let num_relays2 = r2.read_uint32().unwrap();
    for _ in 0..num_relays2 {
        r2.read_uint64().unwrap();
        r2.read_address().unwrap();
        r2.read_uint8().unwrap();
    }
    r2.read_string(RELAY_VERSION_LENGTH).unwrap();
    r2.skip(MAGIC_BYTES * 3).unwrap();
    r2.read_address().unwrap();
    let has_internal2 = r2.read_uint8().unwrap();
    if has_internal2 != 0 {
        r2.read_address().unwrap();
    }

    let mut echoed_relay_pk2 = [0u8; 32];
    r2.read_bytes_into(&mut echoed_relay_pk2).unwrap();
    assert_eq!(
        echoed_relay_pk2, relay_pk_1_bytes,
        "response should echo dallas's public key"
    );
}

// ===================================================================
// Test 4: Two relays from JSON update -> second sees first as active peer
// ===================================================================

#[tokio::test]
async fn test_json_loaded_two_relays_see_each_other_as_peers() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk_0, relay_pk_0) = generate_keypair();
    let (relay_sk_1, relay_pk_1) = generate_keypair();
    let (_relay_sk_2, relay_pk_2) = generate_keypair();

    let relay_keys = [
        relay_pk_0.as_bytes().clone(),
        relay_pk_1.as_bytes().clone(),
        relay_pk_2.as_bytes().clone(),
    ];

    let json = json_fixture(&relay_keys);
    let relay_data = RelayData::from_json(&json).unwrap();
    let state = build_state_from_json(relay_data, &backend_sk, &backend_pk);

    // First: relay-amsterdam sends update
    let host_addr_ams = u32::from_be_bytes([10, 0, 0, 2]);
    let plaintext_ams = build_plaintext_request(host_addr_ams, 40000);
    let encrypted_ams = encrypt_request(&plaintext_ams, &relay_sk_0, &backend_pk);
    let (status, _) = post_relay_update(state.clone(), encrypted_ams).await;
    assert_eq!(status, StatusCode::OK);

    // Second: relay-dallas sends update -> response should list amsterdam as peer
    let host_addr_dal = u32::from_be_bytes([10, 0, 0, 1]);
    let plaintext_dal = build_plaintext_request(host_addr_dal, 40000);
    let encrypted_dal = encrypt_request(&plaintext_dal, &relay_sk_1, &backend_pk);
    let (status2, body2) = post_relay_update(state.clone(), encrypted_dal).await;
    assert_eq!(status2, StatusCode::OK);

    // Parse dallas's response - should have amsterdam in the relay list
    let mut r = relay_xdp::encoding::Reader::new(&body2);
    r.read_uint8().unwrap(); // version
    r.read_uint64().unwrap(); // timestamp
    let num_relays = r.read_uint32().unwrap();
    assert_eq!(
        num_relays, 1,
        "dallas should see amsterdam as an active peer"
    );

    // Read the peer relay info
    let peer_id = r.read_uint64().unwrap();
    let (peer_addr, peer_port) = r.read_address().unwrap();
    let _peer_internal = r.read_uint8().unwrap();

    // peer should be amsterdam (10.0.0.2:40000)
    assert_eq!(peer_addr, u32::from_be_bytes([10, 0, 0, 2]));
    assert_eq!(peer_port, 40000);

    // Verify the relay ID matches what we expect from amsterdam's address
    let expected_peer_id = relay_backend::relay_update::relay_id("10.0.0.2:40000");
    assert_eq!(peer_id, expected_peer_id);
}

// ===================================================================
// Test 5: Wrong relay key for JSON-loaded relay -> 400
// ===================================================================

#[tokio::test]
async fn test_json_loaded_relay_wrong_key_returns_bad_request() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (_relay_sk_0, relay_pk_0) = generate_keypair();
    let (_relay_sk_1, relay_pk_1) = generate_keypair();
    let (_relay_sk_2, relay_pk_2) = generate_keypair();
    let (wrong_sk, _wrong_pk) = generate_keypair();

    let relay_keys = [
        relay_pk_0.as_bytes().clone(),
        relay_pk_1.as_bytes().clone(),
        relay_pk_2.as_bytes().clone(),
    ];

    let json = json_fixture(&relay_keys);
    let relay_data = RelayData::from_json(&json).unwrap();
    let state = build_state_from_json(relay_data, &backend_sk, &backend_pk);

    // Encrypt with wrong key for relay-amsterdam
    let host_addr = u32::from_be_bytes([10, 0, 0, 2]);
    let plaintext = build_plaintext_request(host_addr, 40000);
    let encrypted = encrypt_request(&plaintext, &wrong_sk, &backend_pk);

    let (status, _) = post_relay_update(state, encrypted).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "wrong relay key should fail decryption for JSON-loaded relay"
    );
}

// ===================================================================
// Test 6: JSON fixture loaded from temp file -> encrypted request -> 200 OK
// ===================================================================

#[tokio::test]
async fn test_json_file_load_then_encrypted_request() {
    let (backend_sk, backend_pk) = generate_keypair();
    let (relay_sk, relay_pk) = generate_keypair();

    // Write JSON fixture to temp file
    let dir = std::env::temp_dir().join("relay_json_integ_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test_relays.json");

    // Single relay, no need for all 3
    let relay_pk_bytes = relay_pk.as_bytes().clone();
    let relay_keys = [relay_pk_bytes, [0u8; 32], [0u8; 32]];
    let json = json_fixture(&relay_keys);
    std::fs::write(&path, &json).unwrap();

    // Load from file
    let relay_data = RelayData::load_json(&path).expect("failed to load JSON file");
    assert_eq!(relay_data.num_relays, 3);

    let state = build_state_from_json(relay_data, &backend_sk, &backend_pk);

    // Send encrypted request from relay-amsterdam (10.0.0.2:40000)
    let host_addr = u32::from_be_bytes([10, 0, 0, 2]);
    let plaintext = build_plaintext_request(host_addr, 40000);
    let encrypted = encrypt_request(&plaintext, &relay_sk, &backend_pk);

    let (status, body) = post_relay_update(state, encrypted).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.len() > 13);

    // Verify response parses correctly
    let mut r = relay_xdp::encoding::Reader::new(&body);
    let version = r.read_uint8().unwrap();
    assert_eq!(version, 1);

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}
