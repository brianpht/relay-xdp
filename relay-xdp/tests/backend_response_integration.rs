//! Backend response integration tests.
//!
//! These tests verify that relay-xdp correctly parses real responses built by
//! relay-backend's RelayUpdateResponse::write(). Unlike func_parity.rs (which
//! builds mock responses using relay-xdp's own Writer), these tests use the
//! REAL relay-backend encoder, catching encoding mismatches.
//!
//! These tests do NOT use env vars or #[ignore] - they construct Config directly.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use relay_backend::constants::ENCRYPTED_ROUTE_TOKEN_BYTES;
use relay_backend::relay_update::RelayUpdateResponse;
use relay_xdp::config::Config;
use relay_xdp::main_thread::{self, MainThread};

// -------------------------------------------------------
// Test helpers
// -------------------------------------------------------

/// Create a test Config directly (no env vars).
fn test_config(
    relay_public_address: u32,
    relay_port: u16,
    relay_pk: [u8; 32],
    backend_pk: [u8; 32],
) -> Config {
    Config {
        relay_name: "test-relay".to_string(),
        relay_port,
        relay_public_address,
        relay_internal_address: relay_public_address,
        relay_public_key: relay_pk,
        relay_private_key: [0u8; 32],
        relay_backend_public_key: backend_pk,
        relay_secret_key: [0u8; 32],
        gateway_ethernet_address: [0u8; 6],
        use_gateway_ethernet_address: false,
        relay_backend_url: "http://127.0.0.1:0".to_string(),
    }
}

/// Create a MainThread for testing (no BPF, no env vars).
fn test_main_thread(
    config: Config,
) -> (
    MainThread,
    main_thread::MessageQueue<main_thread::ControlMessage>,
) {
    let config = Arc::new(config);
    let quit = Arc::new(AtomicBool::new(false));
    let clean_shutdown = Arc::new(AtomicBool::new(false));
    let control_queue = main_thread::new_queue();
    let stats_queue = main_thread::new_queue();

    let mt = MainThread::new(
        config,
        None, // no BPF
        control_queue.clone(),
        stats_queue,
        quit,
        clean_shutdown,
    )
    .expect("MainThread::new should succeed without BPF");

    (mt, control_queue)
}

/// Build a RelayUpdateResponse using relay-backend's real writer.
fn build_backend_response(
    relay_ids: &[u64],
    relay_addresses: &[SocketAddrV4],
    relay_internal: &[u8],
    expected_pub_addr: SocketAddrV4,
    has_internal: bool,
    internal_addr: SocketAddrV4,
    relay_pk: &[u8; 32],
    backend_pk: &[u8; 32],
    ping_key: &[u8; 32],
    upcoming_magic: [u8; 8],
    current_magic: [u8; 8],
    previous_magic: [u8; 8],
) -> Vec<u8> {
    let response = RelayUpdateResponse {
        version: 1,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        num_relays: relay_ids.len() as u32,
        relay_ids: relay_ids.to_vec(),
        relay_addresses: relay_addresses.to_vec(),
        relay_internal: relay_internal.to_vec(),
        target_version: "relay-rust".to_string(),
        upcoming_magic,
        current_magic,
        previous_magic,
        expected_public_address: expected_pub_addr,
        expected_has_internal_address: if has_internal { 1 } else { 0 },
        expected_internal_address: internal_addr,
        expected_relay_public_key: *relay_pk,
        expected_relay_backend_public_key: *backend_pk,
        test_token: [0u8; ENCRYPTED_ROUTE_TOKEN_BYTES],
        ping_key: *ping_key,
    };
    response.write()
}

// ===================================================================
// Test 1: Real relay-backend response parsed by relay-xdp MainThread
// ===================================================================

#[test]
fn test_backend_response_parsed_by_relay_xdp() {
    let relay_pk = [0x42u8; 32];
    let backend_pk = [0x43u8; 32];
    let ping_key = [0xBBu8; 32];
    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);

    let config = test_config(host_addr, 40000, relay_pk, backend_pk);
    let (mut mt, control_queue) = test_main_thread(config);

    let response_data = build_backend_response(
        &[100, 200],
        &[
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40001),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 40002),
        ],
        &[0, 1],
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000),
        false,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        &relay_pk,
        &backend_pk,
        &ping_key,
        [1, 2, 3, 4, 5, 6, 7, 8],
        [9, 10, 11, 12, 13, 14, 15, 16],
        [17, 18, 19, 20, 21, 22, 23, 24],
    );

    mt.parse_update_response(&response_data)
        .expect("should parse real backend response");

    let queue = control_queue.lock().unwrap();
    assert_eq!(queue.len(), 1, "should produce exactly one control message");

    let msg = &queue[0];
    assert_eq!(msg.current_magic, [9, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(msg.ping_key, ping_key);
    assert_eq!(msg.new_relays.num_relays, 2);
    assert_eq!(msg.new_relays.id[0], 100);
    assert_eq!(msg.new_relays.id[1], 200);
    assert_eq!(msg.new_relays.port[0], 40001);
    assert_eq!(msg.new_relays.port[1], 40002);
    assert_eq!(msg.new_relays.internal[0], 0);
    assert_eq!(msg.new_relays.internal[1], 1);
    assert_eq!(msg.delete_relays.num_relays, 0);

    // Verify addresses were converted to host order correctly
    assert_eq!(msg.new_relays.address[0], u32::from_be_bytes([10, 0, 0, 2]));
    assert_eq!(msg.new_relays.address[1], u32::from_be_bytes([10, 0, 0, 3]));
}

// ===================================================================
// Test 2: Relay set delta computation across successive responses
// ===================================================================

#[test]
fn test_relay_set_delta_computation_across_updates() {
    let relay_pk = [0x42u8; 32];
    let backend_pk = [0x43u8; 32];
    let ping_key = [0xBBu8; 32];
    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);

    let config = test_config(host_addr, 40000, relay_pk, backend_pk);
    let (mut mt, control_queue) = test_main_thread(config);

    let magic = [0u8; 8];

    // Response 1: relays 100, 200
    let resp1 = build_backend_response(
        &[100, 200],
        &[
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40001),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 40002),
        ],
        &[0, 0],
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000),
        false,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        &relay_pk,
        &backend_pk,
        &ping_key,
        magic,
        magic,
        magic,
    );

    mt.parse_update_response(&resp1).unwrap();

    {
        let queue = control_queue.lock().unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(
            queue[0].new_relays.num_relays, 2,
            "first update: 2 new relays"
        );
        assert_eq!(
            queue[0].delete_relays.num_relays, 0,
            "first update: 0 deleted relays"
        );
    }

    // Response 2: relays 200, 300 (100 removed, 300 added)
    let resp2 = build_backend_response(
        &[200, 300],
        &[
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 40002),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 4), 40003),
        ],
        &[0, 0],
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000),
        false,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        &relay_pk,
        &backend_pk,
        &ping_key,
        magic,
        magic,
        magic,
    );

    mt.parse_update_response(&resp2).unwrap();

    {
        let queue = control_queue.lock().unwrap();
        assert_eq!(queue.len(), 2, "should have 2 control messages total");

        let msg = &queue[1];
        assert_eq!(
            msg.new_relays.num_relays, 1,
            "second update: 1 new relay (300)"
        );
        assert_eq!(msg.new_relays.id[0], 300);
        assert_eq!(
            msg.delete_relays.num_relays, 1,
            "second update: 1 deleted relay (100)"
        );
        assert_eq!(msg.delete_relays.id[0], 100);
    }

    // Response 3: relays 200, 300 (no changes)
    let resp3 = build_backend_response(
        &[200, 300],
        &[
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 40002),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 4), 40003),
        ],
        &[0, 0],
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000),
        false,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        &relay_pk,
        &backend_pk,
        &ping_key,
        magic,
        magic,
        magic,
    );

    mt.parse_update_response(&resp3).unwrap();

    {
        let queue = control_queue.lock().unwrap();
        assert_eq!(queue.len(), 3);
        let msg = &queue[2];
        assert_eq!(msg.new_relays.num_relays, 0, "third update: 0 new relays");
        assert_eq!(
            msg.delete_relays.num_relays, 0,
            "third update: 0 deleted relays"
        );
    }
}

// ===================================================================
// Test 3: Wrong public key in response is rejected
// ===================================================================

#[test]
fn test_response_wrong_public_key_rejected() {
    let relay_pk = [0x42u8; 32];
    let backend_pk = [0x43u8; 32];
    let ping_key = [0xBBu8; 32];
    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);

    let config = test_config(host_addr, 40000, relay_pk, backend_pk);
    let (mut mt, _control_queue) = test_main_thread(config);

    // Response with wrong relay public key
    let mut wrong_pk = relay_pk;
    wrong_pk[0] ^= 0xFF;

    let resp = build_backend_response(
        &[],
        &[],
        &[],
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000),
        false,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        &wrong_pk,
        &backend_pk,
        &ping_key,
        [0u8; 8],
        [0u8; 8],
        [0u8; 8],
    );

    let result = mt.parse_update_response(&resp);
    assert!(
        result.is_err(),
        "should reject response with wrong public key"
    );
    let err = format!("{:#}", result.unwrap_err());
    assert!(
        err.contains("public key"),
        "error should mention public key: {err}"
    );
}

// ===================================================================
// Test 4: Response with zero relays succeeds
// ===================================================================

#[test]
fn test_response_zero_relays_succeeds() {
    let relay_pk = [0x42u8; 32];
    let backend_pk = [0x43u8; 32];
    let ping_key = [0xCCu8; 32];
    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);

    let config = test_config(host_addr, 40000, relay_pk, backend_pk);
    let (mut mt, control_queue) = test_main_thread(config);

    let resp = build_backend_response(
        &[],
        &[],
        &[],
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000),
        false,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        &relay_pk,
        &backend_pk,
        &ping_key,
        [0u8; 8],
        [0u8; 8],
        [0u8; 8],
    );

    mt.parse_update_response(&resp)
        .expect("zero-relay response should parse successfully");

    let queue = control_queue.lock().unwrap();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].new_relays.num_relays, 0);
    assert_eq!(queue[0].ping_key, ping_key);
}

// ===================================================================
// Test 5: Response with internal address parsed correctly
// ===================================================================

#[test]
fn test_response_with_internal_address() {
    let relay_pk = [0x42u8; 32];
    let backend_pk = [0x43u8; 32];
    let ping_key = [0xDDu8; 32];

    let pub_addr = u32::from_be_bytes([203, 0, 113, 1]);
    let int_addr = u32::from_be_bytes([10, 0, 0, 99]);

    let config = test_config(pub_addr, 40000, relay_pk, backend_pk);
    // Override internal address to match the response
    let config = Config {
        relay_internal_address: int_addr,
        ..config
    };

    let (mut mt, control_queue) = test_main_thread(config);

    let resp = build_backend_response(
        &[100, 200, 300],
        &[
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40001),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40002),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 40003),
        ],
        &[0, 1, 0],
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 40000),
        true,
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 99), 40000),
        &relay_pk,
        &backend_pk,
        &ping_key,
        [0u8; 8],
        [0u8; 8],
        [0u8; 8],
    );

    mt.parse_update_response(&resp)
        .expect("response with internal address should parse");

    let queue = control_queue.lock().unwrap();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].new_relays.num_relays, 3);
    assert_eq!(
        queue[0].new_relays.internal[1], 1,
        "relay 200 should be internal"
    );
}
