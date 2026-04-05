//! Cross-crate wire format tests.
//!
//! These tests verify that relay-xdp's Writer/Reader and relay-backend's
//! SimpleWriter/SimpleReader produce and consume compatible wire formats.
//! This catches encoding mismatches between the two crates that per-crate
//! tests cannot detect (each crate's tests only use its own encoder).
//!
//! Key insight: relay-xdp writes addresses via `write_uint32(addr.to_be())`
//! which produces the same wire bytes as relay-backend's raw IP octets,
//! because LE(BE(host_order)) == network-order octets on little-endian.

use std::net::{Ipv4Addr, SocketAddrV4};

use relay_backend::constants::*;
use relay_backend::encoding::{SimpleReader, SimpleWriter};
use relay_backend::relay_update::{RelayUpdateRequest, RelayUpdateResponse};

use relay_xdp::encoding::{Reader as XdpReader, Writer as XdpWriter};
use relay_xdp_common::{
    RELAY_ADDRESS_IPV4, RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES, RELAY_NUM_COUNTERS,
    RELAY_PING_KEY_BYTES, RELAY_VERSION_LENGTH,
};

// ===================================================================
// Helper: build relay update request using relay-xdp's Writer
// (matches main_thread.rs::update() exactly)
// ===================================================================

fn build_request_with_xdp_writer(
    relay_public_address: u32, // host byte order
    relay_port: u16,
    current_time: u64,
    start_time: u64,
    sample_relay_ids: &[u64],
    sample_rtts: &[u8],
    sample_jitters: &[u8],
    sample_losses: &[u16],
    session_count: u32,
    relay_flags: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    let mut w = XdpWriter::new(&mut buf);

    w.write_uint8(1); // version

    // Address - exactly as main_thread.rs does it
    w.write_uint8(RELAY_ADDRESS_IPV4);
    w.write_uint32(relay_public_address.to_be());
    w.write_uint16(relay_port);

    w.write_uint64(current_time);
    w.write_uint64(start_time);

    w.write_uint32(sample_relay_ids.len() as u32);
    for i in 0..sample_relay_ids.len() {
        w.write_uint64(sample_relay_ids[i]);
        w.write_uint8(sample_rtts[i]);
        w.write_uint8(sample_jitters[i]);
        w.write_uint16(sample_losses[i]);
    }

    w.write_uint32(session_count);
    w.write_uint32(0); // envelope_bw_up
    w.write_uint32(0); // envelope_bw_down
    w.write_float32(0.0); // pps_sent
    w.write_float32(0.0); // pps_recv
    w.write_float32(0.0); // bw_sent
    w.write_float32(0.0); // bw_recv
    w.write_float32(0.0); // client_pps
    w.write_float32(0.0); // server_pps
    w.write_float32(0.0); // relay_pps
    w.write_uint64(relay_flags);
    w.write_string("relay-rust", RELAY_VERSION_LENGTH);
    w.write_uint32(RELAY_NUM_COUNTERS as u32);
    for _ in 0..RELAY_NUM_COUNTERS {
        w.write_uint64(0);
    }

    buf
}

// ===================================================================
// Helper: build relay update response using relay-backend's writer
// ===================================================================

fn build_response_with_backend(
    relay_ids: &[u64],
    relay_addresses: &[SocketAddrV4],
    relay_internal: &[u8],
    expected_public_address: SocketAddrV4,
    has_internal: bool,
    internal_address: SocketAddrV4,
    relay_pk: &[u8; 32],
    backend_pk: &[u8; 32],
    ping_key: &[u8; 32],
) -> Vec<u8> {
    let response = RelayUpdateResponse {
        version: 1,
        timestamp: 1700000000,
        num_relays: relay_ids.len() as u32,
        relay_ids: relay_ids.to_vec(),
        relay_addresses: relay_addresses.to_vec(),
        relay_internal: relay_internal.to_vec(),
        target_version: "relay-rust".to_string(),
        upcoming_magic: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        current_magic: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02],
        previous_magic: [0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22],
        expected_public_address,
        expected_has_internal_address: if has_internal { 1 } else { 0 },
        expected_internal_address: internal_address,
        expected_relay_public_key: *relay_pk,
        expected_relay_backend_public_key: *backend_pk,
        test_token: [0u8; ENCRYPTED_ROUTE_TOKEN_BYTES],
        ping_key: *ping_key,
    };
    response.write()
}

// ===================================================================
// Test 1: relay-xdp Writer builds request -> relay-backend parses
// ===================================================================

#[test]
fn test_xdp_writer_request_parsed_by_backend() {
    // 10.0.0.1 in host order = 0x0A000001
    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);
    let port = 40000u16;

    let sample_ids = [0xAAAABBBBCCCCDDDD_u64, 0x1111222233334444];
    let sample_rtts = [15u8, 25];
    let sample_jitters = [3u8, 5];
    let sample_losses = [100u16, 200];

    let buf = build_request_with_xdp_writer(
        host_addr,
        port,
        1700000000,
        1699999000,
        &sample_ids,
        &sample_rtts,
        &sample_jitters,
        &sample_losses,
        42,
        0,
    );

    // Parse with relay-backend's reader
    let request = RelayUpdateRequest::read(&buf).expect("backend should parse xdp-built request");

    assert_eq!(request.version, 1);
    assert_eq!(
        request.address,
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000)
    );
    assert_eq!(request.current_time, 1700000000);
    assert_eq!(request.start_time, 1699999000);
    assert_eq!(request.num_samples, 2);
    assert_eq!(request.sample_relay_id[0], 0xAAAABBBBCCCCDDDD);
    assert_eq!(request.sample_relay_id[1], 0x1111222233334444);
    assert_eq!(request.sample_rtt, [15, 25]);
    assert_eq!(request.sample_jitter, [3, 5]);
    assert_eq!(request.sample_packet_loss, [100, 200]);
    assert_eq!(request.session_count, 42);
    assert_eq!(request.relay_flags, 0);
    assert_eq!(request.relay_version, "relay-rust");
}

// ===================================================================
// Test 2: relay-backend writes response -> relay-xdp Reader parses
// ===================================================================

#[test]
fn test_backend_response_parsed_by_xdp_reader() {
    let relay_pk = [0x42u8; 32];
    let backend_pk = [0x43u8; 32];
    let ping_key = [0xBBu8; 32];

    let relay_ids = [100u64, 200];
    let relay_addrs = [
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40001),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40002),
    ];
    let relay_internal = [0u8, 1];

    let expected_pub = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 50000);

    let data = build_response_with_backend(
        &relay_ids,
        &relay_addrs,
        &relay_internal,
        expected_pub,
        false,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        &relay_pk,
        &backend_pk,
        &ping_key,
    );

    // Parse with relay-xdp's Reader (same path as main_thread.rs::parse_update_response)
    let mut r = XdpReader::new(&data);

    let version = r.read_uint8().unwrap();
    assert_eq!(version, 1);

    let timestamp = r.read_uint64().unwrap();
    assert_eq!(timestamp, 1700000000);

    let num_relays = r.read_uint32().unwrap();
    assert_eq!(num_relays, 2);

    // Relay 1: 10.0.0.1:40001
    let id0 = r.read_uint64().unwrap();
    assert_eq!(id0, 100);
    let addr_type = r.read_uint8().unwrap();
    assert_eq!(addr_type, RELAY_ADDRESS_IPV4);
    let addr_be = r.read_uint32().unwrap();
    let addr_host = u32::from_be(addr_be);
    assert_eq!(addr_host, u32::from_be_bytes([10, 0, 0, 1]));
    let port = r.read_uint16().unwrap();
    assert_eq!(port, 40001);
    let internal = r.read_uint8().unwrap();
    assert_eq!(internal, 0);

    // Relay 2: 10.0.0.2:40002
    let id1 = r.read_uint64().unwrap();
    assert_eq!(id1, 200);
    let _ = r.read_uint8().unwrap(); // addr_type
    let addr_be = r.read_uint32().unwrap();
    let addr_host = u32::from_be(addr_be);
    assert_eq!(addr_host, u32::from_be_bytes([10, 0, 0, 2]));
    let port = r.read_uint16().unwrap();
    assert_eq!(port, 40002);
    let internal = r.read_uint8().unwrap();
    assert_eq!(internal, 1);

    // Target version
    let target_ver = r.read_string(RELAY_VERSION_LENGTH).unwrap();
    assert_eq!(target_ver, "relay-rust");

    // Magic bytes
    let mut upcoming = [0u8; 8];
    let mut current = [0u8; 8];
    let mut previous = [0u8; 8];
    r.read_bytes_into(&mut upcoming).unwrap();
    r.read_bytes_into(&mut current).unwrap();
    r.read_bytes_into(&mut previous).unwrap();
    assert_eq!(upcoming, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    assert_eq!(current, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02]);
    assert_eq!(previous, [0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22]);

    // Expected public address
    let (pub_addr, pub_port) = r.read_address().unwrap();
    assert_eq!(pub_addr, u32::from_be_bytes([192, 168, 1, 100]));
    assert_eq!(pub_port, 50000);

    // has_internal = 0
    let has_internal = r.read_uint8().unwrap();
    assert_eq!(has_internal, 0);

    // Keys
    let mut read_relay_pk = [0u8; 32];
    let mut read_backend_pk = [0u8; 32];
    r.read_bytes_into(&mut read_relay_pk).unwrap();
    r.read_bytes_into(&mut read_backend_pk).unwrap();
    assert_eq!(read_relay_pk, relay_pk);
    assert_eq!(read_backend_pk, backend_pk);

    // Skip test token
    r.skip(RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES).unwrap();

    // Ping key
    let mut read_ping_key = [0u8; RELAY_PING_KEY_BYTES];
    r.read_bytes_into(&mut read_ping_key).unwrap();
    assert_eq!(read_ping_key, ping_key);
}

// ===================================================================
// Test 3: Address encoding - byte-level compatibility for request path
// ===================================================================

#[test]
fn test_address_encoding_request_byte_level() {
    // relay-xdp writes: write_uint32(host.to_be()) which stores LE bytes of the BE value.
    // On a LE machine, LE(BE(host)) == network-order octets.
    // relay-backend reads: raw IP octets.
    // These must be identical byte sequences.

    let test_ips: &[(Ipv4Addr, u32)] = &[
        (
            Ipv4Addr::new(10, 0, 0, 1),
            u32::from_be_bytes([10, 0, 0, 1]),
        ),
        (
            Ipv4Addr::new(192, 168, 1, 100),
            u32::from_be_bytes([192, 168, 1, 100]),
        ),
        (
            Ipv4Addr::new(172, 16, 254, 1),
            u32::from_be_bytes([172, 16, 254, 1]),
        ),
        (
            Ipv4Addr::new(255, 255, 255, 255),
            u32::from_be_bytes([255, 255, 255, 255]),
        ),
        (Ipv4Addr::new(0, 0, 0, 1), u32::from_be_bytes([0, 0, 0, 1])),
    ];

    for &(ref ip, host_order) in test_ips {
        // relay-xdp writes address
        let mut xdp_buf = Vec::new();
        let mut w = XdpWriter::new(&mut xdp_buf);
        w.write_uint8(RELAY_ADDRESS_IPV4);
        w.write_uint32(host_order.to_be());
        w.write_uint16(40000);

        // relay-backend writes address
        let mut sw = SimpleWriter::new(32);
        sw.write_address(&SocketAddrV4::new(*ip, 40000));
        let backend_buf = sw.get_data().to_vec();

        // Wire bytes must be identical
        assert_eq!(
            xdp_buf, backend_buf,
            "wire format mismatch for IP {ip}: xdp={xdp_buf:02x?} backend={backend_buf:02x?}"
        );

        // Verify relay-backend can parse xdp-written address
        let mut sr = SimpleReader::new(&xdp_buf);
        let parsed = sr.read_address().expect("backend should parse xdp address");
        assert_eq!(parsed, SocketAddrV4::new(*ip, 40000));

        // Verify relay-xdp can parse backend-written address
        let mut xr = XdpReader::new(&backend_buf);
        let (addr_host, port) = xr.read_address().unwrap();
        assert_eq!(addr_host, host_order, "host order mismatch for IP {ip}");
        assert_eq!(port, 40000);
    }
}

// ===================================================================
// Test 4: Address encoding - response path byte-level
// ===================================================================

#[test]
fn test_address_encoding_response_byte_level() {
    // relay-backend SimpleWriter writes raw IP octets in the response.
    // relay-xdp Reader reads them as LE u32, then from_be() to get host order.
    // This works because raw IP octets == big-endian byte representation.

    let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let expected_host = u32::from_be_bytes([10, 0, 0, 1]);

    // Build response with this address
    let mut sw = SimpleWriter::new(32);
    sw.write_address(&addr);
    let wire = sw.get_data().to_vec();

    // Verify wire bytes: [type=1, 10, 0, 0, 1, port_lo, port_hi]
    assert_eq!(wire[0], 1); // IPv4
    assert_eq!(wire[1], 10);
    assert_eq!(wire[2], 0);
    assert_eq!(wire[3], 0);
    assert_eq!(wire[4], 1);
    assert_eq!(&wire[5..7], &40000u16.to_le_bytes());

    // Parse with relay-xdp Reader
    let mut xr = XdpReader::new(&wire);
    let (addr_host, port) = xr.read_address().unwrap();
    assert_eq!(addr_host, expected_host);
    assert_eq!(port, 40000);
}

// ===================================================================
// Test 5: NONE address encoding cross-crate
// ===================================================================

#[test]
fn test_none_address_encoding_cross_crate() {
    // relay-backend NONE address
    let mut sw = SimpleWriter::new(32);
    sw.write_address(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let wire = sw.get_data().to_vec();
    assert_eq!(wire, [0u8]); // type=0 (NONE), no IP or port

    // relay-backend can re-parse it
    let mut sr = SimpleReader::new(&wire);
    let parsed = sr.read_address().unwrap();
    assert_eq!(parsed, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
}

// ===================================================================
// Test 6: Multi-relay response parsed by relay-xdp Reader
// ===================================================================

#[test]
fn test_multi_relay_response_cross_crate() {
    let relay_pk = [0x42u8; 32];
    let backend_pk = [0x43u8; 32];
    let ping_key = [0xBBu8; 32];

    // 4 relays across different subnets
    let relay_ids = [100u64, 200, 300, 400];
    let relay_addrs = [
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40001),
        SocketAddrV4::new(Ipv4Addr::new(172, 16, 0, 1), 40002),
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 40003),
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 50), 40004),
    ];
    let relay_internal = [0u8, 1, 0, 1];

    let expected_pub = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40001);

    let data = build_response_with_backend(
        &relay_ids,
        &relay_addrs,
        &relay_internal,
        expected_pub,
        false,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        &relay_pk,
        &backend_pk,
        &ping_key,
    );

    // Parse with relay-xdp Reader
    let mut r = XdpReader::new(&data);
    let _version = r.read_uint8().unwrap();
    let _timestamp = r.read_uint64().unwrap();
    let num_relays = r.read_uint32().unwrap();
    assert_eq!(num_relays, 4);

    let expected_ips = [
        (Ipv4Addr::new(10, 0, 0, 1), 40001u16),
        (Ipv4Addr::new(172, 16, 0, 1), 40002),
        (Ipv4Addr::new(192, 168, 1, 1), 40003),
        (Ipv4Addr::new(203, 0, 113, 50), 40004),
    ];

    for i in 0..4 {
        let id = r.read_uint64().unwrap();
        assert_eq!(id, relay_ids[i]);
        let _addr_type = r.read_uint8().unwrap();
        let addr_be = r.read_uint32().unwrap();
        let addr_host = u32::from_be(addr_be);
        let port = r.read_uint16().unwrap();
        let internal = r.read_uint8().unwrap();

        let expected_host = u32::from_be_bytes(expected_ips[i].0.octets());
        assert_eq!(addr_host, expected_host, "relay {i} address mismatch");
        assert_eq!(port, expected_ips[i].1, "relay {i} port mismatch");
        assert_eq!(internal, relay_internal[i], "relay {i} internal mismatch");
    }
}

// ===================================================================
// Test 7: Magic bytes preserved through cross-crate roundtrip
// ===================================================================

#[test]
fn test_magic_bytes_preserved_cross_crate() {
    let upcoming = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let current = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02];
    let previous = [0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22];

    let response = RelayUpdateResponse {
        version: 1,
        timestamp: 1700000000,
        num_relays: 0,
        relay_ids: vec![],
        relay_addresses: vec![],
        relay_internal: vec![],
        target_version: "v1".to_string(),
        upcoming_magic: upcoming,
        current_magic: current,
        previous_magic: previous,
        expected_public_address: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000),
        expected_has_internal_address: 0,
        expected_internal_address: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        expected_relay_public_key: [0u8; 32],
        expected_relay_backend_public_key: [0u8; 32],
        test_token: [0u8; ENCRYPTED_ROUTE_TOKEN_BYTES],
        ping_key: [0u8; PING_KEY_BYTES],
    };

    let data = response.write();

    // Parse with relay-xdp Reader
    let mut r = XdpReader::new(&data);
    let _version = r.read_uint8().unwrap();
    let _timestamp = r.read_uint64().unwrap();
    let num_relays = r.read_uint32().unwrap();
    assert_eq!(num_relays, 0);

    let _target_ver = r.read_string(RELAY_VERSION_LENGTH).unwrap();

    let mut read_upcoming = [0u8; 8];
    let mut read_current = [0u8; 8];
    let mut read_previous = [0u8; 8];
    r.read_bytes_into(&mut read_upcoming).unwrap();
    r.read_bytes_into(&mut read_current).unwrap();
    r.read_bytes_into(&mut read_previous).unwrap();

    assert_eq!(read_upcoming, upcoming, "upcoming magic mismatch");
    assert_eq!(read_current, current, "current magic mismatch");
    assert_eq!(read_previous, previous, "previous magic mismatch");
}

// ===================================================================
// Test 8: Ping key preserved through cross-crate roundtrip
// ===================================================================

#[test]
fn test_ping_key_preserved_cross_crate() {
    let ping_key: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];

    let data = build_response_with_backend(
        &[],
        &[],
        &[],
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000),
        false,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        &[0u8; 32],
        &[0u8; 32],
        &ping_key,
    );

    // Parse with relay-xdp Reader, skip to ping key
    let mut r = XdpReader::new(&data);
    r.read_uint8().unwrap(); // version
    r.read_uint64().unwrap(); // timestamp
    let n = r.read_uint32().unwrap(); // num_relays
    assert_eq!(n, 0);
    r.read_string(RELAY_VERSION_LENGTH).unwrap(); // target_version
    r.skip(8 * 3).unwrap(); // 3 magic values
    r.read_address().unwrap(); // expected public address
    let has_internal = r.read_uint8().unwrap(); // has_internal
    assert_eq!(has_internal, 0);
    r.skip(32).unwrap(); // relay pk
    r.skip(32).unwrap(); // backend pk
    r.skip(RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES).unwrap(); // test token

    let mut read_key = [0u8; 32];
    r.read_bytes_into(&mut read_key).unwrap();
    assert_eq!(read_key, ping_key);
}

// ===================================================================
// Test 9: Response with internal address parsed by relay-xdp Reader
// ===================================================================

#[test]
fn test_response_with_internal_address_cross_crate() {
    let relay_pk = [0x42u8; 32];
    let backend_pk = [0x43u8; 32];
    let ping_key = [0xBBu8; 32];

    let expected_pub = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 40000);
    let internal_addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 99), 40000);

    let data = build_response_with_backend(
        &[],
        &[],
        &[],
        expected_pub,
        true,
        internal_addr,
        &relay_pk,
        &backend_pk,
        &ping_key,
    );

    // Parse with relay-xdp Reader
    let mut r = XdpReader::new(&data);
    r.read_uint8().unwrap(); // version
    r.read_uint64().unwrap(); // timestamp
    let n = r.read_uint32().unwrap();
    assert_eq!(n, 0);
    r.read_string(RELAY_VERSION_LENGTH).unwrap();
    r.skip(8 * 3).unwrap(); // magic

    let (pub_addr, pub_port) = r.read_address().unwrap();
    assert_eq!(pub_addr, u32::from_be_bytes([203, 0, 113, 1]));
    assert_eq!(pub_port, 40000);

    let has_internal = r.read_uint8().unwrap();
    assert_eq!(has_internal, 1);

    let (int_addr, int_port) = r.read_address().unwrap();
    assert_eq!(int_addr, u32::from_be_bytes([10, 0, 0, 99]));
    assert_eq!(int_port, 40000);

    // Verify remaining fields parse correctly
    let mut read_pk = [0u8; 32];
    r.read_bytes_into(&mut read_pk).unwrap();
    assert_eq!(read_pk, relay_pk);
}

// ===================================================================
// Test 10: Request with shutting_down flag cross-crate
// ===================================================================

#[test]
fn test_request_shutting_down_flag_cross_crate() {
    let host_addr = u32::from_be_bytes([10, 0, 0, 1]);
    let buf = build_request_with_xdp_writer(
        host_addr,
        40000,
        1700000000,
        1699999000,
        &[],
        &[],
        &[],
        &[],
        0,
        1, // RELAY_FLAGS_SHUTTING_DOWN
    );

    let request = RelayUpdateRequest::read(&buf).expect("backend should parse");
    assert_eq!(request.relay_flags, 1);
    assert_eq!(request.num_samples, 0);
    assert_eq!(
        request.address,
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000)
    );
}
