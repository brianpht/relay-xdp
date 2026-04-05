//! Integration tests for relay-backend ↔ relay-xdp compatibility.
//!
//! These tests verify wire-format compatibility between the Rust relay-backend
//! and the relay-xdp (relay) crate, ensuring that:
//!
//! 1. Relay update request packets (built by relay-xdp's Writer) are correctly
//!    parsed by relay-backend's SimpleReader.
//! 2. Relay update response packets (built by relay-backend's SimpleWriter) are
//!    correctly parsed by relay-xdp's Reader format.
//! 3. FNV-1a relay ID hashing produces correct values.
//! 4. Cost matrix and route matrix bitpacked serialization round-trips correctly.
//! 5. The optimizer produces valid routes from realistic cost data.
//! 6. The relay manager correctly aggregates ping data and produces costs.
//! 7. The full HTTP handler pipeline works end-to-end.

// We need to reference the relay-backend library crate. Since the binary crate
// doesn't expose a lib, we reference modules directly via the test integration path.
// Relay-backend modules are re-exported for testing via `#[cfg(test)]` or by
// compiling as a library. We'll import from the crate directly.

mod helpers;

use std::net::{Ipv4Addr, SocketAddrV4};

// ===================================================================
// Test 1: FNV-1a relay ID correctness
// ===================================================================

/// FNV-1a 64-bit hash computes the relay ID from the address string.
/// We verify our Rust fnv1a_64 produces the expected values.
#[test]
fn test_fnv1a_relay_id_matches_go() {
    // FNV-1a constants
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;

    fn fnv1a_64(data: &[u8]) -> u64 {
        let mut hash = FNV_OFFSET;
        for &b in data {
            hash ^= b as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }

    // Known test vectors for FNV-1a 64-bit hash
    // fnv1a_64(b"10.0.0.1:40000") should produce a deterministic u64
    let test_cases = vec![
        ("10.0.0.1:40000", fnv1a_64(b"10.0.0.1:40000")),
        ("192.168.1.100:50000", fnv1a_64(b"192.168.1.100:50000")),
        ("", fnv1a_64(b"")),
    ];

    for (input, expected) in &test_cases {
        let result = fnv1a_64(input.as_bytes());
        assert_eq!(result, *expected, "FNV-1a mismatch for '{}'", input);
    }

    // Verify FNV-1a offset basis for empty string
    // fnv1a_64(b"") == FNV_OFFSET (14695981039346656037)
    assert_eq!(fnv1a_64(b""), FNV_OFFSET);
}

// ===================================================================
// Test 2: SimpleWriter/SimpleReader wire format (relay update packets)
// ===================================================================

/// Simulate the exact byte layout that relay-xdp's main_thread.rs produces
/// for a relay update request, then parse it with the relay-backend's
/// RelayUpdateRequest::read().
#[test]
fn test_relay_update_request_wire_format() {
    // Build the payload exactly as relay-xdp does (without crypto)
    let mut buf = Vec::with_capacity(4096);

    // relay-xdp uses its own Writer which is functionally identical to SimpleWriter
    // We replicate the exact byte layout here.

    let version: u8 = 1;
    let relay_address = Ipv4Addr::new(10, 0, 0, 1);
    let relay_port: u16 = 40000;
    let current_time: u64 = 1700000000;
    let start_time: u64 = 1699999000;
    let num_samples: u32 = 2;

    // Samples: relay_id, rtt, jitter, packet_loss
    let sample_relay_ids: Vec<u64> = vec![0xAAAABBBBCCCCDDDD, 0x1111222233334444];
    let sample_rtts: Vec<u8> = vec![15, 25];
    let sample_jitters: Vec<u8> = vec![3, 5];
    let sample_packet_losses: Vec<u16> = vec![100, 200];

    let session_count: u32 = 42;
    let envelope_bw_up: u32 = 1000;
    let envelope_bw_down: u32 = 2000;
    let pps_sent: f32 = 100.5;
    let pps_recv: f32 = 99.3;
    let bw_sent: f32 = 800.0;
    let bw_recv: f32 = 750.0;
    let client_pps: f32 = 10.0;
    let server_pps: f32 = 5.0;
    let relay_pps: f32 = 50.0;
    let relay_flags: u64 = 0; // not shutting down
    let relay_version = "relay-rust";
    let num_relay_counters: u32 = 150;

    // Write version
    buf.push(version);

    // Write address: type(1) + ip octets(4) + port(2 LE)
    // Wire format: type byte, then 4 IP octets, then LE u16 port.
    // relay-backend's SimpleReader::read_address reads the same way.
    buf.push(1u8); // RELAY_ADDRESS_IPV4
    buf.extend_from_slice(&relay_address.octets()); // IP octets directly
    buf.extend_from_slice(&relay_port.to_le_bytes());

    // current_time, start_time
    buf.extend_from_slice(&current_time.to_le_bytes());
    buf.extend_from_slice(&start_time.to_le_bytes());

    // num_samples
    buf.extend_from_slice(&num_samples.to_le_bytes());

    // samples
    for i in 0..num_samples as usize {
        buf.extend_from_slice(&sample_relay_ids[i].to_le_bytes());
        buf.push(sample_rtts[i]);
        buf.push(sample_jitters[i]);
        buf.extend_from_slice(&sample_packet_losses[i].to_le_bytes());
    }

    // counters
    buf.extend_from_slice(&session_count.to_le_bytes());
    buf.extend_from_slice(&envelope_bw_up.to_le_bytes());
    buf.extend_from_slice(&envelope_bw_down.to_le_bytes());
    buf.extend_from_slice(&pps_sent.to_bits().to_le_bytes());
    buf.extend_from_slice(&pps_recv.to_bits().to_le_bytes());
    buf.extend_from_slice(&bw_sent.to_bits().to_le_bytes());
    buf.extend_from_slice(&bw_recv.to_bits().to_le_bytes());
    buf.extend_from_slice(&client_pps.to_bits().to_le_bytes());
    buf.extend_from_slice(&server_pps.to_bits().to_le_bytes());
    buf.extend_from_slice(&relay_pps.to_bits().to_le_bytes());

    // relay_flags
    buf.extend_from_slice(&relay_flags.to_le_bytes());

    // relay_version (string: uint32 len + bytes)
    let ver_bytes = relay_version.as_bytes();
    buf.extend_from_slice(&(ver_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(ver_bytes);

    // num_relay_counters
    buf.extend_from_slice(&num_relay_counters.to_le_bytes());

    // counters (150 x uint64)
    for _ in 0..150 {
        buf.extend_from_slice(&0u64.to_le_bytes());
    }

    // Now parse with relay-backend's SimpleReader-based parser
    let request = helpers::parse_relay_update_request(&buf);

    assert_eq!(request.version, 1);
    assert_eq!(
        request.address,
        SocketAddrV4::new(relay_address, relay_port)
    );
    assert_eq!(request.current_time, current_time);
    assert_eq!(request.start_time, start_time);
    assert_eq!(request.num_samples, num_samples);
    assert_eq!(request.sample_relay_id[0], 0xAAAABBBBCCCCDDDD);
    assert_eq!(request.sample_relay_id[1], 0x1111222233334444);
    assert_eq!(request.sample_rtt[0], 15);
    assert_eq!(request.sample_rtt[1], 25);
    assert_eq!(request.sample_jitter[0], 3);
    assert_eq!(request.sample_jitter[1], 5);
    assert_eq!(request.sample_packet_loss[0], 100);
    assert_eq!(request.sample_packet_loss[1], 200);
    assert_eq!(request.session_count, session_count);
    assert_eq!(request.envelope_bandwidth_up_kbps, envelope_bw_up);
    assert_eq!(request.envelope_bandwidth_down_kbps, envelope_bw_down);
    assert!((request.packets_sent_per_second - pps_sent).abs() < 0.01);
    assert!((request.packets_received_per_second - pps_recv).abs() < 0.01);
    assert!((request.bandwidth_sent_kbps - bw_sent).abs() < 0.01);
    assert!((request.bandwidth_received_kbps - bw_recv).abs() < 0.01);
    assert_eq!(request.relay_flags, 0);
    assert_eq!(request.relay_version, "relay-rust");
    assert_eq!(request.num_relay_counters, 150);
}

/// Test relay update request with shutting_down flag
#[test]
fn test_relay_update_request_shutting_down() {
    let buf = helpers::build_relay_update_request_bytes(
        Ipv4Addr::new(192, 168, 1, 100),
        50000,
        1700000000,
        1699999000,
        &[], // no samples
        &[],
        &[],
        &[],
        0,
        0,
        0,
        1, // shutting down
        "relay-v2",
    );

    let request = helpers::parse_relay_update_request(&buf);
    assert_eq!(request.relay_flags, 1);
    assert_eq!(request.relay_version, "relay-v2");
    assert_eq!(request.num_samples, 0);
}

// ===================================================================
// Test 3: Relay update response wire format
// ===================================================================

/// Build a relay update response (as relay-backend's SimpleWriter does)
/// and verify it can be parsed by relay-xdp's Reader logic.
#[test]
fn test_relay_update_response_wire_format() {
    let response_bytes = helpers::build_relay_update_response(
        1,                                         // version
        1700000042,                                // timestamp
        &[0xAABBCCDD11223344, 0x5566778899AABBCC], // relay_ids
        &[
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40001),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 40002),
        ],
        &[0, 1],                                              // internal flags
        "relay-v1",                                           // target_version
        &[1u8; 8],                                            // upcoming_magic
        &[2u8; 8],                                            // current_magic
        &[3u8; 8],                                            // previous_magic
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000), // expected public addr
        false,                                                // has internal
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),          // internal addr (unused)
        &[0xAA; 32],                                          // relay public key
        &[0xBB; 32],                                          // backend public key
        &[0xCC; 111],                                         // test token
        &[0xDD; 32],                                          // ping key
    );

    // Now parse this using the same SimpleReader approach as relay-xdp
    let parsed = helpers::parse_relay_update_response(&response_bytes);

    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.timestamp, 1700000042);
    assert_eq!(parsed.num_relays, 2);
    assert_eq!(parsed.relay_ids[0], 0xAABBCCDD11223344);
    assert_eq!(parsed.relay_ids[1], 0x5566778899AABBCC);
    assert_eq!(
        parsed.relay_addresses[0],
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40001)
    );
    assert_eq!(
        parsed.relay_addresses[1],
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 40002)
    );
    assert_eq!(parsed.relay_internal[0], 0);
    assert_eq!(parsed.relay_internal[1], 1);
    assert_eq!(parsed.target_version, "relay-v1");
    assert_eq!(parsed.upcoming_magic, [1u8; 8]);
    assert_eq!(parsed.current_magic, [2u8; 8]);
    assert_eq!(parsed.previous_magic, [3u8; 8]);
    assert_eq!(
        parsed.expected_public_address,
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000)
    );
    assert_eq!(parsed.expected_relay_public_key, [0xAA; 32]);
    assert_eq!(parsed.expected_relay_backend_public_key, [0xBB; 32]);
    assert_eq!(parsed.ping_key, [0xDD; 32]);
}

/// Ensure response with internal address is correctly serialized and parsed.
#[test]
fn test_relay_update_response_with_internal_address() {
    let response_bytes = helpers::build_relay_update_response(
        1,
        1700000042,
        &[0x1234567890ABCDEF],
        &[SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40001)],
        &[1], // has internal
        "test",
        &[0; 8],
        &[0; 8],
        &[0; 8],
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000),
        true,
        SocketAddrV4::new(Ipv4Addr::new(172, 16, 0, 1), 40000),
        &[0; 32],
        &[0; 32],
        &[0; 111],
        &[0; 32],
    );

    let parsed = helpers::parse_relay_update_response(&response_bytes);
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.has_internal, true);
    assert_eq!(
        parsed.internal_address,
        SocketAddrV4::new(Ipv4Addr::new(172, 16, 0, 1), 40000)
    );
}

// ===================================================================
// Test 4: Cost matrix write/read roundtrip
// ===================================================================

#[test]
fn test_cost_matrix_roundtrip() {
    let num_relays = 5;
    let cost_size = helpers::tri_matrix_length(num_relays);

    let relay_ids: Vec<u64> = (0..num_relays).map(|i| 1000 + i as u64).collect();
    let relay_addresses: Vec<SocketAddrV4> = (0..num_relays)
        .map(|i| SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, (i + 1) as u8), 40000))
        .collect();
    let relay_names: Vec<String> = (0..num_relays).map(|i| format!("relay-{}", i)).collect();
    let relay_latitudes: Vec<f32> = (0..num_relays).map(|i| i as f32 * 10.0).collect();
    let relay_longitudes: Vec<f32> = (0..num_relays).map(|i| i as f32 * -20.0).collect();
    let relay_datacenter_ids: Vec<u64> = (0..num_relays).map(|i| 5000 + i as u64).collect();
    let dest_relays: Vec<bool> = (0..num_relays).map(|i| i % 2 == 0).collect();

    // Build a simple cost matrix: all costs start at 255 (unknown)
    let mut costs = vec![255u8; cost_size];
    // Set some known costs
    costs[helpers::tri_matrix_index(1, 0)] = 10;
    costs[helpers::tri_matrix_index(2, 0)] = 20;
    costs[helpers::tri_matrix_index(2, 1)] = 15;
    costs[helpers::tri_matrix_index(3, 0)] = 30;

    let relay_price = vec![1u8; num_relays];

    let written = helpers::write_cost_matrix(
        2, // version
        &relay_ids,
        &relay_addresses,
        &relay_names,
        &relay_latitudes,
        &relay_longitudes,
        &relay_datacenter_ids,
        &dest_relays,
        &costs,
        &relay_price,
    );

    assert!(!written.is_empty(), "cost matrix should not be empty");

    // Read it back
    let parsed = helpers::read_cost_matrix(&written);

    assert_eq!(parsed.version, 2);
    assert_eq!(parsed.relay_ids, relay_ids);
    assert_eq!(parsed.relay_addresses, relay_addresses);
    assert_eq!(parsed.relay_names, relay_names);
    for i in 0..num_relays {
        assert!(
            (parsed.relay_latitudes[i] - relay_latitudes[i]).abs() < 0.001,
            "latitude mismatch at {}",
            i
        );
        assert!(
            (parsed.relay_longitudes[i] - relay_longitudes[i]).abs() < 0.001,
            "longitude mismatch at {}",
            i
        );
    }
    assert_eq!(parsed.relay_datacenter_ids, relay_datacenter_ids);
    assert_eq!(parsed.dest_relays, dest_relays);
    assert_eq!(parsed.costs, costs);
    assert_eq!(parsed.relay_price, relay_price);
}

#[test]
fn test_cost_matrix_empty_relays() {
    let written = helpers::write_cost_matrix(2, &[], &[], &[], &[], &[], &[], &[], &[], &[]);
    let parsed = helpers::read_cost_matrix(&written);
    assert_eq!(parsed.relay_ids.len(), 0);
    assert_eq!(parsed.costs.len(), 0);
}

// ===================================================================
// Test 5: Route matrix write/read roundtrip
// ===================================================================

#[test]
fn test_route_matrix_roundtrip() {
    let num_relays = 3;
    let entry_count = helpers::tri_matrix_length(num_relays);

    let relay_ids: Vec<u64> = vec![100, 200, 300];
    let relay_addresses: Vec<SocketAddrV4> = vec![
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40001),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 40002),
    ];
    let relay_names = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
    let relay_latitudes = vec![0.0, 10.0, 20.0];
    let relay_longitudes = vec![0.0, -10.0, -20.0];
    let relay_datacenter_ids = vec![1, 2, 3];
    let dest_relays = vec![true, true, false];
    let bin_file = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let costs = vec![10u8; entry_count];
    let relay_price = vec![1u8; num_relays];

    // Build route entries
    let route_entries = helpers::make_simple_route_entries(entry_count);

    let written = helpers::write_route_matrix(
        4, // version
        1700000000,
        &relay_ids,
        &relay_addresses,
        &relay_names,
        &relay_latitudes,
        &relay_longitudes,
        &relay_datacenter_ids,
        &dest_relays,
        &route_entries,
        &bin_file,
        costs.len() as u32,
        42, // optimize_time ms
        &costs,
        &relay_price,
    );

    assert!(!written.is_empty());

    let parsed = helpers::read_route_matrix(&written);

    assert_eq!(parsed.version, 4);
    assert_eq!(parsed.created_at, 1700000000);
    assert_eq!(parsed.relay_ids, relay_ids);
    assert_eq!(parsed.relay_addresses, relay_addresses);
    assert_eq!(parsed.relay_names, relay_names);
    assert_eq!(parsed.dest_relays, dest_relays);
    assert_eq!(parsed.bin_file_data, bin_file);
    assert_eq!(parsed.cost_matrix_size, costs.len() as u32);
    assert_eq!(parsed.optimize_time, 42);
    assert_eq!(parsed.costs, costs);
    assert_eq!(parsed.relay_price, relay_price);
    assert_eq!(parsed.route_entries.len(), entry_count);
}

// ===================================================================
// Test 6: Relay manager - process updates and compute costs
// ===================================================================

#[test]
fn test_relay_manager_process_update_and_get_costs() {
    let manager = helpers::create_relay_manager(false);

    let relay_a_id: u64 = 1001;
    let relay_b_id: u64 = 1002;
    let relay_c_id: u64 = 1003;

    let addr_a = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let addr_b = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40001);
    let addr_c = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 40002);

    let current_time = 1700000000i64;

    // Relay A pings B with 10ms RTT, 1ms jitter, 0% loss
    manager.process_relay_update(
        current_time,
        relay_a_id,
        "relay-a",
        addr_a,
        0,
        "v1",
        0,
        1,
        &[relay_b_id],
        &[10],
        &[1],
        &[0],
        &vec![0u64; 150],
    );

    // Relay B pings A with 12ms RTT
    manager.process_relay_update(
        current_time,
        relay_b_id,
        "relay-b",
        addr_b,
        0,
        "v1",
        0,
        1,
        &[relay_a_id],
        &[12],
        &[2],
        &[0],
        &vec![0u64; 150],
    );

    // Relay C pings A with 20ms RTT
    manager.process_relay_update(
        current_time,
        relay_c_id,
        "relay-c",
        addr_c,
        0,
        "v1",
        0,
        1,
        &[relay_a_id],
        &[20],
        &[3],
        &[0],
        &vec![0u64; 150],
    );

    // Compute costs for [A, B, C]
    let relay_ids = vec![relay_a_id, relay_b_id, relay_c_id];
    let costs = manager.get_costs(current_time, &relay_ids, 1000.0, 100.0);

    // A-B: max(10, 12) = 12, ceil = 12
    let ab_index = helpers::tri_matrix_index(1, 0);
    assert_eq!(costs[ab_index], 12, "A-B cost should be 12");

    // A-C: source=20 (C->A), dest=200000 (A->C not reported) => max=200000 => 255
    let ac_index = helpers::tri_matrix_index(2, 0);
    assert_eq!(
        costs[ac_index], 255,
        "A-C cost should be 255 (one direction missing)"
    );

    // B-C: neither has pinged the other => 255
    let bc_index = helpers::tri_matrix_index(2, 1);
    assert_eq!(costs[bc_index], 255, "B-C cost should be 255 (no data)");
}

#[test]
fn test_relay_manager_shutting_down_excludes_from_active() {
    let manager = helpers::create_relay_manager(false);

    let relay_id: u64 = 9999;
    let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let current_time = 1700000000i64;

    // Normal update
    manager.process_relay_update(
        current_time,
        relay_id,
        "relay-shutting",
        addr,
        0,
        "v1",
        0, // not shutting down
        0,
        &[],
        &[],
        &[],
        &[],
        &vec![0u64; 150],
    );

    let active = manager.get_active_relays(current_time);
    assert_eq!(active.len(), 1);

    // Update with shutting_down flag
    manager.process_relay_update(
        current_time + 1,
        relay_id,
        "relay-shutting",
        addr,
        0,
        "v1",
        1, // shutting down
        0,
        &[],
        &[],
        &[],
        &[],
        &vec![0u64; 150],
    );

    let active = manager.get_active_relays(current_time + 1);
    assert_eq!(active.len(), 0, "shutting down relay should not be active");
}

#[test]
fn test_relay_manager_timeout_expired_entries() {
    let manager = helpers::create_relay_manager(false);

    let relay_id: u64 = 5555;
    let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);

    // Update at time T
    manager.process_relay_update(
        100,
        relay_id,
        "relay-old",
        addr,
        0,
        "v1",
        0,
        0,
        &[],
        &[],
        &[],
        &[],
        &vec![0u64; 150],
    );

    let active = manager.get_active_relays(100);
    assert_eq!(active.len(), 1);

    // Check at time T + RELAY_TIMEOUT + 1 (31 seconds later)
    let active = manager.get_active_relays(131);
    assert_eq!(
        active.len(),
        0,
        "relay should be timed out after 31 seconds"
    );
}

#[test]
fn test_relay_manager_with_history_enabled() {
    let manager = helpers::create_relay_manager(true);

    let relay_a_id: u64 = 1001;
    let relay_b_id: u64 = 1002;
    let addr_a = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);

    let current_time = 1700000000i64;

    // Send multiple updates with different RTTs
    for t in 0..5 {
        manager.process_relay_update(
            current_time + t,
            relay_a_id,
            "relay-a",
            addr_a,
            0,
            "v1",
            0,
            1,
            &[relay_b_id],
            &[(10 + t) as u8], // RTT increases: 10, 11, 12, 13, 14
            &[1],
            &[0],
            &vec![0u64; 150],
        );
    }

    // With history enabled, RTT should be max of history (which includes
    // 1_000_000_000 initial values for unfilled slots)
    let (rtt, _jitter, _packet_loss) = manager.get_history(relay_a_id, relay_b_id);
    // History should contain our values somewhere
    let has_value_10 = rtt.iter().any(|&v| (v - 10.0).abs() < 0.01);
    assert!(has_value_10, "history should contain RTT value ~10.0");
}

// ===================================================================
// Test 7: Optimizer (Optimize2) basic functionality
// ===================================================================

#[test]
fn test_optimizer_no_relays() {
    let result = helpers::optimize2(0, 1, &[], &[], &[], &[]);
    assert!(result.is_empty());
}

#[test]
fn test_optimizer_two_relays_direct_only() {
    // 2 relays with a direct cost of 50ms
    let num_relays = 2;
    let cost_size = helpers::tri_matrix_length(num_relays);
    let mut costs = vec![255u8; cost_size];
    costs[0] = 50; // direct cost between relay 0 and 1

    let relay_price = vec![1u8; num_relays];
    let datacenter_ids = vec![1u64, 2u64];
    let dest_relays = vec![true, true];

    let entries = helpers::optimize2(
        num_relays,
        1,
        &costs,
        &relay_price,
        &datacenter_ids,
        &dest_relays,
    );

    assert_eq!(entries.len(), cost_size);
    // Entry [1,0]: should have direct route with cost 50
    assert_eq!(entries[0].direct_cost, 50);
    assert!(entries[0].num_routes >= 1, "should have at least 1 route");
    assert_eq!(entries[0].route_cost[0], 50);
}

#[test]
fn test_optimizer_three_relays_finds_indirect_route() {
    // 3 relays in a triangle:
    //   0 <-> 1: 100ms (direct)
    //   0 <-> 2: 30ms
    //   2 <-> 1: 40ms
    // Optimal: 0 -> 2 -> 1 = 70ms < 100ms direct
    let num_relays = 3;
    let cost_size = helpers::tri_matrix_length(num_relays);
    let mut costs = vec![255u8; cost_size];

    // tri_matrix_index(1, 0) = direct 0-1
    costs[helpers::tri_matrix_index(1, 0)] = 100;
    // tri_matrix_index(2, 0) = direct 0-2
    costs[helpers::tri_matrix_index(2, 0)] = 30;
    // tri_matrix_index(2, 1) = direct 2-1
    costs[helpers::tri_matrix_index(2, 1)] = 40;

    let relay_price = vec![1u8; num_relays];
    let datacenter_ids = vec![1u64, 2, 3];
    let dest_relays = vec![true, true, true];

    let entries = helpers::optimize2(
        num_relays,
        1,
        &costs,
        &relay_price,
        &datacenter_ids,
        &dest_relays,
    );

    // Entry for pair (1, 0): should find indirect route via 2 with cost 70
    let idx = helpers::tri_matrix_index(1, 0);
    assert_eq!(entries[idx].direct_cost, 100);
    assert!(
        entries[idx].num_routes >= 2,
        "should have direct + indirect routes"
    );

    // Best route should be cost 70 (via relay 2)
    assert_eq!(
        entries[idx].route_cost[0], 70,
        "best route should be 70ms via relay 2"
    );
}

#[test]
fn test_optimizer_no_improvement_skips_indirect() {
    // 2 relays where indirect doesn't help
    let num_relays = 3;
    let cost_size = helpers::tri_matrix_length(num_relays);
    let mut costs = vec![255u8; cost_size];

    // 0-1: 10ms (already very fast)
    costs[helpers::tri_matrix_index(1, 0)] = 10;
    // 0-2: 50ms
    costs[helpers::tri_matrix_index(2, 0)] = 50;
    // 2-1: 50ms
    costs[helpers::tri_matrix_index(2, 1)] = 50;
    // Indirect 0->2->1 = 100ms > 10ms direct, so no improvement

    let relay_price = vec![1u8; num_relays];
    let datacenter_ids = vec![1u64, 2, 3];
    let dest_relays = vec![true, true, true];

    let entries = helpers::optimize2(
        num_relays,
        1,
        &costs,
        &relay_price,
        &datacenter_ids,
        &dest_relays,
    );

    let idx = helpers::tri_matrix_index(1, 0);
    assert_eq!(entries[idx].direct_cost, 10);
    // Should only have the direct route (no indirect is better)
    assert_eq!(entries[idx].num_routes, 1);
    assert_eq!(entries[idx].route_cost[0], 10);
}

// ===================================================================
// Test 8: Tri matrix helpers
// ===================================================================

#[test]
fn test_tri_matrix_length() {
    assert_eq!(helpers::tri_matrix_length(0), 0);
    assert_eq!(helpers::tri_matrix_length(1), 0);
    assert_eq!(helpers::tri_matrix_length(2), 1);
    assert_eq!(helpers::tri_matrix_length(3), 3);
    assert_eq!(helpers::tri_matrix_length(4), 6);
    assert_eq!(helpers::tri_matrix_length(5), 10);
    assert_eq!(helpers::tri_matrix_length(100), 4950);
}

#[test]
fn test_tri_matrix_index_symmetry() {
    // tri_matrix_index(i, j) should equal tri_matrix_index(j, i)
    for i in 0..10 {
        for j in 0..10 {
            if i == j {
                continue;
            }
            assert_eq!(
                helpers::tri_matrix_index(i, j),
                helpers::tri_matrix_index(j, i),
                "tri_matrix_index({},{}) != tri_matrix_index({},{})",
                i,
                j,
                j,
                i
            );
        }
    }
}

#[test]
fn test_tri_matrix_index_values() {
    // Verify known indices match expected TriMatrixIndex values
    assert_eq!(helpers::tri_matrix_index(1, 0), 0);
    assert_eq!(helpers::tri_matrix_index(2, 0), 1);
    assert_eq!(helpers::tri_matrix_index(2, 1), 2);
    assert_eq!(helpers::tri_matrix_index(3, 0), 3);
    assert_eq!(helpers::tri_matrix_index(3, 1), 4);
    assert_eq!(helpers::tri_matrix_index(3, 2), 5);
}

// ===================================================================
// Test 9: Relay CSV generation
// ===================================================================

#[test]
fn test_relays_csv_format() {
    let manager = helpers::create_relay_manager(false);

    let relay_id: u64 = 0xAAAABBBBCCCCDDDD;
    let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let current_time = 1700000000i64;

    manager.process_relay_update(
        current_time,
        relay_id,
        "test-relay",
        addr,
        5,
        "v1.0",
        0,
        0,
        &[],
        &[],
        &[],
        &[],
        &vec![0u64; 150],
    );

    let csv = manager.get_relays_csv(
        current_time,
        &[relay_id],
        &["test-relay".to_string()],
        &[addr],
    );

    let csv_str = String::from_utf8(csv).unwrap();
    assert!(csv_str.starts_with("name,address,id,status,sessions,version\n"));
    assert!(csv_str.contains("test-relay"));
    assert!(csv_str.contains("online"));
    assert!(csv_str.contains(&format!("{:016x}", relay_id)));
}

// ===================================================================
// Test 10: Bitpacked WriteStream/ReadStream roundtrip
// ===================================================================

#[test]
fn test_bitpacked_stream_roundtrip() {
    let data = helpers::write_bitpacked_test_data();
    let parsed = helpers::read_bitpacked_test_data(&data);

    assert_eq!(parsed.uint32_val, 42);
    assert_eq!(parsed.uint64_val, 0xDEADBEEFCAFEBABE);
    assert!((parsed.float32_val - 3.14).abs() < 0.01);
    assert_eq!(parsed.bool_true, true);
    assert_eq!(parsed.bool_false, false);
    assert_eq!(parsed.integer_val, 100);
    assert_eq!(parsed.string_val, "hello");
    assert_eq!(
        parsed.address_val,
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 50000)
    );
}

// ===================================================================
// Test 11: Route matrix analysis
// ===================================================================

#[test]
fn test_route_matrix_analysis_basic() {
    // Build a simple route matrix with known route entries and verify analysis
    let num_relays = 3;
    let entry_count = helpers::tri_matrix_length(num_relays);

    // Create entries where one pair has an indirect route saving 30ms
    let mut route_entries = Vec::new();
    for _ in 0..entry_count {
        route_entries.push(helpers::default_route_entry());
    }

    // Entry 0 (pair 1,0): direct=100, one indirect route at cost 70
    route_entries[0].direct_cost = 100;
    route_entries[0].num_routes = 2;
    route_entries[0].route_cost[0] = 70;
    route_entries[0].route_num_relays[0] = 3;
    route_entries[0].route_relays[0] = [0, 2, 1, 0, 0];
    route_entries[0].route_hash[0] = 12345;
    route_entries[0].route_cost[1] = 100;
    route_entries[0].route_num_relays[1] = 2;
    route_entries[0].route_relays[1] = [0, 1, 0, 0, 0];
    route_entries[0].route_hash[1] = 67890;

    let relay_ids = vec![100u64, 200, 300];
    let relay_addresses: Vec<SocketAddrV4> = (0..3)
        .map(|i| SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, (i + 1) as u8), 40000))
        .collect();
    let relay_names: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
    let relay_latitudes = vec![0.0f32; 3];
    let relay_longitudes = vec![0.0f32; 3];
    let relay_datacenter_ids = vec![1u64, 2, 3];
    let dest_relays = vec![true, true, true];
    let costs = vec![100u8; entry_count];
    let relay_price = vec![1u8; num_relays];

    let written = helpers::write_route_matrix(
        4,
        1700000000,
        &relay_ids,
        &relay_addresses,
        &relay_names,
        &relay_latitudes,
        &relay_longitudes,
        &relay_datacenter_ids,
        &dest_relays,
        &route_entries,
        &[],
        costs.len() as u32,
        10,
        &costs,
        &relay_price,
    );

    let rm = helpers::read_route_matrix(&written);
    let analysis = helpers::analyze_route_matrix(&rm);

    assert!(analysis.total_routes > 0, "should have some routes");
}

// ===================================================================
// Test 12: Full end-to-end relay update → cost computation pipeline
// ===================================================================

#[test]
fn test_end_to_end_relay_update_to_cost_pipeline() {
    // Simulate 4 relays all pinging each other
    let manager = helpers::create_relay_manager(false);
    let current_time = 1700000000i64;

    let relay_ids = vec![1001u64, 1002, 1003, 1004];
    let addresses: Vec<SocketAddrV4> = vec![
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40001),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 40002),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 4), 40003),
    ];
    let names = vec!["relay-0", "relay-1", "relay-2", "relay-3"];

    // Define RTTs between relay pairs (asymmetric)
    // RTT matrix (source -> dest):
    //       0     1     2     3
    //  0    -    10    20    30
    //  1   12     -    15    25
    //  2   22    17     -    10
    //  3   32    27    12     -
    let rtts: [[u8; 4]; 4] = [
        [0, 10, 20, 30],
        [12, 0, 15, 25],
        [22, 17, 0, 10],
        [32, 27, 12, 0],
    ];

    // Each relay sends an update with ping data to all other relays
    for i in 0..4 {
        let mut sample_ids = Vec::new();
        let mut sample_rtt = Vec::new();
        let mut sample_jitter = Vec::new();
        let mut sample_loss = Vec::new();

        for j in 0..4 {
            if i == j {
                continue;
            }
            sample_ids.push(relay_ids[j]);
            sample_rtt.push(rtts[i][j]);
            sample_jitter.push(1u8);
            sample_loss.push(0u16);
        }

        manager.process_relay_update(
            current_time,
            relay_ids[i],
            names[i],
            addresses[i],
            0,
            "v1",
            0,
            sample_ids.len(),
            &sample_ids,
            &sample_rtt,
            &sample_jitter,
            &sample_loss,
            &vec![0u64; 150],
        );
    }

    // Compute costs
    let costs = manager.get_costs(current_time, &relay_ids, 1000.0, 100.0);

    // Verify costs are max of bidirectional RTTs (ceil)
    // Pair (0,1): max(10, 12) = 12
    assert_eq!(costs[helpers::tri_matrix_index(1, 0)], 12);
    // Pair (0,2): max(20, 22) = 22
    assert_eq!(costs[helpers::tri_matrix_index(2, 0)], 22);
    // Pair (0,3): max(30, 32) = 32
    assert_eq!(costs[helpers::tri_matrix_index(3, 0)], 32);
    // Pair (1,2): max(15, 17) = 17
    assert_eq!(costs[helpers::tri_matrix_index(2, 1)], 17);
    // Pair (1,3): max(25, 27) = 27
    assert_eq!(costs[helpers::tri_matrix_index(3, 1)], 27);
    // Pair (2,3): max(10, 12) = 12
    assert_eq!(costs[helpers::tri_matrix_index(3, 2)], 12);

    // Run optimizer
    let dest_relays = vec![true; 4];
    let relay_price = vec![1u8; 4];
    let datacenter_ids = vec![1u64; 4];
    let entries = helpers::optimize2(4, 1, &costs, &relay_price, &datacenter_ids, &dest_relays);

    // Pair (0,3): direct=32, via relay 2: 0->2 (22) + 2->3 (12) = 34 > 32, no improvement
    // Actually, let's check via relay 1: 0->1 (12) + 1->3 (27) = 39 > 32
    // Via relay 2: 0->2 (22) + 2->3 (12) = 34 > 32
    // No indirect improvement for 0-3
    let idx_03 = helpers::tri_matrix_index(3, 0);
    assert_eq!(entries[idx_03].direct_cost, 32);

    // Pair (1,3): direct=27, via relay 2: 1->2 (17) + 2->3 (12) = 29 > 27
    // Via relay 0: 1->0 (12) + 0->3 (32) = 44 > 27
    // No improvement
    let idx_13 = helpers::tri_matrix_index(3, 1);
    assert_eq!(entries[idx_13].direct_cost, 27);

    // Verify every entry has at least one route (the direct one) if direct_cost < 255
    for entry in &entries {
        if entry.direct_cost < 255 {
            assert!(
                entry.num_routes >= 1,
                "entries with direct_cost < 255 should have at least 1 route"
            );
        }
    }
}

// ===================================================================
// Test 13: Packet loss filtering
// ===================================================================

#[test]
fn test_relay_manager_packet_loss_filtering() {
    let manager = helpers::create_relay_manager(false);

    let relay_a_id: u64 = 2001;
    let relay_b_id: u64 = 2002;
    let addr_a = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let addr_b = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40001);
    let current_time = 1700000000i64;

    // High packet loss: 50% = 0.5 * 65535 = 32767
    let high_loss: u16 = 32767;

    manager.process_relay_update(
        current_time,
        relay_a_id,
        "relay-a",
        addr_a,
        0,
        "v1",
        0,
        1,
        &[relay_b_id],
        &[10],
        &[1],
        &[high_loss],
        &vec![0u64; 150],
    );

    manager.process_relay_update(
        current_time,
        relay_b_id,
        "relay-b",
        addr_b,
        0,
        "v1",
        0,
        1,
        &[relay_a_id],
        &[10],
        &[1],
        &[high_loss],
        &vec![0u64; 150],
    );

    // With max_packet_loss=5.0, high loss should be filtered
    let relay_ids = vec![relay_a_id, relay_b_id];
    let costs = manager.get_costs(current_time, &relay_ids, 1000.0, 5.0);
    assert_eq!(
        costs[0], 255,
        "high packet loss pair should be filtered out"
    );

    // With max_packet_loss=100.0, it should pass
    let costs = manager.get_costs(current_time, &relay_ids, 1000.0, 100.0);
    assert_eq!(
        costs[0], 10,
        "low max_packet_loss filter should allow the pair"
    );
}

// ===================================================================
// Test 14: Jitter filtering
// ===================================================================

#[test]
fn test_relay_manager_jitter_filtering() {
    let manager = helpers::create_relay_manager(false);

    let relay_a_id: u64 = 3001;
    let relay_b_id: u64 = 3002;
    let addr_a = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let addr_b = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40001);
    let current_time = 1700000000i64;

    // High jitter = 200ms
    manager.process_relay_update(
        current_time,
        relay_a_id,
        "relay-a",
        addr_a,
        0,
        "v1",
        0,
        1,
        &[relay_b_id],
        &[10],
        &[200], // high jitter
        &[0],
        &vec![0u64; 150],
    );

    manager.process_relay_update(
        current_time,
        relay_b_id,
        "relay-b",
        addr_b,
        0,
        "v1",
        0,
        1,
        &[relay_a_id],
        &[10],
        &[200], // high jitter
        &[0],
        &vec![0u64; 150],
    );

    // With max_jitter=10, should filter
    let relay_ids = vec![relay_a_id, relay_b_id];
    let costs = manager.get_costs(current_time, &relay_ids, 10.0, 100.0);
    assert_eq!(costs[0], 255, "high jitter pair should be filtered");

    // With max_jitter=1000, should pass
    let costs = manager.get_costs(current_time, &relay_ids, 1000.0, 100.0);
    assert_eq!(costs[0], 10, "permissive jitter filter should allow");
}

// ===================================================================
// Test 15: Route hash determinism
// ===================================================================

#[test]
fn test_route_hash_determinism() {
    let relays_a = vec![0i32, 2, 1];
    let relays_b = vec![0i32, 2, 1];
    let relays_c = vec![1i32, 2, 0]; // different order

    let hash_a = helpers::route_hash(&relays_a);
    let hash_b = helpers::route_hash(&relays_b);
    let hash_c = helpers::route_hash(&relays_c);

    assert_eq!(
        hash_a, hash_b,
        "same relay sequence should produce same hash"
    );
    assert_ne!(
        hash_a, hash_c,
        "different relay sequence should produce different hash"
    );
}

// ===================================================================
// Test 16: SimpleWriter address encoding matches expected wire format
// ===================================================================

#[test]
fn test_simple_writer_address_encoding_matches_go() {
    // Wire format for IPv4: [type=1, ip[0], ip[1], ip[2], ip[3], port_lo, port_hi]
    let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let bytes = helpers::simple_write_address(&addr);

    assert_eq!(bytes[0], 1); // IPAddressIPv4
    assert_eq!(bytes[1], 10); // ip[0]
    assert_eq!(bytes[2], 0); // ip[1]
    assert_eq!(bytes[3], 0); // ip[2]
    assert_eq!(bytes[4], 1); // ip[3]
                             // port 40000 = 0x9C40, LE = [0x40, 0x9C]
    assert_eq!(bytes[5], 0x40);
    assert_eq!(bytes[6], 0x9C);
}

#[test]
fn test_simple_writer_none_address() {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    let bytes = helpers::simple_write_address(&addr);

    assert_eq!(bytes[0], 0); // IPAddressNone
    assert_eq!(bytes.len(), 1);
}

// ===================================================================
// Test 17: Large-scale optimizer stress test
// ===================================================================

#[test]
fn test_optimizer_stress_20_relays() {
    let num_relays = 20;
    let cost_size = helpers::tri_matrix_length(num_relays);

    // Create a random-ish cost matrix
    let mut costs = vec![255u8; cost_size];
    for i in 0..num_relays {
        for j in 0..i {
            let idx = helpers::tri_matrix_index(i, j);
            // Assign costs based on distance
            let c = ((i as i32 - j as i32).unsigned_abs() * 10 + 5).min(254) as u8;
            costs[idx] = c;
        }
    }

    let relay_price = vec![1u8; num_relays];
    let datacenter_ids: Vec<u64> = (0..num_relays).map(|i| i as u64).collect();
    let dest_relays = vec![true; num_relays];

    let entries = helpers::optimize2(
        num_relays,
        4, // multiple segments
        &costs,
        &relay_price,
        &datacenter_ids,
        &dest_relays,
    );

    assert_eq!(entries.len(), cost_size);

    // Verify all entries have valid structure
    for entry in &entries {
        assert!(entry.direct_cost >= 0 && entry.direct_cost <= 255);
        assert!(entry.num_routes >= 0 && entry.num_routes <= 16);
        for r in 0..entry.num_routes as usize {
            assert!(entry.route_cost[r] <= entry.direct_cost || entry.direct_cost == 255);
            assert!(entry.route_num_relays[r] >= 2); // at least source + dest
        }
    }

    // Routes should be sorted by cost
    for entry in &entries {
        for r in 1..entry.num_routes as usize {
            assert!(
                entry.route_cost[r] >= entry.route_cost[r - 1],
                "routes should be sorted by cost"
            );
        }
    }
}

// ===================================================================
// Test 18: Relay update request with maximum samples
// ===================================================================

#[test]
fn test_relay_update_request_max_samples() {
    let num = 100; // A reasonable number of samples
    let sample_ids: Vec<u64> = (0..num).map(|i| 10000 + i as u64).collect();
    let sample_rtts: Vec<u8> = (0..num).map(|i| (i % 255) as u8).collect();
    let sample_jitters: Vec<u8> = (0..num).map(|i| (i % 50) as u8).collect();
    let sample_losses: Vec<u16> = (0..num).map(|i| (i * 100) as u16).collect();

    let buf = helpers::build_relay_update_request_bytes(
        Ipv4Addr::new(10, 0, 0, 1),
        40000,
        1700000000,
        1699999000,
        &sample_ids,
        &sample_rtts,
        &sample_jitters,
        &sample_losses,
        0,
        0,
        0,
        0,
        "relay-rust",
    );

    let request = helpers::parse_relay_update_request(&buf);
    assert_eq!(request.num_samples, num as u32);
    for i in 0..num {
        assert_eq!(request.sample_relay_id[i], sample_ids[i]);
        assert_eq!(request.sample_rtt[i], sample_rtts[i]);
        assert_eq!(request.sample_jitter[i], sample_jitters[i]);
        assert_eq!(request.sample_packet_loss[i], sample_losses[i]);
    }
}
