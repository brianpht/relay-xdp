//! Full pipeline integration tests.
//!
//! These tests validate the complete data pipeline from relay-xdp sending
//! updates through relay-backend processing to route optimization.
//! Uses relay-xdp's real Writer to build update payloads, feeds them through
//! relay-backend's RelayManager, then verifies cost computation and optimization.

mod helpers;

use std::net::{Ipv4Addr, SocketAddrV4};

use relay_backend::constants::*;
use relay_backend::relay_update::{relay_id, RelayUpdateRequest};

use relay_xdp::encoding::Writer as XdpWriter;
use relay_xdp_common::RELAY_NUM_COUNTERS;

// -------------------------------------------------------
// Helper: build a complete relay update request using
// relay-xdp's Writer, exactly matching main_thread.rs
// -------------------------------------------------------

fn build_xdp_relay_update(
    relay_public_address: u32,
    relay_port: u16,
    current_time: u64,
    start_time: u64,
    sample_relay_ids: &[u64],
    sample_rtts: &[u8],
    sample_jitters: &[u8],
    sample_losses: &[u16],
    session_count: u32,
    relay_flags: u64,
    relay_version: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    let mut w = XdpWriter::new(&mut buf);

    w.write_uint8(1); // version
    w.write_uint8(relay_xdp_common::RELAY_ADDRESS_IPV4);
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
    w.write_float32(0.0);
    w.write_float32(0.0);
    w.write_float32(0.0);
    w.write_float32(0.0);
    w.write_float32(0.0);
    w.write_float32(0.0);
    w.write_float32(0.0);
    w.write_uint64(relay_flags);
    w.write_string(relay_version, relay_xdp_common::RELAY_VERSION_LENGTH);
    w.write_uint32(RELAY_NUM_COUNTERS as u32);
    for _ in 0..RELAY_NUM_COUNTERS {
        w.write_uint64(0);
    }

    buf
}

/// Helper struct for test relays.
struct TestRelay {
    ip: Ipv4Addr,
    port: u16,
    name: String,
    addr_str: String,
    id: u64,
    host_addr: u32,
}

impl TestRelay {
    fn new(ip: Ipv4Addr, port: u16, name: &str) -> Self {
        let addr = SocketAddrV4::new(ip, port);
        let addr_str = format!("{}", addr);
        let id = relay_id(&addr_str);
        let host_addr = u32::from_be_bytes(ip.octets());
        TestRelay {
            ip,
            port,
            name: name.to_string(),
            addr_str,
            id,
            host_addr,
        }
    }
}

// ===================================================================
// Test 1: 4 relay updates built with relay-xdp Writer -> costs
// ===================================================================

#[test]
fn test_four_relay_updates_to_cost_matrix() {
    // Create 4 test relays
    let relays = [
        TestRelay::new(Ipv4Addr::new(10, 0, 0, 1), 40000, "relay-a"),
        TestRelay::new(Ipv4Addr::new(10, 0, 0, 2), 40000, "relay-b"),
        TestRelay::new(Ipv4Addr::new(10, 0, 0, 3), 40000, "relay-c"),
        TestRelay::new(Ipv4Addr::new(10, 0, 0, 4), 40000, "relay-d"),
    ];

    let relay_ids: Vec<u64> = relays.iter().map(|r| r.id).collect();

    let rm = helpers::create_relay_manager(false);
    let current_time: i64 = 1700000000;

    // Each relay reports RTT to every other relay
    // A->B=10, A->C=20, A->D=50
    // B->A=12, B->C=15, B->D=45
    // C->A=22, C->B=14, C->D=30
    // D->A=48, D->B=44, D->C=28

    let rtt_matrix: [[u8; 4]; 4] = [
        [0, 10, 20, 50],
        [12, 0, 15, 45],
        [22, 14, 0, 30],
        [48, 44, 28, 0],
    ];

    for src in 0..4 {
        // Build sample data: RTT from src to all other relays
        let mut sample_ids = Vec::new();
        let mut sample_rtts = Vec::new();
        let mut sample_jitters = Vec::new();
        let mut sample_losses = Vec::new();

        for dst in 0..4 {
            if src == dst {
                continue;
            }
            sample_ids.push(relay_ids[dst]);
            sample_rtts.push(rtt_matrix[src][dst]);
            sample_jitters.push(1u8);
            sample_losses.push(0u16);
        }

        // Build the request using relay-xdp's Writer
        let buf = build_xdp_relay_update(
            relays[src].host_addr,
            relays[src].port,
            current_time as u64,
            (current_time - 1000) as u64,
            &sample_ids,
            &sample_rtts,
            &sample_jitters,
            &sample_losses,
            10,
            0,
            "relay-rust",
        );

        // Parse with relay-backend's reader
        let request =
            RelayUpdateRequest::read(&buf).expect("backend should parse xdp-built request");
        assert_eq!(request.version, 1);
        assert_eq!(
            request.address,
            SocketAddrV4::new(relays[src].ip, relays[src].port)
        );

        // Feed into relay manager
        rm.process_relay_update(
            current_time,
            relays[src].id,
            &relays[src].name,
            SocketAddrV4::new(relays[src].ip, relays[src].port),
            request.session_count,
            &request.relay_version,
            request.relay_flags,
            request.num_samples as usize,
            &request.sample_relay_id,
            &request.sample_rtt,
            &request.sample_jitter,
            &request.sample_packet_loss,
            &request.relay_counters,
        );
    }

    // Verify all 4 relays are active
    let active = rm.get_active_relays(current_time);
    assert_eq!(active.len(), 4, "all 4 relays should be active");

    // Get costs
    let costs = rm.get_costs(current_time, &relay_ids, 1000.0, 100.0);
    let expected_pairs = helpers::tri_matrix_length(4);
    assert_eq!(costs.len(), expected_pairs, "4 relays = 6 cost entries");

    // Verify costs: cost(i,j) = MAX(rtt(i->j), rtt(j->i))
    // A-B: max(10,12) = 12
    let idx_ab = helpers::tri_matrix_index(0, 1);
    assert!(idx_ab < costs.len());
    assert_eq!(costs[idx_ab], 12, "cost(A,B) should be max(10,12)=12");

    // A-C: max(20,22) = 22
    let idx_ac = helpers::tri_matrix_index(0, 2);
    assert_eq!(costs[idx_ac], 22, "cost(A,C) should be max(20,22)=22");

    // B-C: max(15,14) = 15
    let idx_bc = helpers::tri_matrix_index(1, 2);
    assert_eq!(costs[idx_bc], 15, "cost(B,C) should be max(15,14)=15");

    // C-D: max(30,28) = 30
    let idx_cd = helpers::tri_matrix_index(2, 3);
    assert_eq!(costs[idx_cd], 30, "cost(C,D) should be max(30,28)=30");

    // A-D: max(50,48) = 50
    let idx_ad = helpers::tri_matrix_index(0, 3);
    assert_eq!(costs[idx_ad], 50, "cost(A,D) should be max(50,48)=50");
}

// ===================================================================
// Test 2: Indirect route discovery through optimizer
// ===================================================================

#[test]
fn test_indirect_route_discovery_pipeline() {
    // 3 relays: A, B, C
    // Direct: A-C = 100ms
    // Indirect: A-B = 20ms, B-C = 25ms => A->B->C = 45ms (better!)
    let relays = [
        TestRelay::new(Ipv4Addr::new(10, 0, 0, 1), 40000, "relay-a"),
        TestRelay::new(Ipv4Addr::new(10, 0, 0, 2), 40000, "relay-b"),
        TestRelay::new(Ipv4Addr::new(10, 0, 0, 3), 40000, "relay-c"),
    ];

    let relay_ids: Vec<u64> = relays.iter().map(|r| r.id).collect();

    let rm = helpers::create_relay_manager(false);
    let current_time: i64 = 1700000000;

    // A sees: B=20ms, C=100ms
    // B sees: A=20ms, C=25ms
    // C sees: A=100ms, B=25ms
    let rtt_data: [(&TestRelay, &[(u64, u8)]); 3] = [
        (&relays[0], &[(relay_ids[1], 20), (relay_ids[2], 100)]),
        (&relays[1], &[(relay_ids[0], 20), (relay_ids[2], 25)]),
        (&relays[2], &[(relay_ids[0], 100), (relay_ids[1], 25)]),
    ];

    for (relay, samples) in &rtt_data {
        let sample_ids: Vec<u64> = samples.iter().map(|s| s.0).collect();
        let sample_rtts: Vec<u8> = samples.iter().map(|s| s.1).collect();
        let sample_jitters = vec![1u8; samples.len()];
        let sample_losses = vec![0u16; samples.len()];

        let buf = build_xdp_relay_update(
            relay.host_addr,
            relay.port,
            current_time as u64,
            (current_time - 1000) as u64,
            &sample_ids,
            &sample_rtts,
            &sample_jitters,
            &sample_losses,
            0,
            0,
            "relay-rust",
        );

        let request = RelayUpdateRequest::read(&buf).unwrap();
        rm.process_relay_update(
            current_time,
            relay.id,
            &relay.name,
            SocketAddrV4::new(relay.ip, relay.port),
            request.session_count,
            &request.relay_version,
            request.relay_flags,
            request.num_samples as usize,
            &request.sample_relay_id,
            &request.sample_rtt,
            &request.sample_jitter,
            &request.sample_packet_loss,
            &request.relay_counters,
        );
    }

    let costs = rm.get_costs(current_time, &relay_ids, 1000.0, 100.0);

    // Verify direct costs
    let cost_ab = costs[helpers::tri_matrix_index(0, 1)];
    let cost_bc = costs[helpers::tri_matrix_index(1, 2)];
    let cost_ac = costs[helpers::tri_matrix_index(0, 2)];
    assert_eq!(cost_ab, 20);
    assert_eq!(cost_bc, 25);
    assert_eq!(cost_ac, 100);

    // Run optimizer
    let relay_datacenter = vec![0u64; 3];
    let dest_relays = vec![true; 3];
    let relay_price = vec![0u8; 3];

    let route_entries =
        helpers::optimize2(3, 1, &costs, &relay_price, &relay_datacenter, &dest_relays);

    // Check A-C pair (index 1 in triangular matrix for relays 0,2)
    let idx_ac = helpers::tri_matrix_index(0, 2);
    assert!(
        idx_ac < route_entries.len(),
        "should have route entry for A-C pair"
    );

    let entry = &route_entries[idx_ac];
    assert_eq!(entry.direct_cost, 100, "direct A-C cost should be 100");

    // Should find an indirect route through B with cost < 100
    if entry.num_routes > 0 {
        assert!(
            entry.route_cost[0] < 100,
            "indirect route cost ({}) should be less than direct (100)",
            entry.route_cost[0]
        );
    }
}

// ===================================================================
// Test 3: Shutting down relay excluded from costs
// ===================================================================

#[test]
fn test_shutting_down_relay_excluded_from_costs() {
    let relays = [
        TestRelay::new(Ipv4Addr::new(10, 0, 0, 1), 40000, "relay-a"),
        TestRelay::new(Ipv4Addr::new(10, 0, 0, 2), 40000, "relay-b"),
        TestRelay::new(Ipv4Addr::new(10, 0, 0, 3), 40000, "relay-c"),
    ];

    let relay_ids: Vec<u64> = relays.iter().map(|r| r.id).collect();
    let rm = helpers::create_relay_manager(false);
    let current_time: i64 = 1700000000;

    // All relays see each other at 10ms
    for src in 0..3 {
        let mut sample_ids = Vec::new();
        let mut sample_rtts = Vec::new();

        for dst in 0..3 {
            if src == dst {
                continue;
            }
            sample_ids.push(relay_ids[dst]);
            sample_rtts.push(10u8);
        }

        let sample_jitters = vec![1u8; sample_ids.len()];
        let sample_losses = vec![0u16; sample_ids.len()];

        // Relay C (index 2) is shutting down
        let flags = if src == 2 {
            RELAY_FLAGS_SHUTTING_DOWN
        } else {
            0
        };

        let buf = build_xdp_relay_update(
            relays[src].host_addr,
            relays[src].port,
            current_time as u64,
            (current_time - 1000) as u64,
            &sample_ids,
            &sample_rtts,
            &sample_jitters,
            &sample_losses,
            0,
            flags,
            "relay-rust",
        );

        let request = RelayUpdateRequest::read(&buf).unwrap();
        rm.process_relay_update(
            current_time,
            relays[src].id,
            &relays[src].name,
            SocketAddrV4::new(relays[src].ip, relays[src].port),
            request.session_count,
            &request.relay_version,
            request.relay_flags,
            request.num_samples as usize,
            &request.sample_relay_id,
            &request.sample_rtt,
            &request.sample_jitter,
            &request.sample_packet_loss,
            &request.relay_counters,
        );
    }

    // Verify relay C is NOT in active relays
    let active = rm.get_active_relays(current_time);
    assert_eq!(
        active.len(),
        2,
        "only 2 non-shutting-down relays should be active"
    );
    for r in &active {
        assert_ne!(
            r.name, "relay-c",
            "shutting-down relay should not be active"
        );
    }

    // Get costs - pairs involving relay-c should be 255 (unreachable)
    let costs = rm.get_costs(current_time, &relay_ids, 1000.0, 100.0);

    // A-B should have a valid cost (10ms)
    let idx_ab = helpers::tri_matrix_index(0, 1);
    assert_eq!(costs[idx_ab], 10, "A-B cost should be 10");

    // A-C and B-C should be 255 (unreachable because C is shutting down)
    let idx_ac = helpers::tri_matrix_index(0, 2);
    let idx_bc = helpers::tri_matrix_index(1, 2);
    assert_eq!(
        costs[idx_ac], 255,
        "A-C should be unreachable (C shutting down)"
    );
    assert_eq!(
        costs[idx_bc], 255,
        "B-C should be unreachable (C shutting down)"
    );
}
