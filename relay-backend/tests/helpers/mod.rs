//! Test helpers - wraps relay-backend modules for integration tests.
//!
//! Provides convenience functions that build/parse relay update packets,
//! cost matrices, route matrices, etc. using the relay-backend library.

use std::net::{Ipv4Addr, SocketAddrV4};

use relay_backend::constants::*;
use relay_backend::cost_matrix::CostMatrix;
use relay_backend::encoding::{SimpleReader, SimpleWriter};
use relay_backend::optimizer::{self, RouteEntry};
use relay_backend::relay_manager::RelayManager;
use relay_backend::relay_update::{RelayUpdateRequest, RelayUpdateResponse};
use relay_backend::route_matrix::{RouteMatrix, RouteMatrixAnalysis};

// -------------------------------------------------------
// Tri-matrix re-exports
// -------------------------------------------------------

pub fn tri_matrix_length(size: usize) -> usize {
    relay_backend::encoding::tri_matrix_length(size)
}

pub fn tri_matrix_index(i: usize, j: usize) -> usize {
    relay_backend::encoding::tri_matrix_index(i, j)
}

// -------------------------------------------------------
// Relay update request helpers
// -------------------------------------------------------

/// Parse raw bytes into a RelayUpdateRequest (used to verify wire compatibility).
pub fn parse_relay_update_request(buf: &[u8]) -> RelayUpdateRequest {
    RelayUpdateRequest::read(buf).expect("failed to parse relay update request")
}

/// Build raw bytes for a relay update request matching relay-xdp's wire format.
pub fn build_relay_update_request_bytes(
    ip: Ipv4Addr,
    port: u16,
    current_time: u64,
    start_time: u64,
    sample_relay_ids: &[u64],
    sample_rtts: &[u8],
    sample_jitters: &[u8],
    sample_losses: &[u16],
    session_count: u32,
    envelope_bw_up: u32,
    envelope_bw_down: u32,
    relay_flags: u64,
    relay_version: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);

    // version
    buf.push(1u8);

    // address: type(1) + ip octets(4) + port(2 LE)
    // SimpleReader::read_address uses raw IP octets in this format.
    buf.push(1u8); // RELAY_ADDRESS_IPV4
    buf.extend_from_slice(&ip.octets());
    buf.extend_from_slice(&port.to_le_bytes());

    // current_time, start_time
    buf.extend_from_slice(&current_time.to_le_bytes());
    buf.extend_from_slice(&start_time.to_le_bytes());

    // num_samples
    let num_samples = sample_relay_ids.len() as u32;
    buf.extend_from_slice(&num_samples.to_le_bytes());

    // samples
    for i in 0..num_samples as usize {
        buf.extend_from_slice(&sample_relay_ids[i].to_le_bytes());
        buf.push(sample_rtts[i]);
        buf.push(sample_jitters[i]);
        buf.extend_from_slice(&sample_losses[i].to_le_bytes());
    }

    // counters
    buf.extend_from_slice(&session_count.to_le_bytes());
    buf.extend_from_slice(&envelope_bw_up.to_le_bytes());
    buf.extend_from_slice(&envelope_bw_down.to_le_bytes());
    buf.extend_from_slice(&0.0f32.to_bits().to_le_bytes()); // pps_sent
    buf.extend_from_slice(&0.0f32.to_bits().to_le_bytes()); // pps_recv
    buf.extend_from_slice(&0.0f32.to_bits().to_le_bytes()); // bw_sent
    buf.extend_from_slice(&0.0f32.to_bits().to_le_bytes()); // bw_recv
    buf.extend_from_slice(&0.0f32.to_bits().to_le_bytes()); // client_pps
    buf.extend_from_slice(&0.0f32.to_bits().to_le_bytes()); // server_pps
    buf.extend_from_slice(&0.0f32.to_bits().to_le_bytes()); // relay_pps

    // relay_flags
    buf.extend_from_slice(&relay_flags.to_le_bytes());

    // relay_version (string: uint32 len + bytes)
    let ver_bytes = relay_version.as_bytes();
    buf.extend_from_slice(&(ver_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(ver_bytes);

    // num_relay_counters
    buf.extend_from_slice(&(NUM_RELAY_COUNTERS as u32).to_le_bytes());

    // counters (150 x uint64)
    for _ in 0..NUM_RELAY_COUNTERS {
        buf.extend_from_slice(&0u64.to_le_bytes());
    }

    buf
}

// -------------------------------------------------------
// Relay update response helpers
// -------------------------------------------------------

/// Parsed relay update response fields (matching what relay-xdp reads).
pub struct ParsedRelayUpdateResponse {
    pub version: u8,
    pub timestamp: u64,
    pub num_relays: u32,
    pub relay_ids: Vec<u64>,
    pub relay_addresses: Vec<SocketAddrV4>,
    pub relay_internal: Vec<u8>,
    pub target_version: String,
    pub upcoming_magic: [u8; 8],
    pub current_magic: [u8; 8],
    pub previous_magic: [u8; 8],
    pub expected_public_address: SocketAddrV4,
    pub has_internal: bool,
    pub internal_address: SocketAddrV4,
    pub expected_relay_public_key: [u8; 32],
    pub expected_relay_backend_public_key: [u8; 32],
    pub test_token: Vec<u8>,
    pub ping_key: [u8; 32],
}

/// Build relay update response bytes using SimpleWriter (relay-backend's wire format).
pub fn build_relay_update_response(
    version: u8,
    timestamp: u64,
    relay_ids: &[u64],
    relay_addresses: &[SocketAddrV4],
    relay_internal: &[u8],
    target_version: &str,
    upcoming_magic: &[u8; 8],
    current_magic: &[u8; 8],
    previous_magic: &[u8; 8],
    expected_public_address: SocketAddrV4,
    has_internal: bool,
    internal_address: SocketAddrV4,
    expected_relay_pk: &[u8; 32],
    expected_backend_pk: &[u8; 32],
    test_token: &[u8; ENCRYPTED_ROUTE_TOKEN_BYTES],
    ping_key: &[u8; PING_KEY_BYTES],
) -> Vec<u8> {
    let response = RelayUpdateResponse {
        version,
        timestamp,
        num_relays: relay_ids.len() as u32,
        relay_ids: relay_ids.to_vec(),
        relay_addresses: relay_addresses.to_vec(),
        relay_internal: relay_internal.to_vec(),
        target_version: target_version.to_string(),
        upcoming_magic: *upcoming_magic,
        current_magic: *current_magic,
        previous_magic: *previous_magic,
        expected_public_address,
        expected_has_internal_address: if has_internal { 1 } else { 0 },
        expected_internal_address: internal_address,
        expected_relay_public_key: *expected_relay_pk,
        expected_relay_backend_public_key: *expected_backend_pk,
        test_token: *test_token,
        ping_key: *ping_key,
    };

    response.write()
}

/// Parse relay update response bytes using SimpleReader (mimicking relay-xdp's reader).
pub fn parse_relay_update_response(data: &[u8]) -> ParsedRelayUpdateResponse {
    let mut r = SimpleReader::new(data);

    let version = r.read_uint8().expect("version");
    let timestamp = r.read_uint64().expect("timestamp");
    let num_relays = r.read_uint32().expect("num_relays");

    let mut relay_ids = Vec::new();
    let mut relay_addresses = Vec::new();
    let mut relay_internal_flags = Vec::new();

    for _ in 0..num_relays {
        relay_ids.push(r.read_uint64().expect("relay_id"));
        relay_addresses.push(r.read_address().expect("relay_address"));
        relay_internal_flags.push(r.read_uint8().expect("relay_internal"));
    }

    let target_version = r.read_string(MAX_RELAY_VERSION_LENGTH as u32).expect("target_version");

    let mut upcoming_magic = [0u8; 8];
    let mut current_magic = [0u8; 8];
    let mut previous_magic = [0u8; 8];
    let upcoming = r.read_bytes(8).expect("upcoming_magic");
    let current = r.read_bytes(8).expect("current_magic");
    let previous = r.read_bytes(8).expect("previous_magic");
    upcoming_magic.copy_from_slice(&upcoming);
    current_magic.copy_from_slice(&current);
    previous_magic.copy_from_slice(&previous);

    let expected_public_address = r.read_address().expect("expected_public_address");

    let has_internal_byte = r.read_uint8().expect("has_internal");
    let has_internal = has_internal_byte != 0;
    let mut internal_address = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    if has_internal {
        internal_address = r.read_address().expect("internal_address");
    }

    let mut expected_relay_public_key = [0u8; 32];
    let mut expected_relay_backend_public_key = [0u8; 32];
    let pk = r.read_bytes(32).expect("relay_pk");
    let bk = r.read_bytes(32).expect("backend_pk");
    expected_relay_public_key.copy_from_slice(&pk);
    expected_relay_backend_public_key.copy_from_slice(&bk);

    let test_token = r.read_bytes(ENCRYPTED_ROUTE_TOKEN_BYTES).expect("test_token");

    let mut ping_key = [0u8; 32];
    let pk_bytes = r.read_bytes(PING_KEY_BYTES).expect("ping_key");
    ping_key.copy_from_slice(&pk_bytes);

    ParsedRelayUpdateResponse {
        version,
        timestamp,
        num_relays,
        relay_ids,
        relay_addresses,
        relay_internal: relay_internal_flags,
        target_version,
        upcoming_magic,
        current_magic,
        previous_magic,
        expected_public_address,
        has_internal,
        internal_address,
        expected_relay_public_key,
        expected_relay_backend_public_key,
        test_token,
        ping_key,
    }
}

// -------------------------------------------------------
// Cost matrix helpers
// -------------------------------------------------------

pub struct ParsedCostMatrix {
    pub version: u32,
    pub relay_ids: Vec<u64>,
    pub relay_addresses: Vec<SocketAddrV4>,
    pub relay_names: Vec<String>,
    pub relay_latitudes: Vec<f32>,
    pub relay_longitudes: Vec<f32>,
    pub relay_datacenter_ids: Vec<u64>,
    pub dest_relays: Vec<bool>,
    pub costs: Vec<u8>,
    pub relay_price: Vec<u8>,
}

pub fn write_cost_matrix(
    version: u32,
    relay_ids: &[u64],
    relay_addresses: &[SocketAddrV4],
    relay_names: &[String],
    relay_latitudes: &[f32],
    relay_longitudes: &[f32],
    relay_datacenter_ids: &[u64],
    dest_relays: &[bool],
    costs: &[u8],
    relay_price: &[u8],
) -> Vec<u8> {
    let cm = CostMatrix {
        version,
        relay_ids: relay_ids.to_vec(),
        relay_addresses: relay_addresses.to_vec(),
        relay_names: relay_names.to_vec(),
        relay_latitudes: relay_latitudes.to_vec(),
        relay_longitudes: relay_longitudes.to_vec(),
        relay_datacenter_ids: relay_datacenter_ids.to_vec(),
        dest_relays: dest_relays.to_vec(),
        costs: costs.to_vec(),
        relay_price: relay_price.to_vec(),
    };
    cm.write().expect("failed to write cost matrix")
}

pub fn read_cost_matrix(data: &[u8]) -> ParsedCostMatrix {
    let cm = CostMatrix::read(data).expect("failed to read cost matrix");
    ParsedCostMatrix {
        version: cm.version,
        relay_ids: cm.relay_ids,
        relay_addresses: cm.relay_addresses,
        relay_names: cm.relay_names,
        relay_latitudes: cm.relay_latitudes,
        relay_longitudes: cm.relay_longitudes,
        relay_datacenter_ids: cm.relay_datacenter_ids,
        dest_relays: cm.dest_relays,
        costs: cm.costs,
        relay_price: cm.relay_price,
    }
}

// -------------------------------------------------------
// Route matrix helpers
// -------------------------------------------------------

pub struct ParsedRouteMatrix {
    pub version: u32,
    pub created_at: u64,
    pub relay_ids: Vec<u64>,
    pub relay_addresses: Vec<SocketAddrV4>,
    pub relay_names: Vec<String>,
    pub dest_relays: Vec<bool>,
    pub bin_file_data: Vec<u8>,
    pub route_entries: Vec<RouteEntry>,
    pub cost_matrix_size: u32,
    pub optimize_time: u32,
    pub costs: Vec<u8>,
    pub relay_price: Vec<u8>,
}

pub fn make_simple_route_entries(count: usize) -> Vec<RouteEntry> {
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let mut entry = RouteEntry::default();
        entry.direct_cost = 50;
        entry.num_routes = 1;
        entry.route_cost[0] = 50;
        entry.route_num_relays[0] = 2;
        entry.route_relays[0][0] = 0;
        entry.route_relays[0][1] = 1;
        entry.route_hash[0] = 42;
        entries.push(entry);
    }
    entries
}

pub fn default_route_entry() -> RouteEntry {
    RouteEntry::default()
}

pub fn write_route_matrix(
    version: u32,
    created_at: u64,
    relay_ids: &[u64],
    relay_addresses: &[SocketAddrV4],
    relay_names: &[String],
    relay_latitudes: &[f32],
    relay_longitudes: &[f32],
    relay_datacenter_ids: &[u64],
    dest_relays: &[bool],
    route_entries: &[RouteEntry],
    bin_file: &[u8],
    cost_matrix_size: u32,
    optimize_time: u32,
    costs: &[u8],
    relay_price: &[u8],
) -> Vec<u8> {
    let relay_id_to_index = relay_ids
        .iter()
        .enumerate()
        .map(|(i, &id)| (id, i as i32))
        .collect();

    let rm = RouteMatrix {
        version,
        created_at,
        bin_file_bytes: bin_file.len() as i32,
        bin_file_data: bin_file.to_vec(),
        relay_ids: relay_ids.to_vec(),
        relay_id_to_index,
        relay_addresses: relay_addresses.to_vec(),
        relay_names: relay_names.to_vec(),
        relay_latitudes: relay_latitudes.to_vec(),
        relay_longitudes: relay_longitudes.to_vec(),
        relay_datacenter_ids: relay_datacenter_ids.to_vec(),
        dest_relays: dest_relays.to_vec(),
        route_entries: route_entries.to_vec(),
        cost_matrix_size,
        optimize_time,
        costs: costs.to_vec(),
        relay_price: relay_price.to_vec(),
    };
    rm.write().expect("failed to write route matrix")
}

pub fn read_route_matrix(data: &[u8]) -> ParsedRouteMatrix {
    let rm = RouteMatrix::read(data).expect("failed to read route matrix");
    ParsedRouteMatrix {
        version: rm.version,
        created_at: rm.created_at,
        relay_ids: rm.relay_ids,
        relay_addresses: rm.relay_addresses,
        relay_names: rm.relay_names,
        dest_relays: rm.dest_relays,
        bin_file_data: rm.bin_file_data,
        route_entries: rm.route_entries,
        cost_matrix_size: rm.cost_matrix_size,
        optimize_time: rm.optimize_time,
        costs: rm.costs,
        relay_price: rm.relay_price,
    }
}

pub fn analyze_route_matrix(rm: &ParsedRouteMatrix) -> RouteMatrixAnalysis {
    // Reconstruct a full RouteMatrix for analysis
    let relay_id_to_index = rm
        .relay_ids
        .iter()
        .enumerate()
        .map(|(i, &id)| (id, i as i32))
        .collect();

    let full_rm = RouteMatrix {
        version: rm.version,
        created_at: rm.created_at,
        bin_file_bytes: rm.bin_file_data.len() as i32,
        bin_file_data: rm.bin_file_data.clone(),
        relay_ids: rm.relay_ids.clone(),
        relay_id_to_index,
        relay_addresses: rm.relay_addresses.clone(),
        relay_names: rm.relay_names.clone(),
        relay_latitudes: vec![0.0; rm.relay_ids.len()],
        relay_longitudes: vec![0.0; rm.relay_ids.len()],
        relay_datacenter_ids: vec![0; rm.relay_ids.len()],
        dest_relays: rm.dest_relays.clone(),
        route_entries: rm.route_entries.clone(),
        cost_matrix_size: rm.cost_matrix_size,
        optimize_time: rm.optimize_time,
        costs: rm.costs.clone(),
        relay_price: rm.relay_price.clone(),
    };
    full_rm.analyze()
}

// -------------------------------------------------------
// Relay manager helpers
// -------------------------------------------------------

pub fn create_relay_manager(enable_history: bool) -> RelayManager {
    RelayManager::new(enable_history)
}

// -------------------------------------------------------
// Optimizer helpers
// -------------------------------------------------------

pub fn optimize2(
    num_relays: usize,
    num_segments: usize,
    cost: &[u8],
    relay_price: &[u8],
    relay_datacenter: &[u64],
    destination_relay: &[bool],
) -> Vec<RouteEntry> {
    optimizer::optimize2(
        num_relays,
        num_segments,
        cost,
        relay_price,
        relay_datacenter,
        destination_relay,
    )
}

pub fn route_hash(relays: &[i32]) -> u32 {
    optimizer::route_hash(relays)
}

// -------------------------------------------------------
// Bitpacked stream test helpers
// -------------------------------------------------------

pub struct BitpackedTestData {
    pub uint32_val: u32,
    pub uint64_val: u64,
    pub float32_val: f32,
    pub bool_true: bool,
    pub bool_false: bool,
    pub integer_val: i32,
    pub string_val: String,
    pub address_val: SocketAddrV4,
}

pub fn write_bitpacked_test_data() -> Vec<u8> {
    use relay_backend::encoding::WriteStream;

    let mut ws = WriteStream::new(1024);
    ws.serialize_uint32(42);
    ws.serialize_uint64(0xDEADBEEFCAFEBABE);
    ws.serialize_float32(3.14);
    ws.serialize_bool(true);
    ws.serialize_bool(false);
    ws.serialize_integer(100, 0, 255);
    ws.serialize_string("hello", MAX_RELAY_NAME_LENGTH);
    ws.serialize_address(&SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 50000));
    ws.flush();
    assert!(ws.error().is_none(), "write stream error: {:?}", ws.error());
    ws.get_data()[..ws.get_bytes_processed()].to_vec()
}

pub fn read_bitpacked_test_data(data: &[u8]) -> BitpackedTestData {
    use relay_backend::encoding::ReadStream;

    let mut rs = ReadStream::new(data);
    let uint32_val = rs.serialize_uint32();
    let uint64_val = rs.serialize_uint64();
    let float32_val = rs.serialize_float32();
    let bool_true = rs.serialize_bool();
    let bool_false = rs.serialize_bool();
    let integer_val = rs.serialize_integer(0, 255);
    let string_val = rs.serialize_string(MAX_RELAY_NAME_LENGTH);
    let address_val = rs.serialize_address();
    assert!(rs.error().is_none(), "read stream error: {:?}", rs.error());

    BitpackedTestData {
        uint32_val,
        uint64_val,
        float32_val,
        bool_true,
        bool_false,
        integer_val,
        string_val,
        address_val,
    }
}

// -------------------------------------------------------
// SimpleWriter address helper
// -------------------------------------------------------

pub fn simple_write_address(addr: &SocketAddrV4) -> Vec<u8> {
    let mut w = SimpleWriter::new(32);
    w.write_address(addr);
    w.get_data().to_vec()
}

