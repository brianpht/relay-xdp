//! Relay database loader.
//! Port of the relay data loading from `modules/common/service.go`.

use std::collections::HashMap;
use std::net::SocketAddrV4;

/// Relay data loaded from environment / database bin file.
/// This is the relay configuration data needed by the backend.
pub struct RelayData {
    pub num_relays: usize,
    pub relay_ids: Vec<u64>,
    pub relay_addresses: Vec<SocketAddrV4>,
    pub relay_names: Vec<String>,
    pub relay_latitudes: Vec<f32>,
    pub relay_longitudes: Vec<f32>,
    pub relay_datacenter_ids: Vec<u64>,
    pub relay_price: Vec<u8>,
    pub relay_id_to_index: HashMap<u64, usize>,
    pub dest_relays: Vec<bool>,
    pub database_bin_file: Vec<u8>,
}

impl RelayData {
    /// Create an empty relay data structure.
    pub fn empty() -> Self {
        RelayData {
            num_relays: 0,
            relay_ids: vec![],
            relay_addresses: vec![],
            relay_names: vec![],
            relay_latitudes: vec![],
            relay_longitudes: vec![],
            relay_datacenter_ids: vec![],
            relay_price: vec![],
            relay_id_to_index: HashMap::new(),
            dest_relays: vec![],
            database_bin_file: vec![],
        }
    }
}

