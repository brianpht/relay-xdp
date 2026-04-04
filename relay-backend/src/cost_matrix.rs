//! Cost matrix serialization.
//! Port of `modules/common/cost_matrix.go`.

use std::net::SocketAddrV4;

use crate::constants::*;
use crate::encoding::{tri_matrix_length, ReadStream, WriteStream};

pub const COST_MATRIX_VERSION_MIN: u32 = 1;
pub const COST_MATRIX_VERSION_MAX: u32 = 2;
pub const COST_MATRIX_VERSION_WRITE: u32 = 2;

#[derive(Clone)]
pub struct CostMatrix {
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

impl CostMatrix {
    pub fn get_max_size(&self) -> usize {
        let num_relays = self.relay_ids.len();
        let mut size = 256
            + num_relays * (8 + 19 + MAX_RELAY_NAME_LENGTH + 4 + 4 + 8 + 1)
            + tri_matrix_length(num_relays)
            + num_relays
            + 4;
        size += 4;
        size -= size % 4;
        size
    }

    pub fn write(&self) -> Result<Vec<u8>, String> {
        let mut ws = WriteStream::new(self.get_max_size());

        ws.serialize_uint32(self.version);

        let num_relays = self.relay_ids.len() as u32;
        ws.serialize_uint32(num_relays);

        for i in 0..num_relays as usize {
            ws.serialize_uint64(self.relay_ids[i]);
            ws.serialize_address(&self.relay_addresses[i]);
            ws.serialize_string(&self.relay_names[i], MAX_RELAY_NAME_LENGTH);
            ws.serialize_float32(self.relay_latitudes[i]);
            ws.serialize_float32(self.relay_longitudes[i]);
            ws.serialize_uint64(self.relay_datacenter_ids[i]);
        }

        if !self.costs.is_empty() {
            ws.serialize_bytes(&self.costs);
        }

        if self.version >= 2 && !self.relay_price.is_empty() {
            ws.serialize_bytes(&self.relay_price);
        }

        for &dest in &self.dest_relays {
            ws.serialize_bool(dest);
        }

        if let Some(e) = ws.error() {
            return Err(format!("failed to serialize cost matrix: {}", e));
        }

        ws.flush();
        Ok(ws.get_data()[..ws.get_bytes_processed()].to_vec())
    }

    pub fn read(buffer: &[u8]) -> Result<Self, String> {
        let mut rs = ReadStream::new(buffer);

        let version = rs.serialize_uint32();
        if version < COST_MATRIX_VERSION_MIN || version > COST_MATRIX_VERSION_MAX {
            return Err(format!("invalid cost matrix version: {}", version));
        }

        let num_relays = rs.serialize_uint32() as usize;

        let mut relay_ids = vec![0u64; num_relays];
        let mut relay_addresses = Vec::with_capacity(num_relays);
        let mut relay_names = vec![String::new(); num_relays];
        let mut relay_latitudes = vec![0.0f32; num_relays];
        let mut relay_longitudes = vec![0.0f32; num_relays];
        let mut relay_datacenter_ids = vec![0u64; num_relays];

        for i in 0..num_relays {
            relay_ids[i] = rs.serialize_uint64();
            relay_addresses.push(rs.serialize_address());
            relay_names[i] = rs.serialize_string(MAX_RELAY_NAME_LENGTH);
            relay_latitudes[i] = rs.serialize_float32();
            relay_longitudes[i] = rs.serialize_float32();
            relay_datacenter_ids[i] = rs.serialize_uint64();
        }

        let cost_size = tri_matrix_length(num_relays);
        let mut costs = vec![0u8; cost_size];
        if cost_size > 0 {
            rs.serialize_bytes(&mut costs);
        }

        let mut relay_price = vec![0u8; num_relays];
        if version >= 2 && num_relays > 0 {
            rs.serialize_bytes(&mut relay_price);
        }

        let mut dest_relays = vec![false; num_relays];
        for i in 0..num_relays {
            dest_relays[i] = rs.serialize_bool();
        }

        if let Some(e) = rs.error() {
            return Err(format!("failed to read cost matrix: {}", e));
        }

        Ok(CostMatrix {
            version,
            relay_ids,
            relay_addresses,
            relay_names,
            relay_latitudes,
            relay_longitudes,
            relay_datacenter_ids,
            dest_relays,
            costs,
            relay_price,
        })
    }
}

