//! Route matrix serialization.
//! Port of `modules/common/route_matrix.go`.

use std::collections::HashMap;
use std::net::SocketAddrV4;

use crate::constants::*;
use crate::encoding::{tri_matrix_index, tri_matrix_length, ReadStream, WriteStream};
use crate::optimizer::RouteEntry;

pub const ROUTE_MATRIX_VERSION_MIN: u32 = 3;
pub const ROUTE_MATRIX_VERSION_MAX: u32 = 4;
pub const ROUTE_MATRIX_VERSION_WRITE: u32 = 4;

#[derive(Clone)]
pub struct RouteMatrix {
    pub version: u32,
    pub created_at: u64,
    pub bin_file_bytes: i32,
    pub bin_file_data: Vec<u8>,

    pub relay_ids: Vec<u64>,
    pub relay_id_to_index: HashMap<u64, i32>,
    pub relay_addresses: Vec<SocketAddrV4>,
    pub relay_names: Vec<String>,
    pub relay_latitudes: Vec<f32>,
    pub relay_longitudes: Vec<f32>,
    pub relay_datacenter_ids: Vec<u64>,

    pub dest_relays: Vec<bool>,
    pub route_entries: Vec<RouteEntry>,

    pub cost_matrix_size: u32,
    pub optimize_time: u32,

    pub costs: Vec<u8>,
    pub relay_price: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct RouteMatrixAnalysis {
    pub total_routes: usize,
    pub average_num_routes: f32,
    pub average_route_length: f32,
    pub no_route_percent: f32,
    pub one_route_percent: f32,
    pub no_direct_route_percent: f32,
    pub rtt_bucket_no_improvement: f32,
    pub rtt_bucket_0_5ms: f32,
    pub rtt_bucket_5_10ms: f32,
    pub rtt_bucket_10_15ms: f32,
    pub rtt_bucket_15_20ms: f32,
    pub rtt_bucket_20_25ms: f32,
    pub rtt_bucket_25_30ms: f32,
    pub rtt_bucket_30_35ms: f32,
    pub rtt_bucket_35_40ms: f32,
    pub rtt_bucket_40_45ms: f32,
    pub rtt_bucket_45_50ms: f32,
    pub rtt_bucket_50ms_plus: f32,
}

impl RouteMatrix {
    pub fn get_max_size(&self) -> usize {
        let num_relays = self.relay_ids.len();
        let entry_count = tri_matrix_length(num_relays);
        let mut size = 1024;
        size += num_relays * (8 + 19 + MAX_RELAY_NAME_LENGTH + 4 + 4 + 8);
        size += entry_count
            * (4 + 4 + 12 * MAX_ROUTES_PER_ENTRY + 4 * MAX_ROUTES_PER_ENTRY * MAX_ROUTE_RELAYS);
        size += self.bin_file_bytes as usize;
        size += entry_count;
        size += 4 + num_relays;
        size -= size % 4;
        size
    }

    pub fn write(&self) -> Result<Vec<u8>, String> {
        let mut ws = WriteStream::new(self.get_max_size());

        ws.serialize_bits(self.version, 8);
        ws.serialize_uint64(self.created_at);

        ws.serialize_integer(self.bin_file_bytes, 0, MAX_DATABASE_SIZE);
        if self.bin_file_bytes > 0 {
            ws.serialize_bytes(&self.bin_file_data[..self.bin_file_bytes as usize]);
        }

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

        for &dest in &self.dest_relays {
            ws.serialize_bool(dest);
        }

        let num_entries = self.route_entries.len() as u32;
        ws.serialize_uint32(num_entries);

        for entry in &self.route_entries {
            ws.serialize_integer(entry.direct_cost, 0, MAX_ROUTE_COST);
            ws.serialize_integer(entry.num_routes, 0, MAX_ROUTES_PER_ENTRY as i32);

            for r in 0..entry.num_routes as usize {
                ws.serialize_integer(entry.route_cost[r], -1, MAX_ROUTE_COST);
                ws.serialize_integer(entry.route_num_relays[r], 0, MAX_ROUTE_RELAYS as i32);
                ws.serialize_uint32(entry.route_hash[r]);
                for relay_idx in 0..entry.route_num_relays[r] as usize {
                    ws.serialize_integer(entry.route_relays[r][relay_idx], 0, i32::MAX);
                }
            }
        }

        // Version >= 2
        ws.serialize_uint32(self.cost_matrix_size);
        ws.serialize_uint32(self.optimize_time);

        // Version >= 3
        if num_entries > 0 && !self.costs.is_empty() {
            ws.serialize_bytes(&self.costs);
        }

        // Version >= 4
        if num_relays > 0 && !self.relay_price.is_empty() {
            ws.serialize_bytes(&self.relay_price);
        }

        if let Some(e) = ws.error() {
            return Err(format!("failed to serialize route matrix: {}", e));
        }

        ws.flush();
        Ok(ws.get_data()[..ws.get_bytes_processed()].to_vec())
    }

    pub fn read(buffer: &[u8]) -> Result<Self, String> {
        let mut rs = ReadStream::new(buffer);

        let version = rs.serialize_bits(8);
        if version < ROUTE_MATRIX_VERSION_MIN || version > ROUTE_MATRIX_VERSION_MAX {
            return Err(format!("invalid route matrix version: {}", version));
        }

        let created_at = rs.serialize_uint64();

        let bin_file_bytes = rs.serialize_integer(0, MAX_DATABASE_SIZE);
        let mut bin_file_data = vec![];
        if bin_file_bytes > 0 {
            bin_file_data = vec![0u8; bin_file_bytes as usize];
            rs.serialize_bytes(&mut bin_file_data);
        }

        let num_relays = rs.serialize_uint32() as usize;

        let mut relay_id_to_index = HashMap::new();
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
            relay_id_to_index.insert(relay_ids[i], i as i32);
        }

        let mut dest_relays = vec![false; num_relays];
        for i in 0..num_relays {
            dest_relays[i] = rs.serialize_bool();
        }

        let num_entries = rs.serialize_uint32() as usize;
        let mut route_entries = vec![RouteEntry::default(); num_entries];

        for entry in &mut route_entries {
            entry.direct_cost = rs.serialize_integer(0, MAX_ROUTE_COST);
            entry.num_routes = rs.serialize_integer(0, MAX_ROUTES_PER_ENTRY as i32);

            for r in 0..entry.num_routes as usize {
                entry.route_cost[r] = rs.serialize_integer(-1, MAX_ROUTE_COST);
                entry.route_num_relays[r] = rs.serialize_integer(0, MAX_ROUTE_RELAYS as i32);
                entry.route_hash[r] = rs.serialize_uint32();
                for relay_idx in 0..entry.route_num_relays[r] as usize {
                    entry.route_relays[r][relay_idx] = rs.serialize_integer(0, i32::MAX);
                }
            }
        }

        let mut cost_matrix_size = 0u32;
        let mut optimize_time = 0u32;
        if version >= 2 {
            cost_matrix_size = rs.serialize_uint32();
            optimize_time = rs.serialize_uint32();
        }

        let mut costs = vec![0u8; num_entries];
        if version >= 3 && num_entries > 0 {
            rs.serialize_bytes(&mut costs);
        }

        let mut relay_price = vec![0u8; num_relays];
        if version >= 4 && num_relays > 0 {
            rs.serialize_bytes(&mut relay_price);
        }

        if let Some(e) = rs.error() {
            return Err(format!("failed to read route matrix: {}", e));
        }

        Ok(RouteMatrix {
            version,
            created_at,
            bin_file_bytes,
            bin_file_data,
            relay_ids,
            relay_id_to_index,
            relay_addresses,
            relay_names,
            relay_latitudes,
            relay_longitudes,
            relay_datacenter_ids,
            dest_relays,
            route_entries,
            cost_matrix_size,
            optimize_time,
            costs,
            relay_price,
        })
    }

    pub fn analyze(&self) -> RouteMatrixAnalysis {
        let mut analysis = RouteMatrixAnalysis::default();

        let n = self.relay_ids.len();
        let mut num_relay_pairs: f64 = 0.0;
        let mut num_no_direct: f64 = 0.0;
        let mut num_no_improvement: f64 = 0.0;
        let mut buckets = [0i32; 11];

        for i in 0..n {
            for j in 0..i {
                if !self.dest_relays[i] && !self.dest_relays[j] {
                    continue;
                }
                let idx = tri_matrix_index(i, j);
                num_relay_pairs += 1.0;

                if self.route_entries[idx].direct_cost != 255 {
                    if self.route_entries[idx].num_routes > 0 {
                        let improvement =
                            self.route_entries[idx].direct_cost - self.route_entries[idx].route_cost[0];
                        let bucket = match improvement {
                            i if i <= 5 => 0,
                            i if i <= 10 => 1,
                            i if i <= 15 => 2,
                            i if i <= 20 => 3,
                            i if i <= 25 => 4,
                            i if i <= 30 => 5,
                            i if i <= 35 => 6,
                            i if i <= 40 => 7,
                            i if i <= 45 => 8,
                            i if i <= 50 => 9,
                            _ => 10,
                        };
                        buckets[bucket] += 1;
                    } else {
                        num_no_improvement += 1.0;
                    }
                } else {
                    num_no_direct += 1.0;
                }
            }
        }

        if num_relay_pairs > 0.0 {
            analysis.no_direct_route_percent = (num_no_direct / num_relay_pairs * 100.0) as f32;
            analysis.rtt_bucket_no_improvement =
                (num_no_improvement / num_relay_pairs * 100.0) as f32;
            analysis.rtt_bucket_0_5ms = (buckets[0] as f64 / num_relay_pairs * 100.0) as f32;
            analysis.rtt_bucket_5_10ms = (buckets[1] as f64 / num_relay_pairs * 100.0) as f32;
            analysis.rtt_bucket_10_15ms = (buckets[2] as f64 / num_relay_pairs * 100.0) as f32;
            analysis.rtt_bucket_15_20ms = (buckets[3] as f64 / num_relay_pairs * 100.0) as f32;
            analysis.rtt_bucket_20_25ms = (buckets[4] as f64 / num_relay_pairs * 100.0) as f32;
            analysis.rtt_bucket_25_30ms = (buckets[5] as f64 / num_relay_pairs * 100.0) as f32;
            analysis.rtt_bucket_30_35ms = (buckets[6] as f64 / num_relay_pairs * 100.0) as f32;
            analysis.rtt_bucket_35_40ms = (buckets[7] as f64 / num_relay_pairs * 100.0) as f32;
            analysis.rtt_bucket_40_45ms = (buckets[8] as f64 / num_relay_pairs * 100.0) as f32;
            analysis.rtt_bucket_45_50ms = (buckets[9] as f64 / num_relay_pairs * 100.0) as f32;
            analysis.rtt_bucket_50ms_plus = (buckets[10] as f64 / num_relay_pairs * 100.0) as f32;
        }

        let mut total_routes: u64 = 0;
        let mut relay_pairs = 0;
        let mut no_routes = 0;
        let mut one_route = 0;
        let mut total_route_length: u64 = 0;

        for i in 0..n {
            for j in 0..i {
                if !self.dest_relays[i] && !self.dest_relays[j] {
                    continue;
                }
                relay_pairs += 1;
                let idx = tri_matrix_index(i, j);
                let nr = self.route_entries[idx].num_routes;
                total_routes += nr as u64;
                if nr == 0 {
                    no_routes += 1;
                }
                if nr == 1 {
                    one_route += 1;
                }
                for k in 0..nr as usize {
                    total_route_length += self.route_entries[idx].route_num_relays[k] as u64;
                }
            }
        }

        analysis.total_routes = total_routes as usize;
        if num_relay_pairs > 0.0 {
            analysis.average_num_routes = (total_routes as f64 / num_relay_pairs) as f32;
        }
        if total_routes > 0 {
            analysis.average_route_length = (total_route_length as f64 / total_routes as f64) as f32;
        }
        if relay_pairs > 0 {
            analysis.no_route_percent = (no_routes as f32 / relay_pairs as f32) * 100.0;
            analysis.one_route_percent = (one_route as f32 / relay_pairs as f32) * 100.0;
        }

        analysis
    }
}

