//! Relay update packet parsing and response building.
//! Port of `modules/packets/relay_packets.go`.

use std::net::SocketAddrV4;

use crate::constants::*;
use crate::encoding::{SimpleReader, SimpleWriter};

// -------------------------------------------------------
// RelayUpdateRequest
// -------------------------------------------------------

pub struct RelayUpdateRequest {
    pub version: u8,
    pub address: SocketAddrV4,
    pub current_time: u64,
    pub start_time: u64,
    pub num_samples: u32,
    pub sample_relay_id: Vec<u64>,
    pub sample_rtt: Vec<u8>,
    pub sample_jitter: Vec<u8>,
    pub sample_packet_loss: Vec<u16>,
    pub session_count: u32,
    pub envelope_bandwidth_up_kbps: u32,
    pub envelope_bandwidth_down_kbps: u32,
    pub packets_sent_per_second: f32,
    pub packets_received_per_second: f32,
    pub bandwidth_sent_kbps: f32,
    pub bandwidth_received_kbps: f32,
    pub client_pings_per_second: f32,
    pub server_pings_per_second: f32,
    pub relay_pings_per_second: f32,
    pub relay_flags: u64,
    pub relay_version: String,
    pub num_relay_counters: u32,
    pub relay_counters: Vec<u64>,
}

impl RelayUpdateRequest {
    pub fn read(buffer: &[u8]) -> Result<Self, String> {
        let mut r = SimpleReader::new(buffer);

        let version = r.read_uint8().ok_or("could not read version")?;
        if version < 1 || version > 1 {
            return Err("invalid relay update request packet version".into());
        }

        let address = r.read_address().ok_or("could not read relay address")?;
        let current_time = r.read_uint64().ok_or("could not read current time")?;
        let start_time = r.read_uint64().ok_or("could not read start time")?;
        let num_samples = r.read_uint32().ok_or("could not read num samples")?;

        if num_samples as usize > MAX_RELAYS {
            return Err(format!("invalid num samples: {}", num_samples));
        }

        let mut sample_relay_id = vec![0u64; num_samples as usize];
        let mut sample_rtt = vec![0u8; num_samples as usize];
        let mut sample_jitter = vec![0u8; num_samples as usize];
        let mut sample_packet_loss = vec![0u16; num_samples as usize];

        for i in 0..num_samples as usize {
            sample_relay_id[i] = r.read_uint64().ok_or("could not read sample relay id")?;
            sample_rtt[i] = r.read_uint8().ok_or("could not read sample rtt")?;
            sample_jitter[i] = r.read_uint8().ok_or("could not read sample jitter")?;
            sample_packet_loss[i] = r.read_uint16().ok_or("could not read sample packet loss")?;
        }

        let session_count = r.read_uint32().ok_or("could not read session count")?;
        let envelope_bandwidth_up_kbps = r
            .read_uint32()
            .ok_or("could not read envelope bandwidth up")?;
        let envelope_bandwidth_down_kbps = r
            .read_uint32()
            .ok_or("could not read envelope bandwidth down")?;
        let packets_sent_per_second = r.read_float32().ok_or("could not read packets sent/s")?;
        let packets_received_per_second =
            r.read_float32().ok_or("could not read packets received/s")?;
        let bandwidth_sent_kbps = r.read_float32().ok_or("could not read bandwidth sent")?;
        let bandwidth_received_kbps =
            r.read_float32().ok_or("could not read bandwidth received")?;
        let client_pings_per_second =
            r.read_float32().ok_or("could not read client pings/s")?;
        let server_pings_per_second =
            r.read_float32().ok_or("could not read server pings/s")?;
        let relay_pings_per_second = r.read_float32().ok_or("could not read relay pings/s")?;
        let relay_flags = r.read_uint64().ok_or("could not read relay flags")?;
        let relay_version = r
            .read_string(MAX_RELAY_VERSION_LENGTH as u32)
            .ok_or("could not read relay version")?;
        let num_relay_counters = r.read_uint32().ok_or("could not read num relay counters")?;

        if num_relay_counters != NUM_RELAY_COUNTERS as u32 {
            return Err(format!(
                "wrong number of relay counters: expected {}, got {}",
                NUM_RELAY_COUNTERS, num_relay_counters
            ));
        }

        let mut relay_counters = vec![0u64; NUM_RELAY_COUNTERS];
        for i in 0..NUM_RELAY_COUNTERS {
            relay_counters[i] = r.read_uint64().ok_or("could not read relay counter")?;
        }

        Ok(RelayUpdateRequest {
            version,
            address,
            current_time,
            start_time,
            num_samples,
            sample_relay_id,
            sample_rtt,
            sample_jitter,
            sample_packet_loss,
            session_count,
            envelope_bandwidth_up_kbps,
            envelope_bandwidth_down_kbps,
            packets_sent_per_second,
            packets_received_per_second,
            bandwidth_sent_kbps,
            bandwidth_received_kbps,
            client_pings_per_second,
            server_pings_per_second,
            relay_pings_per_second,
            relay_flags,
            relay_version,
            num_relay_counters,
            relay_counters,
        })
    }
}

// -------------------------------------------------------
// RelayUpdateResponse
// -------------------------------------------------------

pub struct RelayUpdateResponse {
    pub version: u8,
    pub timestamp: u64,
    pub num_relays: u32,
    pub relay_ids: Vec<u64>,
    pub relay_addresses: Vec<SocketAddrV4>,
    pub relay_internal: Vec<u8>,
    pub target_version: String,
    pub upcoming_magic: [u8; MAGIC_BYTES],
    pub current_magic: [u8; MAGIC_BYTES],
    pub previous_magic: [u8; MAGIC_BYTES],
    pub expected_public_address: SocketAddrV4,
    pub expected_has_internal_address: u8,
    pub expected_internal_address: SocketAddrV4,
    pub expected_relay_public_key: [u8; 32],
    pub expected_relay_backend_public_key: [u8; 32],
    pub test_token: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES],
    pub ping_key: [u8; PING_KEY_BYTES],
}

impl RelayUpdateResponse {
    pub fn get_max_size(&self) -> usize {
        let mut size = 256;
        size += self.num_relays as usize * (8 + 7 + 1);
        size += MAX_RELAY_VERSION_LENGTH;
        size += MAGIC_BYTES * 3;
        size += 7 * 2;
        size += 1 + 2 * 32;
        size += ENCRYPTED_ROUTE_TOKEN_BYTES;
        size += PING_KEY_BYTES;
        size
    }

    pub fn write(&self) -> Vec<u8> {
        let mut w = SimpleWriter::new(self.get_max_size());

        w.write_uint8(self.version);
        w.write_uint64(self.timestamp);
        w.write_uint32(self.num_relays);

        for i in 0..self.num_relays as usize {
            w.write_uint64(self.relay_ids[i]);
            w.write_address(&self.relay_addresses[i]);
            w.write_uint8(self.relay_internal[i]);
        }

        w.write_string(&self.target_version, MAX_RELAY_VERSION_LENGTH as u32);
        w.write_bytes(&self.upcoming_magic);
        w.write_bytes(&self.current_magic);
        w.write_bytes(&self.previous_magic);

        w.write_address(&self.expected_public_address);
        w.write_uint8(self.expected_has_internal_address);
        if self.expected_has_internal_address != 0 {
            w.write_address(&self.expected_internal_address);
        }
        w.write_bytes(&self.expected_relay_public_key);
        w.write_bytes(&self.expected_relay_backend_public_key);
        w.write_bytes(&self.test_token);
        w.write_bytes(&self.ping_key);

        w.get_data().to_vec()
    }
}

/// Compute relay ID from address string (same as Go common.RelayId).
/// Uses FNV-1a hash of the address string.
pub fn relay_id(address: &str) -> u64 {
    fnv1a_64(address.as_bytes())
}

fn fnv1a_64(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;
    let mut hash = FNV_OFFSET;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

