//! Relay manager — tracks relay set, manages ping history per relay.
//! Port of `relay_manager.c` and `relay_manager.h`.

#![allow(dead_code)]

use std::collections::HashMap;

use relay_xdp_common::{RELAY_PING_SAFETY, RELAY_PING_STATS_WINDOW, RELAY_PING_TIME};

use crate::ping_history::PingHistory;
use crate::platform;

/// A set of relays (used for delta computation between updates).
#[derive(Clone, Default)]
pub struct RelaySet {
    pub num_relays: usize,
    pub id: Vec<u64>,
    pub address: Vec<u32>,
    pub port: Vec<u16>,
    pub internal: Vec<u8>,
}

impl RelaySet {
    pub fn new() -> Self {
        Self {
            num_relays: 0,
            id: Vec::new(),
            address: Vec::new(),
            port: Vec::new(),
            internal: Vec::new(),
        }
    }

    pub fn push(&mut self, id: u64, address: u32, port: u16, internal: u8) {
        self.id.push(id);
        self.address.push(address);
        self.port.push(port);
        self.internal.push(internal);
        self.num_relays += 1;
    }

    pub fn clear(&mut self) {
        self.num_relays = 0;
        self.id.clear();
        self.address.clear();
        self.port.clear();
        self.internal.clear();
    }
}

/// Per-relay ping statistics reported to main thread.
#[derive(Clone, Default)]
pub struct PingStats {
    pub num_relays: usize,
    pub relay_ids: Vec<u64>,
    pub relay_rtt: Vec<f32>,
    pub relay_jitter: Vec<f32>,
    pub relay_packet_loss: Vec<f32>,
}

/// Manages the set of relays we ping and their histories.
pub struct RelayManager {
    pub num_relays: usize,
    pub relay_ids: Vec<u64>,
    pub relay_addresses: Vec<u32>,
    pub relay_ports: Vec<u16>,
    pub relay_internal: Vec<u8>,
    pub relay_last_ping_time: Vec<f64>,
    pub relay_ping_history: Vec<PingHistory>,
    /// O(1) lookup: (address, port) → relay index
    relay_index: HashMap<(u32, u16), usize>,
    /// Reusable buffer for get_ping_stats (B5: avoid 4 Vec allocs per call)
    ping_stats_buf: PingStats,
}

impl RelayManager {
    pub fn new() -> Self {
        Self {
            num_relays: 0,
            relay_ids: Vec::new(),
            relay_addresses: Vec::new(),
            relay_ports: Vec::new(),
            relay_internal: Vec::new(),
            relay_last_ping_time: Vec::new(),
            relay_ping_history: Vec::new(),
            relay_index: HashMap::new(),
            ping_stats_buf: PingStats::default(),
        }
    }

    /// Apply relay set changes (add new, remove deleted).
    pub fn update(&mut self, new_relays: &RelaySet, delete_relays: &RelaySet) {
        if new_relays.num_relays == 0 && delete_relays.num_relays == 0 {
            return;
        }

        // Copy existing relays minus deletions
        let mut ids = Vec::new();
        let mut addrs = Vec::new();
        let mut ports = Vec::new();
        let mut internal = Vec::new();
        let mut histories = Vec::new();

        for i in 0..self.num_relays {
            let is_deleted = delete_relays
                .id
                .iter()
                .any(|&del_id| del_id == self.relay_ids[i]);
            if !is_deleted {
                ids.push(self.relay_ids[i]);
                addrs.push(self.relay_addresses[i]);
                ports.push(self.relay_ports[i]);
                internal.push(self.relay_internal[i]);
                // Move ping history (take from old vec, replace with dummy)
                histories.push(std::mem::replace(
                    &mut self.relay_ping_history[i],
                    PingHistory::new(),
                ));
            }
        }

        // Add new relays
        for i in 0..new_relays.num_relays {
            ids.push(new_relays.id[i]);
            addrs.push(new_relays.address[i]);
            ports.push(new_relays.port[i]);
            internal.push(new_relays.internal[i]);
            histories.push(PingHistory::new());
        }

        let num = ids.len();
        self.num_relays = num;
        self.relay_ids = ids;
        self.relay_addresses = addrs;
        self.relay_ports = ports;
        self.relay_internal = internal;
        self.relay_ping_history = histories;

        // Rebuild O(1) lookup index
        self.relay_index.clear();
        for i in 0..num {
            self.relay_index.insert((self.relay_addresses[i], self.relay_ports[i]), i);
        }

        // Distribute ping times evenly
        let current_time = platform::time();
        self.relay_last_ping_time = (0..num)
            .map(|i| {
                current_time - RELAY_PING_TIME + (i as f64) * RELAY_PING_TIME / (num as f64)
            })
            .collect();
    }

    /// Process a received pong from (from_address, from_port) with given sequence.
    pub fn process_pong(&mut self, from_address: u32, from_port: u16, sequence: u64) -> bool {
        if let Some(&idx) = self.relay_index.get(&(from_address, from_port)) {
            self.relay_ping_history[idx].pong_received(sequence, platform::time());
            return true;
        }
        false
    }

    /// Get aggregate ping stats for all relays.
    /// Reuses internal buffer to avoid per-call allocations.
    pub fn get_ping_stats(&mut self) -> PingStats {
        let current_time = platform::time();
        self.ping_stats_buf.num_relays = self.num_relays;
        self.ping_stats_buf.relay_ids.clear();
        self.ping_stats_buf.relay_rtt.clear();
        self.ping_stats_buf.relay_jitter.clear();
        self.ping_stats_buf.relay_packet_loss.clear();

        for i in 0..self.num_relays {
            let hs = self.relay_ping_history[i]
                .get_stats(current_time - RELAY_PING_STATS_WINDOW, current_time, RELAY_PING_SAFETY);
            self.ping_stats_buf.relay_ids.push(self.relay_ids[i]);
            self.ping_stats_buf.relay_rtt.push(hs.rtt);
            self.ping_stats_buf.relay_jitter.push(hs.jitter);
            self.ping_stats_buf.relay_packet_loss.push(hs.packet_loss);
        }

        self.ping_stats_buf.clone()
    }
}
