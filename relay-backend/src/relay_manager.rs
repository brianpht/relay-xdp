//! In-memory relay pair state tracker.
//! Port of `modules/common/relay_manager.go`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddrV4;
use std::sync::RwLock;

use crate::constants::*;
use crate::encoding::tri_matrix_index;
use crate::encoding::tri_matrix_length;

// -------------------------------------------------------
// Types
// -------------------------------------------------------

struct DestEntry {
    last_update_time: i64,
    rtt: f32,
    jitter: f32,
    packet_loss: f32,
    history_index: usize,
    history_count: usize,
    history_rtt: [f32; RELAY_HISTORY_SIZE],
    history_jitter: [f32; RELAY_HISTORY_SIZE],
    history_packet_loss: [f32; RELAY_HISTORY_SIZE],
}

impl DestEntry {
    fn new() -> Self {
        DestEntry {
            last_update_time: 0,
            rtt: 0.0,
            jitter: 0.0,
            packet_loss: 0.0,
            history_index: 0,
            history_count: 0,
            history_rtt: [0.0; RELAY_HISTORY_SIZE],
            history_jitter: [0.0; RELAY_HISTORY_SIZE],
            history_packet_loss: [0.0; RELAY_HISTORY_SIZE],
        }
    }
}

struct SourceEntry {
    last_update_time: i64,
    relay_id: u64,
    relay_name: String,
    relay_address: SocketAddrV4,
    sessions: u32,
    relay_version: String,
    shutting_down: bool,
    dest_entries: HashMap<u64, DestEntry>,
    counters: [u64; NUM_RELAY_COUNTERS],
}

#[derive(Clone)]
pub struct Relay {
    pub id: u64,
    pub name: String,
    pub address: SocketAddrV4,
    pub status: i32,
    pub sessions: u32,
    pub version: String,
}

pub static RELAY_STATUS_STRINGS: [&str; 3] = ["offline", "online", "shutting down"];

struct RelayManagerInner {
    enable_history: bool,
    source_entries: HashMap<u64, SourceEntry>,
}

pub struct RelayManager {
    inner: RwLock<RelayManagerInner>,
}

// -------------------------------------------------------
// History helpers
// -------------------------------------------------------

fn history_max(history: &[f32; RELAY_HISTORY_SIZE], count: usize) -> f32 {
    let n = count.min(RELAY_HISTORY_SIZE);
    if n == 0 {
        return 0.0;
    }
    let mut max = 0.0f32;
    for &v in history[..n].iter() {
        if v > max {
            max = v;
        }
    }
    max
}

fn history_mean(history: &[f32; RELAY_HISTORY_SIZE], count: usize) -> f32 {
    let n = count.min(RELAY_HISTORY_SIZE);
    if n == 0 {
        return 0.0;
    }
    let sum: f64 = history[..n].iter().map(|&v| v as f64).sum();
    (sum / n as f64) as f32
}

// -------------------------------------------------------
// Implementation
// -------------------------------------------------------

impl RelayManager {
    pub fn new(enable_history: bool) -> Self {
        RelayManager {
            inner: RwLock::new(RelayManagerInner {
                enable_history,
                source_entries: HashMap::new(),
            }),
        }
    }

    pub fn process_relay_update(
        &self,
        current_time: i64,
        relay_id: u64,
        relay_name: &str,
        relay_address: SocketAddrV4,
        sessions: u32,
        relay_version: &str,
        relay_flags: u64,
        num_samples: usize,
        sample_relay_id: &[u64],
        sample_rtt: &[u8],
        sample_jitter: &[u8],
        sample_packet_loss: &[u16],
        counters: &[u64],
    ) {
        let mut inner = self.inner.write().expect("relay manager lock poisoned");

        // Look up or create source entry
        let needs_reset = match inner.source_entries.get(&relay_id) {
            Some(entry) => entry.last_update_time < current_time - RELAY_TIMEOUT,
            None => true,
        };

        if needs_reset {
            inner.source_entries.insert(
                relay_id,
                SourceEntry {
                    last_update_time: 0,
                    relay_id,
                    relay_name: String::new(),
                    relay_address: SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
                    sessions: 0,
                    relay_version: String::new(),
                    shutting_down: false,
                    dest_entries: HashMap::new(),
                    counters: [0; NUM_RELAY_COUNTERS],
                },
            );
        }

        let enable_history = inner.enable_history;
        let source_entry = inner.source_entries.get_mut(&relay_id).unwrap();

        // Time out stale dest entries
        source_entry
            .dest_entries
            .retain(|_, v| v.last_update_time >= current_time - RELAY_TIMEOUT);

        let shutting_down = (relay_flags & RELAY_FLAGS_SHUTTING_DOWN) != 0;

        source_entry.last_update_time = current_time;
        source_entry.relay_id = relay_id;
        source_entry.relay_name = relay_name.to_string();
        source_entry.relay_address = relay_address;
        source_entry.sessions = sessions;
        source_entry.relay_version = relay_version.to_string();
        source_entry.shutting_down = shutting_down;


        for i in 0..num_samples {
            let dest_relay_id = sample_relay_id[i];
            let dest_entry = source_entry
                .dest_entries
                .entry(dest_relay_id)
                .or_insert_with(DestEntry::new);

            let rtt = sample_rtt[i] as f32;
            let jitter = sample_jitter[i] as f32;
            let packet_loss = sample_packet_loss[i] as f32 / 65535.0 * 100.0;

            dest_entry.history_rtt[dest_entry.history_index] = rtt;
            dest_entry.history_jitter[dest_entry.history_index] = jitter;
            dest_entry.history_packet_loss[dest_entry.history_index] = packet_loss;

            if enable_history {
                dest_entry.rtt = history_max(&dest_entry.history_rtt, dest_entry.history_count);
                dest_entry.jitter = history_mean(&dest_entry.history_jitter, dest_entry.history_count);
                dest_entry.packet_loss = history_mean(&dest_entry.history_packet_loss, dest_entry.history_count);
            } else {
                dest_entry.rtt = rtt;
                dest_entry.jitter = jitter;
                dest_entry.packet_loss = packet_loss;
            }

            dest_entry.history_index = (dest_entry.history_index + 1) % RELAY_HISTORY_SIZE;
            if dest_entry.history_count < RELAY_HISTORY_SIZE {
                dest_entry.history_count += 1;
            }
            dest_entry.last_update_time = current_time;
        }

        // Update counters
        let count = counters.len().min(NUM_RELAY_COUNTERS);
        source_entry.counters[..count].copy_from_slice(&counters[..count]);
    }

    fn get_sample_inner(
        inner: &RelayManagerInner,
        source_relay_id: u64,
        dest_relay_id: u64,
    ) -> (f32, f32, f32) {
        let mut source_rtt: f32 = 200_000.0;
        let mut source_jitter: f32 = 200_000.0;
        let mut source_packet_loss: f32 = 200_000.0;

        let mut dest_rtt: f32 = 200_000.0;
        let mut dest_jitter: f32 = 200_000.0;
        let mut dest_packet_loss: f32 = 200_000.0;

        if let Some(src) = inner.source_entries.get(&source_relay_id) {
            if let Some(d) = src.dest_entries.get(&dest_relay_id) {
                source_rtt = d.rtt;
                source_jitter = d.jitter;
                source_packet_loss = d.packet_loss;
            }
        }

        if let Some(src) = inner.source_entries.get(&dest_relay_id) {
            if let Some(d) = src.dest_entries.get(&source_relay_id) {
                dest_rtt = d.rtt;
                dest_jitter = d.jitter;
                dest_packet_loss = d.packet_loss;
            }
        }

        (
            source_rtt.max(dest_rtt),
            source_jitter.max(dest_jitter),
            source_packet_loss.max(dest_packet_loss),
        )
    }

    pub fn get_costs(
        &self,
        current_time: i64,
        relay_ids: &[u64],
        max_jitter: f32,
        max_packet_loss: f32,
    ) -> Vec<u8> {
        let num_relays = relay_ids.len();
        let mut costs = vec![255u8; tri_matrix_length(num_relays)];

        let inner = self.inner.read().expect("relay manager lock poisoned");

        // Build active set inline to avoid double-lock
        let mut active_set = HashSet::new();
        for source_entry in inner.source_entries.values() {
            let expired = current_time - source_entry.last_update_time > RELAY_TIMEOUT;
            if !expired && !source_entry.shutting_down {
                active_set.insert(source_entry.relay_id);
            }
        }

        for i in 0..num_relays {
            let source_relay_id = relay_ids[i];
            if !active_set.contains(&source_relay_id) {
                continue;
            }
            for j in 0..i {
                let dest_relay_id = relay_ids[j];
                if !active_set.contains(&dest_relay_id) {
                    continue;
                }
                let (rtt, jitter, packet_loss) =
                    Self::get_sample_inner(&inner, source_relay_id, dest_relay_id);
                if rtt < 255.0 && jitter <= max_jitter && packet_loss <= max_packet_loss {
                    let index = tri_matrix_index(i, j);
                    let cost = rtt.ceil() as u8;
                    costs[index] = if cost == 0 { 255 } else { cost };
                }
            }
        }

        costs
    }

    pub fn get_active_relays(&self, current_time: i64) -> Vec<Relay> {
        let inner = self.inner.read().expect("relay manager lock poisoned");
        let mut active_relays = Vec::new();

        for source_entry in inner.source_entries.values() {
            let expired = current_time - source_entry.last_update_time > RELAY_TIMEOUT;
            if expired || source_entry.shutting_down {
                continue;
            }
            active_relays.push(Relay {
                id: source_entry.relay_id,
                name: source_entry.relay_name.clone(),
                address: source_entry.relay_address,
                status: RELAY_STATUS_ONLINE,
                sessions: source_entry.sessions,
                version: source_entry.relay_version.clone(),
            });
        }

        active_relays.sort_by(|a, b| a.name.cmp(&b.name));
        active_relays
    }

    pub fn get_active_relay_map(&self, current_time: i64) -> HashMap<u64, Relay> {
        let active = self.get_active_relays(current_time);
        active.into_iter().map(|r| (r.id, r)).collect()
    }

    pub fn get_relays(
        &self,
        current_time: i64,
        relay_ids: &[u64],
        relay_names: &[String],
        relay_addresses: &[SocketAddrV4],
    ) -> Vec<Relay> {
        let inner = self.inner.read().expect("relay manager lock poisoned");
        let mut relays = Vec::new();

        for source_entry in inner.source_entries.values() {
            let mut relay = Relay {
                id: source_entry.relay_id,
                name: source_entry.relay_name.clone(),
                address: source_entry.relay_address,
                status: RELAY_STATUS_ONLINE,
                sessions: source_entry.sessions,
                version: String::new(),
            };

            if source_entry.shutting_down {
                relay.status = RELAY_STATUS_SHUTTING_DOWN;
            }

            let expired = current_time - source_entry.last_update_time > RELAY_TIMEOUT;
            if expired {
                relay.status = RELAY_STATUS_OFFLINE;
            }

            if relay.status == RELAY_STATUS_ONLINE {
                relay.version = source_entry.relay_version.clone();
            }
            if relay.status != RELAY_STATUS_ONLINE {
                relay.sessions = 0;
            }

            relays.push(relay);
        }

        // Add unknown relays as offline
        for i in 0..relay_ids.len() {
            if !inner.source_entries.contains_key(&relay_ids[i]) {
                relays.push(Relay {
                    id: relay_ids[i],
                    name: relay_names[i].clone(),
                    address: relay_addresses[i],
                    status: RELAY_STATUS_OFFLINE,
                    sessions: 0,
                    version: String::new(),
                });
            }
        }

        relays.sort_by(|a, b| a.name.cmp(&b.name));
        relays
    }

    pub fn get_relays_csv(
        &self,
        current_time: i64,
        relay_ids: &[u64],
        relay_names: &[String],
        relay_addresses: &[SocketAddrV4],
    ) -> Vec<u8> {
        let mut csv = String::from("name,address,id,status,sessions,version\n");
        let relays = self.get_relays(current_time, relay_ids, relay_names, relay_addresses);

        for relay in &relays {
            csv += &format!(
                "{},{},{:016x},{},{},{}\n",
                relay.name,
                relay.address,
                relay.id,
                RELAY_STATUS_STRINGS[relay.status as usize],
                relay.sessions,
                relay.version
            );
        }

        csv.into_bytes()
    }

    pub fn get_relay_counters(&self, relay_id: u64) -> Vec<u64> {
        let inner = self.inner.read().expect("relay manager lock poisoned");
        match inner.source_entries.get(&relay_id) {
            Some(entry) => entry.counters.to_vec(),
            None => vec![],
        }
    }

    pub fn get_history(
        &self,
        source_relay_id: u64,
        dest_relay_id: u64,
    ) -> (Vec<f32>, Vec<f32>, Vec<f32>) {
        let mut rtt = vec![0.0f32; RELAY_HISTORY_SIZE];
        let mut jitter = vec![0.0f32; RELAY_HISTORY_SIZE];
        let mut packet_loss = vec![0.0f32; RELAY_HISTORY_SIZE];

        let inner = self.inner.read().expect("relay manager lock poisoned");

        if let Some(src) = inner.source_entries.get(&source_relay_id) {
            if let Some(d) = src.dest_entries.get(&dest_relay_id) {
                rtt.copy_from_slice(&d.history_rtt);
                jitter.copy_from_slice(&d.history_jitter);
                packet_loss.copy_from_slice(&d.history_packet_loss);
            }
        }

        (rtt, jitter, packet_loss)
    }
}

