//! Main thread — HTTP POST relay update loop + BPF map management.
//! Port of `relay_main.c`.

use anyhow::{bail, Context, Result};
use relay_xdp_common::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bpf::BpfContext;
use crate::config::Config;
use crate::encoding::{Reader, Writer};
use crate::manager::{PingStats, RelaySet};
use crate::platform;
use crate::RELAY_VERSION;

/// Control message sent from main thread to ping thread.
pub struct ControlMessage {
    pub current_timestamp: u64,
    pub current_magic: [u8; 8],
    pub ping_key: [u8; RELAY_PING_KEY_BYTES],
    pub new_relays: RelaySet,
    pub delete_relays: RelaySet,
}

/// Stats message sent from ping thread to main thread.
pub struct StatsMessage {
    pub pings_sent: u64,
    pub bytes_sent: u64,
    pub ping_stats: PingStats,
}

pub type MessageQueue<T> = Arc<Mutex<VecDeque<T>>>;

pub fn new_queue<T>() -> MessageQueue<T> {
    Arc::new(Mutex::new(VecDeque::new()))
}


pub struct MainThread {
    config: Arc<Config>,
    bpf: Option<Arc<Mutex<BpfContext>>>,
    control_queue: MessageQueue<ControlMessage>,
    stats_queue: MessageQueue<StatsMessage>,
    quit: Arc<AtomicBool>,
    clean_shutdown: Arc<AtomicBool>,

    // State
    start_time: u64,
    current_timestamp: u64,
    initialized: bool,
    shutting_down: bool,
    relay_ping_set: RelaySet,
    pings_sent: u64,
    bytes_sent: u64,
    ping_stats: PingStats,

    // Reusable buffers
    update_data: Vec<u8>,
    http_agent: ureq::Agent,

    // Stats tracking
    last_stats_time: f64,
    last_stats_packets_sent: u64,
    last_stats_packets_received: u64,
    last_stats_bytes_sent: u64,
    last_stats_bytes_received: u64,
    last_stats_client_pings_received: u64,
    last_stats_server_pings_received: u64,
    last_stats_relay_pings_received: u64,
}

impl MainThread {
    pub fn new(
        config: Arc<Config>,
        bpf: Option<Arc<Mutex<BpfContext>>>,
        control_queue: MessageQueue<ControlMessage>,
        stats_queue: MessageQueue<StatsMessage>,
        quit: Arc<AtomicBool>,
        clean_shutdown: Arc<AtomicBool>,
    ) -> Result<Self> {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set relay config in BPF (if available)
        if let Some(ref bpf) = bpf {
            let mut bpf_guard = bpf.lock().unwrap();
            let relay_config = RelayConfig {
                dedicated: 0,
                relay_port: config.relay_port.to_be(),
                relay_public_address: config.relay_public_address.to_be(),
                relay_internal_address: config.relay_internal_address.to_be(),
                relay_secret_key: config.relay_secret_key,
                relay_backend_public_key: config.relay_backend_public_key,
                gateway_ethernet_address: config.gateway_ethernet_address,
                use_gateway_ethernet_address: if config.use_gateway_ethernet_address {
                    1
                } else {
                    0
                },
            };
            let mut config_map = bpf_guard.config_map()?;
            config_map
                .set(0, relay_config, 0)
                .context("failed to set relay config")?;
        }

        Ok(Self {
            config,
            bpf,
            control_queue,
            stats_queue,
            quit,
            clean_shutdown,
            start_time,
            current_timestamp: 0,
            initialized: false,
            shutting_down: false,
            relay_ping_set: RelaySet::new(),
            pings_sent: 0,
            bytes_sent: 0,
            ping_stats: PingStats::default(),
            update_data: Vec::with_capacity(4096),
            http_agent: ureq::Agent::new_with_config(
                ureq::Agent::config_builder()
                    .timeout_global(Some(std::time::Duration::from_secs(10)))
                    .build(),
            ),
            last_stats_time: 0.0,
            last_stats_packets_sent: 0,
            last_stats_packets_received: 0,
            last_stats_bytes_sent: 0,
            last_stats_bytes_received: 0,
            last_stats_client_pings_received: 0,
            last_stats_server_pings_received: 0,
            last_stats_relay_pings_received: 0,
        })
    }

    /// Main loop — runs until quit signal.
    pub fn run(&mut self) -> Result<()> {
        log::info!("Starting main thread");

        let mut update_attempts = 0;

        while !self.quit.load(Ordering::Relaxed) && !self.clean_shutdown.load(Ordering::Relaxed) {
            match self.update() {
                Ok(()) => {
                    update_attempts = 0;
                }
                Err(e) => {
                    log::error!("update failed: {e:#}");
                    update_attempts += 1;
                    if update_attempts >= RELAY_MAX_UPDATE_ATTEMPTS {
                        log::error!(
                            "could not update relay {RELAY_MAX_UPDATE_ATTEMPTS} times in a row, shutting down"
                        );
                        self.quit.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
            platform::sleep(1.0);
        }

        // Handle clean shutdown (SIGTERM/SIGHUP)
        if self.clean_shutdown.load(Ordering::Relaxed) {
            println!("\nClean shutdown...");
            self.shutting_down = true;

            let mut seconds = 0u32;
            while seconds <= 60 {
                match self.update() {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("update failed during clean shutdown: {e:#}");
                        break;
                    }
                }
                println!("Shutting down in {} seconds", 60 - seconds);
                platform::sleep(1.0);
                seconds += 1;
            }

            if seconds < 60 {
                println!("Sleeping for extra 30 seconds for safety...");
                platform::sleep(30.0);
            }

            println!("Clean shutdown completed");
        } else {
            println!("\nHard shutdown!");
        }

        // Signal quit to stop ping thread
        self.quit.store(true, Ordering::Relaxed);

        Ok(())
    }

    fn update(&mut self) -> Result<()> {
        // Timeout old sessions + whitelist entries in BPF maps
        let session_stats = self.update_timeouts()?;

        // Read per-CPU stats
        let mut counters = [0u64; RELAY_NUM_COUNTERS];
        if let Some(ref bpf) = self.bpf {
            let mut bpf_guard = bpf.lock().unwrap();
            if let Ok(stats_map) = bpf_guard.stats_map() {
                if let Ok(values) = stats_map.get(&0, 0) {
                    for per_cpu_stats in values.iter() {
                        for j in 0..RELAY_NUM_COUNTERS {
                            counters[j] += per_cpu_stats.counters[j];
                        }
                    }
                }
            }
        }
        counters[RELAY_COUNTER_SESSIONS] = session_stats.session_count;
        counters[RELAY_COUNTER_ENVELOPE_KBPS_UP] = session_stats.envelope_kbps_up;
        counters[RELAY_COUNTER_ENVELOPE_KBPS_DOWN] = session_stats.envelope_kbps_down;

        // Pump stats messages from ping thread
        {
            let mut queue = self.stats_queue.lock().unwrap();
            while let Some(msg) = queue.pop_front() {
                self.pings_sent = msg.pings_sent;
                self.bytes_sent = msg.bytes_sent;
                self.ping_stats = msg.ping_stats;
            }
        }

        counters[RELAY_COUNTER_RELAY_PING_PACKET_SENT] += self.pings_sent;
        counters[RELAY_COUNTER_PACKETS_SENT] += self.pings_sent;
        counters[RELAY_COUNTER_BYTES_SENT] += self.bytes_sent;

        // Derived statistics
        let current_time = platform::time();
        let time_since_last = current_time - self.last_stats_time;
        self.last_stats_time = current_time;

        let delta = |cur: u64, last: u64| -> u64 {
            if cur > last { cur - last } else { 0 }
        };

        let pkts_sent_delta = delta(counters[RELAY_COUNTER_PACKETS_SENT], self.last_stats_packets_sent);
        let pkts_recv_delta = delta(counters[RELAY_COUNTER_PACKETS_RECEIVED], self.last_stats_packets_received);
        let bytes_sent_delta = delta(counters[RELAY_COUNTER_BYTES_SENT], self.last_stats_bytes_sent);
        let bytes_recv_delta = delta(counters[RELAY_COUNTER_BYTES_RECEIVED], self.last_stats_bytes_received);
        let client_pings_delta = delta(counters[RELAY_COUNTER_CLIENT_PING_PACKET_RECEIVED], self.last_stats_client_pings_received);
        let server_pings_delta = delta(counters[RELAY_COUNTER_SERVER_PING_PACKET_RECEIVED], self.last_stats_server_pings_received);
        let relay_pings_delta = delta(counters[RELAY_COUNTER_RELAY_PING_PACKET_RECEIVED], self.last_stats_relay_pings_received);

        let (pps_sent, pps_recv, bw_sent, bw_recv, client_pps, server_pps, relay_pps) =
            if time_since_last > 0.0 {
                (
                    pkts_sent_delta as f64 / time_since_last,
                    pkts_recv_delta as f64 / time_since_last,
                    bytes_sent_delta as f64 * 8.0 / 1000.0 / time_since_last,
                    bytes_recv_delta as f64 * 8.0 / 1000.0 / time_since_last,
                    client_pings_delta as f64 / time_since_last,
                    server_pings_delta as f64 / time_since_last,
                    relay_pings_delta as f64 / time_since_last,
                )
            } else {
                (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
            };

        self.last_stats_packets_sent = counters[RELAY_COUNTER_PACKETS_SENT];
        self.last_stats_packets_received = counters[RELAY_COUNTER_PACKETS_RECEIVED];
        self.last_stats_bytes_sent = counters[RELAY_COUNTER_BYTES_SENT];
        self.last_stats_bytes_received = counters[RELAY_COUNTER_BYTES_RECEIVED];
        self.last_stats_client_pings_received = counters[RELAY_COUNTER_CLIENT_PING_PACKET_RECEIVED];
        self.last_stats_server_pings_received = counters[RELAY_COUNTER_SERVER_PING_PACKET_RECEIVED];
        self.last_stats_relay_pings_received = counters[RELAY_COUNTER_RELAY_PING_PACKET_RECEIVED];

        // Build update payload (reuse buffer)
        self.update_data.clear();
        let mut w = Writer::new(&mut self.update_data);

        let update_version: u8 = 1;
        w.write_uint8(update_version);

        // Relay address (network order)
        w.write_uint8(RELAY_ADDRESS_IPV4);
        w.write_uint32(self.config.relay_public_address.to_be());
        w.write_uint16(self.config.relay_port);

        // Everything after this point gets encrypted
        let _encrypt_start = w.position();

        let local_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        w.write_uint64(local_timestamp);
        w.write_uint64(self.start_time);

        // Ping stats
        w.write_uint32(self.ping_stats.num_relays as u32);
        for i in 0..self.ping_stats.num_relays {
            w.write_uint64(self.ping_stats.relay_ids[i]);
            let rtt = self.ping_stats.relay_rtt[i].ceil().clamp(0.0, 255.0) as u8;
            let jitter = self.ping_stats.relay_jitter[i].ceil().clamp(0.0, 255.0) as u8;
            let packet_loss = (self.ping_stats.relay_packet_loss[i] / 100.0 * 65535.0)
                .ceil()
                .clamp(0.0, 65535.0) as u16;
            w.write_uint8(rtt);
            w.write_uint8(jitter);
            w.write_uint16(packet_loss);
        }

        w.write_uint32(counters[RELAY_COUNTER_SESSIONS] as u32);
        w.write_uint32(counters[RELAY_COUNTER_ENVELOPE_KBPS_UP] as u32);
        w.write_uint32(counters[RELAY_COUNTER_ENVELOPE_KBPS_DOWN] as u32);
        w.write_float32(pps_sent as f32);
        w.write_float32(pps_recv as f32);
        w.write_float32(bw_sent as f32);
        w.write_float32(bw_recv as f32);
        w.write_float32(client_pps as f32);
        w.write_float32(server_pps as f32);
        w.write_float32(relay_pps as f32);

        let relay_flags: u64 = if self.shutting_down { 1 } else { 0 };
        w.write_uint64(relay_flags);

        w.write_string(RELAY_VERSION, RELAY_VERSION_LENGTH);

        w.write_uint32(RELAY_NUM_COUNTERS as u32);
        for i in 0..RELAY_NUM_COUNTERS {
            w.write_uint64(counters[i]);
        }

        // Encrypt the data after the relay address header using crypto_box
        const CRYPTO_BOX_NONCEBYTES: usize = 24;

        let encrypt_start = _encrypt_start;
        let plaintext = self.update_data[encrypt_start..].to_vec();

        // Generate random nonce
        let mut nonce_bytes = [0u8; CRYPTO_BOX_NONCEBYTES];
        crate::platform::random_bytes(&mut nonce_bytes);
        let nonce = crypto_box::Nonce::from(nonce_bytes);

        // Build crypto_box keys
        let server_pk = crypto_box::PublicKey::from(self.config.relay_backend_public_key);
        let client_sk = crypto_box::SecretKey::from(self.config.relay_private_key);
        let salsa_box = crypto_box::SalsaBox::new(&server_pk, &client_sk);

        // Encrypt
        use crypto_box::aead::AeadInPlace;
        let mut ciphertext = plaintext;
        let tag = salsa_box
            .encrypt_in_place_detached(&nonce, b"", &mut ciphertext)
            .map_err(|e| anyhow::anyhow!("crypto_box encrypt failed: {e}"))?;

        // Rebuild update_data: header + MAC(16) + ciphertext + nonce
        self.update_data.truncate(encrypt_start);
        self.update_data.extend_from_slice(&tag);
        self.update_data.extend_from_slice(&ciphertext);
        self.update_data.extend_from_slice(&nonce_bytes);

        let update_url = format!("{}/relay_update", self.config.relay_backend_url);

        // POST the update (B10: reuse persistent HTTP agent for connection keep-alive)
        let response = self.http_agent.post(&update_url)
            .header("Content-Type", "application/octet-stream")
            .header("User-Agent", "network next relay")
            .send(&self.update_data)
            .context("failed to post relay update")?;

        if response.status().as_u16() != 200 {
            bail!("relay update response is {}", response.status());
        }

        // Read response body
        let response_data = response
            .into_body()
            .read_to_vec()
            .context("failed to read response")?;

        self.parse_update_response(&response_data)?;

        Ok(())
    }

    /// Parse the relay update response. Public for testing.
    pub fn parse_update_response(&mut self, data: &[u8]) -> Result<()> {
        let mut r = Reader::new(data);

        let version = r.read_uint8().context("failed to read response version")?;
        if version != 1 {
            bail!("bad relay update response version: expected 1, got {version}");
        }

        let backend_timestamp = r.read_uint64().context("failed to read backend timestamp")?;

        if !self.initialized {
            log::info!("Relay initialized");
            self.initialized = true;
        }

        self.current_timestamp = backend_timestamp;

        let num_relays = r.read_uint32().context("failed to read num_relays")? as usize;
        if num_relays > MAX_RELAYS {
            bail!("too many relays to ping: max {MAX_RELAYS}, got {num_relays}");
        }

        let mut relay_ping_set = RelaySet::new();
        for _ in 0..num_relays {
            let id = r.read_uint64().context("failed to read relay id")?;
            let addr_type = r.read_uint8().context("failed to read relay address type")?;
            if addr_type != RELAY_ADDRESS_IPV4 {
                bail!("only ipv4 relay addresses are supported");
            }
            let addr_be = r.read_uint32().context("failed to read relay address")?;
            let addr = u32::from_be(addr_be);
            let port = r.read_uint16().context("failed to read relay port")?;
            let internal = r.read_uint8().context("failed to read relay internal flag")?;
            relay_ping_set.push(id, addr, port, internal);
        }

        let _target_version = r.read_string(RELAY_VERSION_LENGTH).context("failed to read target version")?;

        let mut next_magic = [0u8; 8];
        let mut current_magic = [0u8; 8];
        let mut previous_magic = [0u8; 8];
        r.read_bytes_into(&mut next_magic).context("failed to read next magic")?;
        r.read_bytes_into(&mut current_magic).context("failed to read current magic")?;
        r.read_bytes_into(&mut previous_magic).context("failed to read previous magic")?;

        let (expected_public_address, expected_port) = r.read_address().context("failed to read expected address")?;
        if self.config.relay_public_address != expected_public_address {
            bail!("relay public address mismatch");
        }
        if self.config.relay_port != expected_port {
            bail!("relay port mismatch");
        }

        let has_internal = r.read_uint8().context("failed to read has_internal flag")?;
        if has_internal != 0 {
            let (expected_internal, _) = r.read_address().context("failed to read internal address")?;
            if self.config.relay_internal_address != expected_internal {
                bail!("relay internal address mismatch");
            }
        }

        let mut expected_relay_pk = [0u8; RELAY_PUBLIC_KEY_BYTES];
        let mut _expected_backend_pk = [0u8; RELAY_BACKEND_PUBLIC_KEY_BYTES];
        r.read_bytes_into(&mut expected_relay_pk).context("failed to read relay public key")?;
        r.read_bytes_into(&mut _expected_backend_pk).context("failed to read backend public key")?;

        if expected_relay_pk != self.config.relay_public_key {
            bail!("relay public key does not match expected value");
        }

        // Skip dummy route token
        r.skip(RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES).context("failed to skip dummy route token")?;

        let mut ping_key = [0u8; RELAY_PING_KEY_BYTES];
        r.read_bytes_into(&mut ping_key).context("failed to read ping key")?;

        // Update BPF state
        if let Some(ref bpf) = self.bpf {
            let mut bpf_guard = bpf.lock().unwrap();
            let state = RelayState {
                current_timestamp: self.current_timestamp,
                current_magic,
                previous_magic,
                next_magic,
                ping_key,
            };
            if let Ok(mut state_map) = bpf_guard.state_map() {
                state_map.set(0, state, 0).ok();
            }
        }

        // Check if control queue is full (skip if so)
        {
            let queue = self.control_queue.lock().unwrap();
            if queue.len() >= 64 {
                return Ok(());
            }
        }

        // Compute relay deltas using HashSet for O(n) instead of O(n²)
        let old_ids: HashSet<u64> = self.relay_ping_set.id.iter().copied().collect();
        let new_ids: HashSet<u64> = relay_ping_set.id.iter().copied().collect();

        let mut new_relays = RelaySet::new();
        for i in 0..relay_ping_set.num_relays {
            if !old_ids.contains(&relay_ping_set.id[i]) {
                new_relays.push(
                    relay_ping_set.id[i],
                    relay_ping_set.address[i],
                    relay_ping_set.port[i],
                    relay_ping_set.internal[i],
                );
            }
        }

        let mut delete_relays = RelaySet::new();
        for i in 0..self.relay_ping_set.num_relays {
            if !new_ids.contains(&self.relay_ping_set.id[i]) {
                delete_relays.push(
                    self.relay_ping_set.id[i],
                    self.relay_ping_set.address[i],
                    self.relay_ping_set.port[i],
                    self.relay_ping_set.internal[i],
                );
            }
        }

        // Send control message to ping thread
        let msg = ControlMessage {
            current_timestamp: backend_timestamp,
            current_magic,
            ping_key,
            new_relays,
            delete_relays,
        };

        {
            let mut queue = self.control_queue.lock().unwrap();
            queue.push_back(msg);
        }

        self.relay_ping_set = relay_ping_set;

        Ok(())
    }

    fn update_timeouts(&self) -> Result<SessionStats> {
        let mut stats = SessionStats::default();

        let bpf = match self.bpf {
            Some(ref bpf) => bpf,
            None => return Ok(stats),
        };

        // Phase 1: Lock → iterate session_map → collect expired keys → unlock
        let session_keys_to_delete: Vec<SessionKey>;
        {
            let mut bpf_guard = bpf.lock().unwrap();
            if let Ok(session_map) = bpf_guard.session_map() {
                session_keys_to_delete = session_map
                    .iter()
                    .filter_map(|result| {
                        if let Ok((key, value)) = result {
                            stats.session_count += 1;
                            stats.envelope_kbps_up += value.envelope_kbps_up as u64;
                            stats.envelope_kbps_down += value.envelope_kbps_down as u64;
                            if value.expire_timestamp < self.current_timestamp {
                                return Some(key);
                            }
                        }
                        None
                    })
                    .collect();
            } else {
                session_keys_to_delete = Vec::new();
            }
        }

        // Phase 2: Lock → batch delete expired sessions → unlock
        if !session_keys_to_delete.is_empty() {
            let mut bpf_guard = bpf.lock().unwrap();
            if let Ok(mut session_map) = bpf_guard.session_map() {
                for key in &session_keys_to_delete {
                    let _ = session_map.remove(key);
                }
            }
        }

        // Phase 3: Lock → iterate whitelist_map → collect expired keys → unlock
        let whitelist_keys_to_delete: Vec<WhitelistKey>;
        {
            let mut bpf_guard = bpf.lock().unwrap();
            if let Ok(whitelist_map) = bpf_guard.whitelist_map() {
                whitelist_keys_to_delete = whitelist_map
                    .iter()
                    .filter_map(|result| {
                        if let Ok((key, value)) = result {
                            if value.expire_timestamp < self.current_timestamp {
                                return Some(key);
                            }
                        }
                        None
                    })
                    .collect();
            } else {
                whitelist_keys_to_delete = Vec::new();
            }
        }

        // Phase 4: Lock → batch delete expired whitelist entries → unlock
        if !whitelist_keys_to_delete.is_empty() {
            let mut bpf_guard = bpf.lock().unwrap();
            if let Ok(mut whitelist_map) = bpf_guard.whitelist_map() {
                for key in &whitelist_keys_to_delete {
                    let _ = whitelist_map.remove(key);
                }
            }
        }

        Ok(stats)
    }
}

#[derive(Default)]
struct SessionStats {
    session_count: u64,
    envelope_kbps_up: u64,
    envelope_kbps_down: u64,
}

