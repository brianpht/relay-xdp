//! Ping thread — relay-to-relay pinging via UDP.
//! Port of `relay_ping.c`.

use anyhow::Result;
use relay_xdp_common::*;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::bpf::BpfContext;
use crate::config::Config;
use crate::encoding::Writer;
use crate::main_thread::{ControlMessage, MessageQueue, StatsMessage};
use crate::manager::RelayManager;
use crate::packet_filter;
use crate::platform;

/// SHA-256 hash using the `sha2` crate (pure Rust).
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hash.into()
}

pub struct PingThread {
    config: Arc<Config>,
    bpf: Option<Arc<Mutex<BpfContext>>>,
    control_queue: MessageQueue<ControlMessage>,
    stats_queue: MessageQueue<StatsMessage>,
    quit: Arc<AtomicBool>,
    socket: UdpSocket,
    manager: RelayManager,
    current_timestamp: u64,
    current_magic: [u8; 8],
    has_ping_key: bool,
    ping_key: [u8; RELAY_PING_KEY_BYTES],
    pings_sent: u64,
    bytes_sent: u64,
    ping_buf: Vec<u8>,
}

impl PingThread {
    pub fn new(
        config: Arc<Config>,
        bpf: Option<Arc<Mutex<BpfContext>>>,
        control_queue: MessageQueue<ControlMessage>,
        stats_queue: MessageQueue<StatsMessage>,
        quit: Arc<AtomicBool>,
    ) -> Result<Self> {
        let socket = platform::create_udp_socket(
            0, // INADDR_ANY
            config.relay_port,
            0.1, // 100ms timeout
            512 * 1024,
            512 * 1024,
        )?;

        Ok(Self {
            config,
            bpf,
            control_queue,
            stats_queue,
            quit,
            socket,
            manager: RelayManager::new(),
            current_timestamp: 0,
            current_magic: [0; 8],
            has_ping_key: false,
            ping_key: [0; RELAY_PING_KEY_BYTES],
            pings_sent: 0,
            bytes_sent: 0,
            ping_buf: Vec::with_capacity(256),
        })
    }

    pub fn run(&mut self) {
        log::info!("Starting ping thread");

        let mut packet_buf = [0u8; RELAY_MAX_PACKET_BYTES];
        let mut last_update_time = 0.0f64;
        let mut last_ping_stats_time = 0.0f64;

        while !self.quit.load(Ordering::Relaxed) {
            // Receive packets (blocking with 100ms timeout)
            if let Ok((bytes, addr)) = self.socket.recv_from(&mut packet_buf) {
                if let std::net::SocketAddr::V4(v4) = addr {
                    let from_address = u32::from_be_bytes(v4.ip().octets());
                    let from_port = v4.port();

                    // Process relay pong packets
                    if bytes == 18 + 8 && packet_buf[0] == RELAY_PONG_PACKET {
                        let r = &packet_buf[18..];
                        let sequence = u64::from_le_bytes(r[..8].try_into().unwrap());
                        self.manager.process_pong(from_address, from_port, sequence);
                    }
                }
            }

            let current_time = platform::time();

            // Run update logic ~100 times per second
            if last_update_time + 0.01 <= current_time {
                last_update_time = current_time;

                // Process control messages from main thread
                loop {
                    let msg = {
                        let mut queue = self.control_queue.lock().unwrap();
                        queue.pop_front()
                    };
                    match msg {
                        None => break,
                        Some(msg) => {
                            self.current_timestamp = msg.current_timestamp;
                            self.has_ping_key = true;
                            self.ping_key = msg.ping_key;
                            self.current_magic = msg.current_magic;

                            // Add/remove relays in BPF relay_map
                            if msg.new_relays.num_relays > 0 {
                                println!("-------------------------------------------------------");
                                if let Some(ref bpf) = self.bpf {
                                    let mut bpf_guard = bpf.lock().unwrap();
                                    if let Ok(mut relay_map) = bpf_guard.relay_map() {
                                        for i in 0..msg.new_relays.num_relays {
                                            let addr_be = msg.new_relays.address[i].to_be();
                                            let port_be = (msg.new_relays.port[i] as u32).to_be();
                                            let key = ((addr_be as u64) << 32) | (port_be as u64 & 0xFFFF);
                                            let _ = relay_map.insert(key, 1u64, 0);
                                        }
                                    }
                                }
                                for i in 0..msg.new_relays.num_relays {
                                    let a = msg.new_relays.address[i].to_be_bytes();
                                    println!(
                                        "new relay {}.{}.{}.{}:{}",
                                        a[0], a[1], a[2], a[3], msg.new_relays.port[i]
                                    );
                                }
                                println!("-------------------------------------------------------");
                            }

                            if msg.delete_relays.num_relays > 0 {
                                println!("-------------------------------------------------------");
                                if let Some(ref bpf) = self.bpf {
                                    let mut bpf_guard = bpf.lock().unwrap();
                                    if let Ok(mut relay_map) = bpf_guard.relay_map() {
                                        for i in 0..msg.delete_relays.num_relays {
                                            let addr_be = msg.delete_relays.address[i].to_be();
                                            let port_be = (msg.delete_relays.port[i] as u32).to_be();
                                            let key = ((addr_be as u64) << 32) | (port_be as u64 & 0xFFFF);
                                            let _ = relay_map.remove(&key);
                                        }
                                    }
                                }
                                for i in 0..msg.delete_relays.num_relays {
                                    let a = msg.delete_relays.address[i].to_be_bytes();
                                    println!(
                                        "delete relay {}.{}.{}.{}:{}",
                                        a[0], a[1], a[2], a[3], msg.delete_relays.port[i]
                                    );
                                }
                                println!("-------------------------------------------------------");
                            }

                            self.manager
                                .update(&msg.new_relays, &msg.delete_relays);
                        }
                    }
                }

                // Send ping packets
                if self.has_ping_key {
                    let expire_timestamp = self.current_timestamp + 30;

                    for i in 0..self.manager.num_relays {
                        if self.manager.relay_last_ping_time[i] + RELAY_PING_TIME <= current_time {
                            self.send_ping(i, expire_timestamp, current_time);
                        }
                    }
                }

                // Post ping stats to main thread (~10 times per second)
                if last_ping_stats_time + 0.1 <= current_time {
                    last_ping_stats_time = current_time;

                    let ping_stats = self.manager.get_ping_stats();
                    let msg = StatsMessage {
                        pings_sent: self.pings_sent,
                        bytes_sent: self.bytes_sent,
                        ping_stats,
                    };

                    let mut queue = self.stats_queue.lock().unwrap();
                    queue.push_back(msg);
                }
            }
        }

        log::info!("Ping thread exiting");
    }

    fn send_ping(&mut self, relay_index: usize, expire_timestamp: u64, current_time: f64) {
        let relay_addr = self.manager.relay_addresses[relay_index];
        let relay_port = self.manager.relay_ports[relay_index];
        let is_internal = self.manager.relay_internal[relay_index] != 0;

        // Build ping token data for SHA-256
        let source_addr = if is_internal {
            self.config.relay_internal_address
        } else {
            self.config.relay_public_address
        };

        let token_data = PingTokenData {
            ping_key: self.ping_key,
            expire_timestamp, // native byte order (C code does NOT use htonl here)
            source_address: source_addr.to_be(),
            source_port: self.config.relay_port.to_be(),
            dest_address: relay_addr.to_be(),
            dest_port: relay_port.to_be(),
        };

        // SHA-256 the token data
        let token_bytes =
            unsafe { std::slice::from_raw_parts(&token_data as *const _ as *const u8, std::mem::size_of::<PingTokenData>()) };
        let ping_token = sha256(token_bytes);

        // Build packet (reuse buffer to avoid per-ping heap allocation)
        self.ping_buf.clear();
        self.ping_buf.push(RELAY_PING_PACKET);

        // Placeholder for pittle (bytes 1-2) and chonkle (bytes 3-17)
        self.ping_buf.extend_from_slice(&[0u8; 17]);

        let mut w = Writer::new(&mut self.ping_buf);
        let sequence = self.manager.relay_ping_history[relay_index].ping_sent(current_time);
        w.write_uint64(sequence);
        w.write_uint64(expire_timestamp);
        w.write_uint8(if is_internal { 1 } else { 0 });
        w.write_bytes(&ping_token);

        let packet_length = self.ping_buf.len() as u16;

        // Generate pittle and chonkle
        let from_bytes = packet_filter::address_to_bytes(source_addr);
        let to_bytes = packet_filter::address_to_bytes(relay_addr);

        let pittle = packet_filter::generate_pittle(&from_bytes, &to_bytes, packet_length);
        let chonkle =
            packet_filter::generate_chonkle(&self.current_magic, &from_bytes, &to_bytes, packet_length);

        self.ping_buf[1] = pittle[0];
        self.ping_buf[2] = pittle[1];
        self.ping_buf[3..18].copy_from_slice(&chonkle);

        // Send via socket
        let dest = std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::from(relay_addr.to_be_bytes()),
            relay_port,
        );
        let _ = self.socket.send_to(&self.ping_buf, dest);

        self.manager.relay_last_ping_time[relay_index] = current_time;
        self.bytes_sent += (8 + 20 + 18 + 1 + 8 + 8 + RELAY_PING_TOKEN_BYTES) as u64;
        self.pings_sent += 1;
    }
}

