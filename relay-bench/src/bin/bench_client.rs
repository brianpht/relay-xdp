// bench_client - UDP game relay benchmark client.
//
// Measures end-to-end RTT between bench_client and bench_server, optionally
// via a relay-xdp relay node.
//
// Modes:
//   direct  - bench_client <-> bench_server via loopback/LAN UDP (no relay)
//   relay   - bench_client -> relay-xdp -> bench_server (requires RELAY_ADDR)
//
// Architecture:
//   tokio runtime:
//     orchestrator  setup + route establishment (sequential)
//     load generator  tokio::time::interval at TARGET_PPS -> Command::SendPacket
//     stats printer   1 Hz -> stdout JSON
//   std::thread (network):
//     ClientInner pump_commands + recv_from loop + RTT measurement
//
// Payload format (RTT measurement):
//   [0..8]  send_timestamp_us  u64 LE microseconds since UNIX_EPOCH
//   [8..]   zero padding to PAYLOAD_BYTES
//
// Env vars (see session doc for full table):
//   BENCH_SERVER_HTTP  (default: 127.0.0.1:18080)
//   BENCH_SERVER_UDP   (default: 127.0.0.1:17777)
//   BENCH_CLIENT_UDP   (default: 127.0.0.1:17778)
//   BACKEND_ADMIN      (default: http://127.0.0.1:81)
//   RELAY_ADDR         (required in relay mode)
//   TARGET_PPS         (default: 1000)
//   PAYLOAD_BYTES      (default: 128, minimum 8)
//   DURATION_SECS      (default: 30)
//   BENCH_MODE         (default: direct | relay)

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use relay_sdk::address::Address;
use relay_sdk::client::{Client, ClientInner};
use relay_sdk::constants::{
    ENCRYPTED_ROUTE_TOKEN_BYTES, MAX_PACKET_BYTES, PACKET_TYPE_ROUTE_RESPONSE,
    SESSION_PRIVATE_KEY_BYTES, UPDATE_TYPE_ROUTE,
};
use relay_sdk::crypto::XCHACHA_KEY_BYTES;
use relay_sdk::packets::{RouteResponsePacket, ROUTE_RESPONSE_BYTES};
use relay_sdk::route::{write_header, HEADER_BYTES};
use relay_sdk::tokens::encrypt_route_token;
use relay_xdp_common::RouteToken;

// ── Config ────────────────────────────────────────────────────────────────────

struct Config {
    bench_server_http: String,
    bench_server_udp: String,
    bench_client_udp: String,
    target_pps: u64,
    payload_bytes: usize,
    duration_secs: u64,
    mode: BenchMode,
}

enum BenchMode {
    Direct,
    // relay_addr and backend_admin are used in step 5 (relay mode implementation).
    #[allow(dead_code)]
    Relay {
        relay_addr: String,
        backend_admin: String,
    },
}

fn read_config() -> Result<Config> {
    let bench_server_http =
        std::env::var("BENCH_SERVER_HTTP").unwrap_or_else(|_| "127.0.0.1:18080".into());
    let bench_server_udp =
        std::env::var("BENCH_SERVER_UDP").unwrap_or_else(|_| "127.0.0.1:17777".into());
    let bench_client_udp =
        std::env::var("BENCH_CLIENT_UDP").unwrap_or_else(|_| "127.0.0.1:17778".into());
    let target_pps: u64 = std::env::var("TARGET_PPS")
        .unwrap_or_else(|_| "1000".into())
        .parse()
        .unwrap_or(1000)
        .max(1);
    let payload_bytes: usize = std::env::var("PAYLOAD_BYTES")
        .unwrap_or_else(|_| "128".into())
        .parse()
        .unwrap_or(128)
        .max(8);
    let duration_secs: u64 = std::env::var("DURATION_SECS")
        .unwrap_or_else(|_| "30".into())
        .parse()
        .unwrap_or(30)
        .max(1);
    let mode_str = std::env::var("BENCH_MODE").unwrap_or_else(|_| "direct".into());

    let mode = match mode_str.as_str() {
        "relay" => {
            let relay_addr =
                std::env::var("RELAY_ADDR").context("RELAY_ADDR required in relay mode")?;
            let backend_admin =
                std::env::var("BACKEND_ADMIN").unwrap_or_else(|_| "http://127.0.0.1:81".into());
            BenchMode::Relay {
                relay_addr,
                backend_admin,
            }
        }
        _ => BenchMode::Direct,
    };

    Ok(Config {
        bench_server_http,
        bench_server_udp,
        bench_client_udp,
        target_pps,
        payload_bytes,
        duration_secs,
        mode,
    })
}

// ── HTTP helpers (raw TCP - no external HTTP client dep) ──────────────────────

fn http_post_json(host_port: &str, path: &str, body: &str) -> Result<u16> {
    let req = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host_port, body.len(), body
    );
    let mut stream =
        TcpStream::connect(host_port).with_context(|| format!("connect {}", host_port))?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.write_all(req.as_bytes()).context("http write")?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).context("http read")?;
    let status = resp
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    Ok(status)
}

// ── RTT stats ─────────────────────────────────────────────────────────────────

fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 * pct) as usize).min(sorted.len() - 1);
    sorted[idx]
}

// ── Direct-mode setup: generate keys + RouteToken + simulate ROUTE_RESPONSE ──

struct DirectSetup {
    session_id: u64,
    session_version: u8,
    session_private_key: [u8; SESSION_PRIVATE_KEY_BYTES],
    client_secret_key: [u8; XCHACHA_KEY_BYTES],
    magic: [u8; 8],
}

/// Set up a ClientInner with a confirmed direct route (no real relay).
///
/// Pattern mirrors relay_sdk_smoke::run_udp_loopback (Group 4):
///   1. Encrypt RouteToken with client_secret_key (next_address = bench_server UDP)
///   2. Call client.route_update -> inner.pump_commands (puts route in pending state)
///   3. Drain the emitted ROUTE_REQUEST SendRaw (discard - no relay in direct mode)
///   4. Build a valid ROUTE_RESPONSE with correct HMAC -> inner.process_incoming
///   5. Verify route is active
fn setup_direct_route(
    inner: &mut ClientInner,
    client: &mut Client,
    ds: &DirectSetup,
    server_udp_addr: &str,
) -> Result<()> {
    // Parse server UDP addr -> octets + port for RouteToken.
    let server_sa: std::net::SocketAddr = server_udp_addr
        .parse()
        .with_context(|| format!("parse server UDP addr: {}", server_udp_addr))?;
    let server_ip = match server_sa.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => bail!("bench only supports IPv4 server addresses"),
    };
    let server_port = server_sa.port();

    // Client external address for pittle/chonkle source field.
    let client_ext_sa: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client_ext = Address::from(client_ext_sa);

    // Server SDK address (where relay packets are directed in direct mode).
    let server_sdk = Address::from(server_sa);

    // Build RouteToken: next_address/next_port are big-endian (network byte order).
    // u32::from_be_bytes(octets).to_be() stores octets as-is on LE machine.
    let route_token = RouteToken {
        session_private_key: ds.session_private_key,
        expire_timestamp: 9_999_999_999u64,
        session_id: ds.session_id,
        envelope_kbps_up: 10_000,
        envelope_kbps_down: 10_000,
        next_address: u32::from_be_bytes(server_ip).to_be(),
        prev_address: 0,
        next_port: server_port.to_be(),
        prev_port: 0,
        session_version: ds.session_version,
        next_internal: 0,
        prev_internal: 0,
    };

    let enc_token = encrypt_route_token(&route_token, &ds.client_secret_key);

    // Tokens vec: [client token (111B)] + [dummy server token (111B)].
    let mut tokens = Vec::with_capacity(ENCRYPTED_ROUTE_TOKEN_BYTES * 2);
    tokens.extend_from_slice(&enc_token);
    tokens.extend_from_slice(&[0u8; ENCRYPTED_ROUTE_TOKEN_BYTES]);

    // Open session pointing at bench_server.
    client.open_session(server_sdk, ds.client_secret_key);
    inner.pump_commands();

    // Deliver route update -> RouteManager goes to pending state + emits ROUTE_REQUEST.
    client.route_update(UPDATE_TYPE_ROUTE, 2, tokens, ds.magic, client_ext);
    inner.pump_commands();

    // Drain and discard the emitted ROUTE_REQUEST (no real relay in direct mode).
    client.drain_notify();
    while client.pop_send_raw().is_some() {}

    // Simulate ROUTE_RESPONSE to confirm the pending route.
    //   relay_header HMAC must match pending_route_private_key = session_private_key.
    let mut relay_hdr = [0u8; HEADER_BYTES];
    write_header(
        PACKET_TYPE_ROUTE_RESPONSE,
        0,
        ds.session_id,
        ds.session_version,
        &ds.session_private_key,
        &mut relay_hdr,
    );
    let rr_pkt = RouteResponsePacket {
        relay_header: relay_hdr,
    };
    let mut rr_buf = [0u8; ROUTE_RESPONSE_BYTES];
    rr_pkt
        .encode(&mut rr_buf)
        .context("encode ROUTE_RESPONSE")?;

    let _ = inner.process_incoming(&rr_buf);
    inner.pump_commands();
    client.drain_notify();
    while client.pop_send_raw().is_some() {} // discard any SendRaw from confirm

    if !inner.route_manager.has_network_next_route() {
        bail!("route not active after simulated ROUTE_RESPONSE - check session keys");
    }

    log::info!(
        "direct route confirmed: session={:016x} server={}",
        ds.session_id,
        server_udp_addr
    );
    Ok(())
}

// ── Network thread ────────────────────────────────────────────────────────────

fn network_thread(
    mut inner: ClientInner,
    client_arc: Arc<Mutex<Client>>,
    pkt_sent: Arc<AtomicU64>,
    pkt_recv: Arc<AtomicU64>,
    rtt_data: Arc<Mutex<Vec<u64>>>,
    client_udp: String,
    shutdown: Arc<AtomicBool>,
) {
    let sock = match UdpSocket::bind(&client_udp) {
        Ok(s) => s,
        Err(e) => {
            log::error!("bench_client: UDP bind {} failed: {}", client_udp, e);
            return;
        }
    };
    sock.set_read_timeout(Some(Duration::from_millis(1)))
        .expect("set_read_timeout");

    log::info!("bench_client: UDP listening on {}", client_udp);

    let mut recv_buf = [0u8; MAX_PACKET_BYTES];
    let mut last_tick = Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        // 1. Process queued commands (SendPacket, etc.) -> emit SendRaw notifies.
        inner.pump_commands();

        // 2. Dispatch all outbound packets via real UDP.
        loop {
            let outbound = { client_arc.lock().unwrap().pop_send_raw() };
            match outbound {
                Some((to, data)) => {
                    if let Some(addr) = Option::<std::net::SocketAddr>::from(to) {
                        if sock.send_to(&data, addr).is_ok() {
                            pkt_sent.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                None => break,
            }
        }

        // 3. Receive and process incoming packets.
        match sock.recv_from(&mut recv_buf) {
            Ok((n, _)) => {
                if let Some(payload) = inner.process_incoming(&recv_buf[..n]) {
                    if payload.len() >= 8 {
                        let ts_bytes: [u8; 8] = payload[0..8].try_into().unwrap();
                        let send_ts_us = u64::from_le_bytes(ts_bytes);
                        let now_us = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_micros() as u64;
                        let rtt_us = now_us.saturating_sub(send_ts_us);
                        rtt_data.lock().unwrap().push(rtt_us);
                    }
                    pkt_recv.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                log::error!("bench_client: recv_from error: {}", e);
            }
        }

        // 4. Tick every ~16 ms to drive route maintenance (continue requests /
        //    timeout checks). Must happen AFTER pop_send_raw to avoid
        //    drain_notify consuming pending SendRaw items.
        let now = Instant::now();
        if now.duration_since(last_tick) >= Duration::from_millis(16) {
            let dt = now.duration_since(last_tick).as_secs_f64();
            client_arc.lock().unwrap().tick(dt);
            last_tick = now;
        }
    }

    log::info!("bench_client: network thread exiting");
}

// ── Stats task ────────────────────────────────────────────────────────────────

fn print_stats(
    ts_ms: u64,
    mode: &str,
    pkt_sent: u64,
    pkt_recv: u64,
    rtt_samples: &mut Vec<u64>,
    route: &str,
) {
    rtt_samples.sort_unstable();
    let p50 = percentile(rtt_samples, 0.50);
    let p95 = percentile(rtt_samples, 0.95);
    let p99 = percentile(rtt_samples, 0.99);
    let loss_pct = if pkt_sent > 0 {
        100.0 * (1.0 - (pkt_recv as f64 / pkt_sent as f64))
    } else {
        0.0
    };
    println!(
        "{}",
        serde_json::json!({
            "ts_ms":       ts_ms,
            "role":        "client",
            "mode":        mode,
            "pkt_sent":    pkt_sent,
            "pkt_recv":    pkt_recv,
            "rtt_p50_us":  p50,
            "rtt_p95_us":  p95,
            "rtt_p99_us":  p99,
            "loss_pct":    loss_pct,
            "route":       route,
        })
    );
    rtt_samples.clear();
}

// ── POST /register_session to bench_server ────────────────────────────────────

fn register_session(
    bench_server_http: &str,
    session_id: u64,
    session_version: u8,
    session_private_key: &[u8; SESSION_PRIVATE_KEY_BYTES],
    relay_address: &str,
) -> Result<()> {
    let body = serde_json::json!({
        "session_id":              session_id,
        "session_version":         session_version,
        "session_private_key_hex": hex::encode(session_private_key),
        "relay_address":           relay_address,
    });
    let body_str = serde_json::to_string(&body)?;
    let status = http_post_json(bench_server_http, "/register_session", &body_str)?;
    if status != 200 {
        bail!("register_session returned status {}", status);
    }
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cfg = read_config()?;

    let mode_label = match &cfg.mode {
        BenchMode::Direct => "direct",
        BenchMode::Relay { .. } => "relay",
    };
    log::info!(
        "bench_client starting: mode={} pps={} payload={}B duration={}s",
        mode_label,
        cfg.target_pps,
        cfg.payload_bytes,
        cfg.duration_secs
    );

    // Generate session materials locally.
    let session_id: u64 = rand::random();
    let session_version: u8 = 1;
    let mut session_private_key = [0u8; SESSION_PRIVATE_KEY_BYTES];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut session_private_key);
    let mut client_secret_key = [0u8; XCHACHA_KEY_BYTES];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_secret_key);
    let magic = [0u8; 8]; // direct mode: magic is not validated end-to-end

    let ds = DirectSetup {
        session_id,
        session_version,
        session_private_key,
        client_secret_key,
        magic,
    };

    // Create ClientInner / Client pair.
    let (mut inner, client) = ClientInner::create();
    let client_arc = Arc::new(Mutex::new(client));

    match &cfg.mode {
        BenchMode::Direct => {
            // Setup route: use bench_server UDP addr as next_address.
            setup_direct_route(
                &mut inner,
                &mut client_arc.lock().unwrap(),
                &ds,
                &cfg.bench_server_udp,
            )?;

            // Register session with bench_server: relay_address = bench_client UDP bind.
            register_session(
                &cfg.bench_server_http,
                session_id,
                session_version,
                &session_private_key,
                &cfg.bench_client_udp,
            )
            .context("register_session with bench_server")?;

            log::info!(
                "direct mode: session {:016x} registered, bench_server={}",
                session_id,
                cfg.bench_server_http
            );
        }
        BenchMode::Relay { .. } => {
            bail!("relay mode is not implemented in step 4 - only direct mode supported");
        }
    }

    // Shared state.
    let pkt_sent = Arc::new(AtomicU64::new(0));
    let pkt_recv = Arc::new(AtomicU64::new(0));
    let rtt_data: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let shutdown = Arc::new(AtomicBool::new(false));

    // Spawn network thread.
    {
        let client_net = Arc::clone(&client_arc);
        let sent_net = Arc::clone(&pkt_sent);
        let recv_net = Arc::clone(&pkt_recv);
        let rtt_net = Arc::clone(&rtt_data);
        let shutdown_net = Arc::clone(&shutdown);
        let client_udp = cfg.bench_client_udp.clone();
        std::thread::Builder::new()
            .name("bench_client_net".into())
            .spawn(move || {
                network_thread(
                    inner,
                    client_net,
                    sent_net,
                    recv_net,
                    rtt_net,
                    client_udp,
                    shutdown_net,
                )
            })
            .expect("failed to spawn network thread");
    }

    // Load generator task: push SendPacket commands at TARGET_PPS.
    let load_shutdown = Arc::clone(&shutdown);
    let load_client = Arc::clone(&client_arc);
    let payload_bytes = cfg.payload_bytes;
    let interval_ns = 1_000_000_000u64 / cfg.target_pps;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_nanos(interval_ns));
        let mut payload = vec![0u8; payload_bytes];
        while !load_shutdown.load(Ordering::Relaxed) {
            interval.tick().await;
            let now_us = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64;
            payload[0..8].copy_from_slice(&now_us.to_le_bytes());
            load_client.lock().unwrap().send_packet(&payload);
        }
    });

    // Stats printer task: 1 Hz -> stdout JSON.
    let stats_shutdown = Arc::clone(&shutdown);
    let stats_sent = Arc::clone(&pkt_sent);
    let stats_recv = Arc::clone(&pkt_recv);
    let stats_rtt = Arc::clone(&rtt_data);
    let mode_label_owned = mode_label.to_string();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        while !stats_shutdown.load(Ordering::Relaxed) {
            interval.tick().await;
            let ts_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let sent = stats_sent.swap(0, Ordering::Relaxed);
            let recv = stats_recv.swap(0, Ordering::Relaxed);
            let mut samples = std::mem::take(&mut *stats_rtt.lock().unwrap());
            print_stats(ts_ms, &mode_label_owned, sent, recv, &mut samples, "active");
        }
    });

    // Run for DURATION_SECS then signal shutdown.
    tokio::time::sleep(Duration::from_secs(cfg.duration_secs)).await;

    shutdown.store(true, Ordering::Relaxed);

    // Give the network thread a moment to finish.
    tokio::time::sleep(Duration::from_millis(100)).await;

    log::info!("bench_client done");
    Ok(())
}
