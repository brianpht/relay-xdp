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
use serde::Deserialize;

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

// Extract the response body from a raw HTTP/1.0 response (after \r\n\r\n).
fn extract_http_body(raw: &str) -> &str {
    match raw.find("\r\n\r\n") {
        Some(pos) => &raw[pos + 4..],
        None => raw,
    }
}

fn http_get_body(host_port: &str, path: &str) -> Result<String> {
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host_port
    );
    let mut stream =
        TcpStream::connect(host_port).with_context(|| format!("connect {}", host_port))?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.write_all(req.as_bytes()).context("http GET write")?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).context("http GET read")?;
    Ok(extract_http_body(&raw).to_string())
}

// Parse the host:port from a URL like "http://1.2.3.4:81" or "1.2.3.4:81".
fn url_host_port(url: &str) -> &str {
    let stripped = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    match stripped.find('/') {
        Some(pos) => &stripped[..pos],
        None => stripped,
    }
}

// ── bench_token response from relay-backend GET /bench_token ─────────────────

// JSON response from relay-backend admin GET /bench_token?relay_addr=...
//
// Fields:
//   session_id               - u64 session identifier
//   session_version          - u8 monotonic version
//   session_private_key      - hex-encoded 32B; packed inside RouteToken and used
//                              to HMAC relay packet headers (CLIENT_TO_SERVER etc.)
//   relay_backend_public_key - hex-encoded 32B XChaCha20-Poly1305 key;
//                              used by bench_client to encrypt the RouteToken
//                              (relay eBPF decrypts with the same symmetric key)
//   relay_address            - "IP:PORT" echoed back (first-hop relay)
//   current_magic            - hex-encoded 8B DDoS filter epoch token
#[derive(Debug, Deserialize)]
struct BenchTokenResponse {
    session_id: u64,
    session_version: u8,
    session_private_key: String,
    relay_backend_public_key: String,
    relay_address: String,
    current_magic: String,
}

fn fetch_bench_token(admin_url: &str, relay_addr: &str) -> Result<BenchTokenResponse> {
    let host_port = url_host_port(admin_url);
    // IP:PORT in relay_addr contains only digits, dots, and colons - no encoding needed.
    let path = format!("/bench_token?relay_addr={}", relay_addr);
    let body = http_get_body(host_port, &path)
        .with_context(|| format!("GET /bench_token from {}", admin_url))?;
    serde_json::from_str(&body).with_context(|| format!("parse /bench_token response: {}", body))
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

// ── Relay-mode setup: build RouteToken + push route_update command ────────────

struct RelaySetup {
    session_id: u64,
    session_version: u8,
    // session_private_key goes inside the RouteToken; bench_server uses it to
    // verify CLIENT_TO_SERVER packet headers.
    session_private_key: [u8; SESSION_PRIVATE_KEY_BYTES],
    // relay_backend_pk is the symmetric XChaCha20-Poly1305 key shared between
    // relay-backend and relay-xdp. bench_client uses it to:
    //   (a) encrypt the RouteToken so relay eBPF can decrypt it via
    //       bpf_relay_xchacha20poly1305_decrypt
    //   (b) pass as client_secret_key to open_session so RouteManager can
    //       decrypt Token[0] client-side to read session_id/next_address
    relay_backend_pk: [u8; XCHACHA_KEY_BYTES],
    magic: [u8; 8],
}

/// Push open_session + route_update commands and pump once.
///
/// The RouteManager builds the ROUTE_REQUEST packet during begin_next_route
/// (triggered by pump_commands on the RouteUpdate command). The network thread
/// sends it to the relay on the first Tick cycle (~16 ms after start).
/// relay-xdp eBPF decrypts the RouteToken, creates a session_map entry, and
/// sends ROUTE_RESPONSE back. The network thread receives it and sets
/// route_active = true.
fn setup_relay_route(
    inner: &mut ClientInner,
    client: &mut Client,
    rs: &RelaySetup,
    relay_addr: &str,
    server_udp_addr: &str,
    client_udp_addr: &str,
) -> Result<()> {
    // Parse relay addr for RouteToken next_address + next_port.
    let relay_sa: std::net::SocketAddr = relay_addr
        .parse()
        .with_context(|| format!("parse relay addr: {}", relay_addr))?;
    let relay_ip = match relay_sa.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => bail!("bench only supports IPv4 relay addresses"),
    };
    let relay_port = relay_sa.port();

    // Server SDK address used as fallback direct destination if relay fails.
    let server_sa: std::net::SocketAddr = server_udp_addr
        .parse()
        .with_context(|| format!("parse bench_server UDP addr: {}", server_udp_addr))?;
    let server_sdk = Address::from(server_sa);

    // Client external address for pittle/chonkle source field in ROUTE_REQUEST.
    let client_ext_sa: std::net::SocketAddr = client_udp_addr
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:17778".parse().unwrap());
    let client_ext = Address::from(client_ext_sa);

    // Build RouteToken: next_address/next_port point at the relay (first hop).
    // next_address stored in network byte order (big-endian u32).
    let route_token = RouteToken {
        session_private_key: rs.session_private_key,
        expire_timestamp: 9_999_999_999u64,
        session_id: rs.session_id,
        envelope_kbps_up: 10_000,
        envelope_kbps_down: 10_000,
        next_address: u32::from_be_bytes(relay_ip).to_be(),
        prev_address: 0,
        next_port: relay_port.to_be(),
        prev_port: 0,
        session_version: rs.session_version,
        next_internal: 0,
        prev_internal: 0,
    };

    // Encrypt the RouteToken with relay_backend_pk. relay-xdp eBPF decrypts it
    // using bpf_relay_xchacha20poly1305_decrypt with the same key to create the
    // session_map entry.
    let enc_token = encrypt_route_token(&route_token, &rs.relay_backend_pk);

    // Tokens vec: [relay token (111B)] + [dummy server token (111B)].
    // num_tokens = 2 is required by ClientInner (begin_next_route rejects < 2).
    let mut tokens = Vec::with_capacity(ENCRYPTED_ROUTE_TOKEN_BYTES * 2);
    tokens.extend_from_slice(&enc_token);
    tokens.extend_from_slice(&[0u8; ENCRYPTED_ROUTE_TOKEN_BYTES]);

    // client_secret_key = relay_backend_pk so RouteManager.begin_next_route can
    // decrypt Token[0] to read session_id, session_private_key and next_address.
    client.open_session(server_sdk, rs.relay_backend_pk);
    inner.pump_commands();

    // Deliver route update -> RouteManager enters pending state and pre-builds
    // the ROUTE_REQUEST packet (sent on first Tick in the network thread).
    client.route_update(UPDATE_TYPE_ROUTE, 2, tokens, rs.magic, client_ext);
    inner.pump_commands();

    log::info!(
        "relay route pending: session={:016x} relay={} server={}",
        rs.session_id,
        relay_addr,
        server_udp_addr
    );
    Ok(())
}

// ── Network thread ────────────────────────────────────────────────────────────

// route_active is set to true by the network thread the first time the
// RouteManager reports a confirmed relay route (ROUTE_RESPONSE received and
// has_network_next_route() returns true). The main task polls this flag in
// relay mode before starting load generation.
#[allow(clippy::too_many_arguments)]
fn network_thread(
    mut inner: ClientInner,
    client_arc: Arc<Mutex<Client>>,
    pkt_sent: Arc<AtomicU64>,
    pkt_recv: Arc<AtomicU64>,
    rtt_data: Arc<Mutex<Vec<u64>>>,
    client_udp: String,
    shutdown: Arc<AtomicBool>,
    route_active: Arc<AtomicBool>,
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

        // 2. Detect when the relay route becomes active and publish the flag.
        if !route_active.load(Ordering::Relaxed) && inner.route_manager.has_network_next_route() {
            route_active.store(true, Ordering::Relaxed);
            log::info!("bench_client: route ACTIVE");
        }

        // 3. Dispatch all outbound packets via real UDP.
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

        // 4. Receive and process incoming packets.
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

        // 5. Tick every ~16 ms to drive route maintenance (ROUTE_REQUEST retries /
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

// ── Stats ─────────────────────────────────────────────────────────────────────

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

    // Create ClientInner / Client pair.
    let (mut inner, client) = ClientInner::create();
    let client_arc = Arc::new(Mutex::new(client));

    // route_active: set by network thread when has_network_next_route() goes true.
    // In direct mode it is pre-set to true (route confirmed before thread start).
    // In relay mode main waits on it with a 15 s timeout.
    let route_active = Arc::new(AtomicBool::new(false));

    match &cfg.mode {
        BenchMode::Direct => {
            // Generate session materials locally (no relay-backend needed).
            let session_id: u64 = rand::random();
            let session_version: u8 = 1;
            let mut session_private_key = [0u8; SESSION_PRIVATE_KEY_BYTES];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut session_private_key);
            let mut client_secret_key = [0u8; XCHACHA_KEY_BYTES];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_secret_key);
            let magic = [0u8; 8]; // magic not validated end-to-end in direct mode

            let ds = DirectSetup {
                session_id,
                session_version,
                session_private_key,
                client_secret_key,
                magic,
            };

            setup_direct_route(
                &mut inner,
                &mut client_arc.lock().unwrap(),
                &ds,
                &cfg.bench_server_udp,
            )?;

            // relay_address = bench_client UDP: bench_server echoes SERVER_TO_CLIENT
            // directly to the client (no relay hop in direct mode).
            register_session(
                &cfg.bench_server_http,
                session_id,
                session_version,
                &session_private_key,
                &cfg.bench_client_udp,
            )
            .context("register_session with bench_server")?;

            // Pre-confirm route_active - route is already established before the
            // network thread starts.
            route_active.store(true, Ordering::Relaxed);

            log::info!(
                "direct mode: session {:016x} registered, bench_server={}",
                session_id,
                cfg.bench_server_http
            );
        }

        BenchMode::Relay {
            relay_addr,
            backend_admin,
        } => {
            // 1. Fetch bench_token from relay-backend admin.
            //    bench_client is responsible for encrypting the RouteToken so that
            //    relay-xdp-common stays as a dev-dep in relay-backend.
            let tok = fetch_bench_token(backend_admin, relay_addr)
                .context("GET /bench_token from relay-backend admin")?;

            log::info!(
                "bench_token: session_id={} version={} relay={}",
                tok.session_id,
                tok.session_version,
                tok.relay_address
            );

            // 2. Decode hex fields from JSON response.
            let session_private_key: [u8; SESSION_PRIVATE_KEY_BYTES] =
                hex::decode(&tok.session_private_key)
                    .context("decode session_private_key hex")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("session_private_key: wrong length"))?;

            let relay_backend_pk: [u8; XCHACHA_KEY_BYTES] =
                hex::decode(&tok.relay_backend_public_key)
                    .context("decode relay_backend_public_key hex")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("relay_backend_public_key: wrong length"))?;

            let magic: [u8; 8] = hex::decode(&tok.current_magic)
                .context("decode current_magic hex")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("current_magic: wrong length"))?;

            let rs = RelaySetup {
                session_id: tok.session_id,
                session_version: tok.session_version,
                session_private_key,
                relay_backend_pk,
                magic,
            };

            // 3. Encrypt RouteToken + push open_session/route_update commands.
            //    ROUTE_REQUEST is pre-built; the network thread sends it on
            //    the first Tick (~16 ms after start).
            setup_relay_route(
                &mut inner,
                &mut client_arc.lock().unwrap(),
                &rs,
                relay_addr,
                &cfg.bench_server_udp,
                &cfg.bench_client_udp,
            )?;

            // 4. Register session with bench_server.
            //    relay_address = RELAY_ADDR so bench_server sends SERVER_TO_CLIENT
            //    to the relay, which forwards it back to the client.
            register_session(
                &cfg.bench_server_http,
                tok.session_id,
                tok.session_version,
                &session_private_key,
                relay_addr,
            )
            .context("register_session with bench_server")?;

            log::info!(
                "relay mode: session {:016x} registered, relay={} server={}",
                tok.session_id,
                relay_addr,
                cfg.bench_server_http
            );
            // route_active stays false; network thread sets it after receiving
            // ROUTE_RESPONSE from relay-xdp.
        }
    }

    // Shared counters.
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
        let route_active_net = Arc::clone(&route_active);
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
                    route_active_net,
                )
            })
            .expect("failed to spawn network thread");
    }

    // In relay mode: wait for the network thread to receive a real ROUTE_RESPONSE
    // from relay-xdp before starting load generation.
    if matches!(cfg.mode, BenchMode::Relay { .. }) {
        log::info!("relay mode: waiting for ROUTE_RESPONSE from relay-xdp (timeout 15s)...");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if route_active.load(Ordering::Relaxed) {
                log::info!("relay mode: ROUTE_RESPONSE received - route confirmed, starting load");
                break;
            }
            if Instant::now() > deadline {
                shutdown.store(true, Ordering::Relaxed);
                bail!(
                    "relay mode: timed out waiting for ROUTE_RESPONSE after 15s - \
                    check RELAY_ADDR and that relay-xdp is running with XDP attached"
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
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

    // Give the network thread a moment to drain.
    tokio::time::sleep(Duration::from_millis(100)).await;

    log::info!("bench_client done");
    Ok(())
}
