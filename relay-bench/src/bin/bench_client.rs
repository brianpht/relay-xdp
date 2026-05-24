// bench_client - UDP game relay benchmark client.
//
// Measures end-to-end RTT between bench_client and bench_server, optionally
// via a relay-xdp relay node.
//
// Modes:
//   direct          - bench_client <-> bench_server via loopback/LAN UDP (no relay)
//   relay           - bench_client -> relay-xdp -> bench_server (requires RELAY_ADDR)
//   server-backend  - full matchmaking via server-backend POST /sessions (requires
//                     SERVER_BACKEND_URL + SERVER_ID); relay chain auto-selected
//
// Architecture:
//   tokio runtime:
//     orchestrator  setup + route establishment (sequential)
//     load generator  tokio::time::interval at TARGET_PPS -> Command::SendPacket
//     stats printer   1 Hz -> stdout JSON
//     refresh task    every ROUTE_REFRESH_INTERVAL_SECS: re-fetch tokens,
//                     update pinger keys, re-register bench_server session,
//                     call route_update so SDK never hits CLIENT_ROUTE_TIMEOUT
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
//   RELAY_ADDR         (required in relay mode when RELAY_CHAIN is not set)
//   RELAY_CHAIN        (optional; comma-separated IP:PORT list for multi-hop;
//                       overrides RELAY_ADDR when set; e.g. "1.2.3.4:40000,5.6.7.8:40000")
//   TARGET_PPS         (default: 1000)
//   PAYLOAD_BYTES      (default: 128, minimum 8)
//   DURATION_SECS      (default: 30)
//   BENCH_MODE         (default: direct | relay | server-backend)
//
// Server-backend mode env vars:
//   SERVER_BACKEND_URL  (required) - e.g. "http://1.2.3.4:8180"
//   SERVER_ID           (required) - UUID of the registered game server
//   CLIENT_LAT          (optional) - decimal latitude; default 0.0
//   CLIENT_LNG          (optional) - decimal longitude; default 0.0

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream, UdpSocket};
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
use relay_sdk::crypto::{hash_sha256, XCHACHA_KEY_BYTES};
use relay_sdk::packets::{RouteResponsePacket, ROUTE_RESPONSE_BYTES};
use relay_sdk::route::{stamp_packet, write_header, HEADER_BYTES};
use relay_sdk::tokens::encrypt_route_token;
use relay_xdp_common::RouteToken;

// Wire-format constants for CLIENT_PING / SERVER_PING. Matches the eBPF
// data-plane parsers in relay-xdp-ebpf::handle_client_ping / handle_server_ping.
const RELAY_CLIENT_PING_PACKET: u8 = 9;
const CLIENT_PING_BYTES: usize = 74;
const PING_KEY_BYTES: usize = 32;
const PING_TOKEN_BYTES: usize = 32;

// How often the background task re-fetches /bench_token and issues a fresh
// UPDATE_TYPE_ROUTE. Must be < CLIENT_ROUTE_TIMEOUT (20s) to prevent the SDK
// route from expiring. SLICE_SECONDS = 10 in relay-sdk; we match it here so
// each refresh arrives well before the current route's expire_time runs out.
const ROUTE_REFRESH_INTERVAL_SECS: u64 = 10;

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
        /// Full relay chain (len >= 1). relay_chain[0] is the first hop.
        /// Populated from RELAY_CHAIN env var (comma-separated) when set,
        /// otherwise from RELAY_ADDR (single-hop backward compat).
        relay_chain: Vec<String>,
        backend_admin: String,
    },
    /// Use server-backend POST /sessions to create a session with automatic
    /// relay chain selection. bench_server receives the session via webhook
    /// POST /notify_session from server-backend directly - bench_client does
    /// NOT call /register_session. Route refresh via POST /sessions/{id}/refresh.
    ServerBackend {
        server_backend_url: String,
        /// UUID string of the registered game server (bench_server).
        server_id: String,
        client_lat: f64,
        client_lng: f64,
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
            // RELAY_CHAIN supersedes RELAY_ADDR when set.
            // RELAY_CHAIN = comma-separated "IP:PORT" list for multi-hop.
            // Falls back to single RELAY_ADDR for 1-hop backward compat.
            let relay_chain_env = std::env::var("RELAY_CHAIN").unwrap_or_default();
            let relay_chain: Vec<String> = if !relay_chain_env.is_empty() {
                relay_chain_env
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            } else {
                let relay_addr =
                    std::env::var("RELAY_ADDR").context("RELAY_ADDR required in relay mode")?;
                vec![relay_addr]
            };
            if relay_chain.is_empty() {
                bail!("RELAY_CHAIN is empty");
            }
            let backend_admin =
                std::env::var("BACKEND_ADMIN").unwrap_or_else(|_| "http://127.0.0.1:81".into());
            BenchMode::Relay {
                relay_chain,
                backend_admin,
            }
        }
        "server-backend" => {
            let server_backend_url = std::env::var("SERVER_BACKEND_URL")
                .context("SERVER_BACKEND_URL required in server-backend mode")?;
            let server_id =
                std::env::var("SERVER_ID").context("SERVER_ID required in server-backend mode")?;
            let client_lat: f64 = std::env::var("CLIENT_LAT")
                .unwrap_or_else(|_| "0.0".into())
                .parse()
                .unwrap_or(0.0);
            let client_lng: f64 = std::env::var("CLIENT_LNG")
                .unwrap_or_else(|_| "0.0".into())
                .parse()
                .unwrap_or(0.0);
            BenchMode::ServerBackend {
                server_backend_url,
                server_id,
                client_lat,
                client_lng,
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

// ── Hex decode helpers ────────────────────────────────────────────────────────

fn decode_hex_32(s: &str, name: &str) -> Result<[u8; 32]> {
    hex::decode(s)
        .with_context(|| format!("decode {} hex", name))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{}: expected 32 bytes", name))
}

fn decode_hex_8(s: &str, name: &str) -> Result<[u8; 8]> {
    hex::decode(s)
        .with_context(|| format!("decode {} hex", name))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{}: expected 8 bytes", name))
}

fn decode_hex_n(s: &str, name: &str, expected: usize) -> Result<Vec<u8>> {
    let v = hex::decode(s).with_context(|| format!("decode {} hex", name))?;
    if v.len() != expected {
        bail!("{}: expected {} bytes, got {}", name, expected, v.len());
    }
    Ok(v)
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
    #[allow(dead_code)]
    relay_backend_public_key: String,
    relay_address: String,
    current_magic: String,
    /// Hex-encoded 32B ping_key (rotates every 10s on the backend).
    /// Required to compute SHA-256 token for CLIENT_PING / SERVER_PING.
    ping_key: String,
    /// Caller's post-NAT public IPv4 (detected by backend via ConnectInfo).
    /// Used as PingTokenData.source_address in CLIENT_PING.
    client_public_address: String,
    /// Hex-encoded 111B Token[0] (client view): next_address = relay.
    /// SDK reads this locally to drive its first-hop send target.
    #[serde(default)]
    client_route_token: String,
    /// Hex-encoded 111B Token[1] (wire token): next_address = bench_server.
    /// What the relay actually decrypts off the wire.
    #[serde(default)]
    wire_route_token: String,
    /// Backwards-compatible single-token field (== client_route_token).
    #[serde(default)]
    #[allow(dead_code)]
    encrypted_route_token: String,
    /// Hex-encoded 32B per-relay XChaCha20-Poly1305 key. Required by
    /// RouteManager.begin_next_route to locally decrypt Token[0] (extracts
    /// session_id, session_private_key, next_address). Derived as
    /// BLAKE2b-512(X25519(backend_sk, relay_pk) || relay_pk || backend_pk)[..32].
    #[serde(default)]
    relay_secret_key: String,
    /// Multi-hop: N hex-encoded 111B wire tokens (one per relay in the chain).
    /// Token[i+1] is encrypted with relay[i]'s symmetric key.
    /// Empty in legacy 1-hop mode (use wire_route_token instead).
    #[serde(default)]
    relay_chain_tokens: Vec<String>,
}

// -- Server-backend session types ---------------------------------------------

/// Full session response from server-backend POST /sessions and
/// POST /sessions/{id}/refresh. Superset of BenchTokenResponse.
#[derive(Debug, Deserialize)]
struct SessionResponse {
    session_id: u64,
    session_version: u8,
    session_private_key: String,
    relay_secret_key: String,
    client_route_token: String,
    relay_chain_tokens: Vec<String>,
    /// Auto-selected relay chain: relay_chain[0] is the first hop.
    relay_chain: Vec<String>,
    /// Game server UDP address returned by server-backend.
    server_udp_addr: String,
    current_magic: String,
    ping_key: String,
    client_public_address: String,
}

/// Config shared with the server-backend route refresh tokio task.
struct ServerBackendRefreshConfig {
    server_backend_url: String,
    /// Session ID from initial POST /sessions; used as URL key for refresh.
    session_id: u64,
    client_lat: f64,
    client_lng: f64,
    client_udp_addr: String,
    keys: Arc<Mutex<PingerRefreshKeys>>,
}

// -- Server-backend HTTP helpers (blocking, run via spawn_blocking) -----------

/// POST /sessions to server-backend to create a new relay session.
/// server-backend selects the relay chain and calls the game server webhook
/// before returning tokens, so bench_client does not need to call
/// /register_session on bench_server.
async fn create_session_via_sb(
    sb_url: &str,
    server_id: &str,
    client_lat: f64,
    client_lng: f64,
) -> Result<SessionResponse> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/sessions", sb_url))
        .json(&serde_json::json!({
            "server_id": server_id,
            "client_lat": client_lat,
            "client_lng": client_lng,
        }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .with_context(|| format!("POST /sessions to {}", sb_url))?;

    if !resp.status().is_success() {
        bail!(
            "POST /sessions returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    let body = resp.text().await.context("read /sessions response body")?;
    serde_json::from_str(&body).with_context(|| format!("parse /sessions response: {}", body))
}

/// POST /sessions/{id}/refresh to server-backend to get fresh tokens.
/// server-backend calls the game server webhook automatically, so
/// bench_client does not call /register_session on bench_server.
/// Returns RefreshedRouteData (same type as do_refresh for relay mode).
///
/// Uses async reqwest::Client (not the blocking variant) because this function
/// is called directly from an async tokio task. Using reqwest::blocking inside
/// tokio::task::spawn_blocking causes repeated invocations to take 13+ seconds
/// (second runtime creation conflict) which exceeds CLIENT_ROUTE_TIMEOUT = 20s
/// and causes ROUTE_REQUEST_TIMEOUT to fire, permanently setting fallback_to_direct.
async fn do_refresh_via_sb(cfg: &ServerBackendRefreshConfig) -> Result<RefreshedRouteData> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/sessions/{}/refresh",
            cfg.server_backend_url, cfg.session_id
        ))
        .json(&serde_json::json!({
            "client_lat": cfg.client_lat,
            "client_lng": cfg.client_lng,
        }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .with_context(|| {
            format!(
                "POST /sessions/{}/refresh to {}",
                cfg.session_id, cfg.server_backend_url
            )
        })?;

    if !resp.status().is_success() {
        bail!(
            "POST /sessions/{}/refresh returned HTTP {}: {}",
            cfg.session_id,
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    let body = resp.text().await.context("read refresh response body")?;
    let tok: SessionResponse =
        serde_json::from_str(&body).with_context(|| format!("parse refresh response: {}", body))?;

    if tok.relay_secret_key.is_empty() || tok.client_route_token.is_empty() {
        bail!(
            "refresh: /sessions/{}/refresh missing relay token fields",
            cfg.session_id
        );
    }

    let session_private_key = decode_hex_32(&tok.session_private_key, "session_private_key")?;
    let ping_key = decode_hex_32(&tok.ping_key, "ping_key")?;
    let magic = decode_hex_8(&tok.current_magic, "current_magic")?;

    let client_route_token: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] = decode_hex_n(
        &tok.client_route_token,
        "client_route_token",
        ENCRYPTED_ROUTE_TOKEN_BYTES,
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("client_route_token: wrong length"))?;

    let relay_chain_tokens: Vec<[u8; ENCRYPTED_ROUTE_TOKEN_BYTES]> = {
        if tok.relay_chain_tokens.is_empty() {
            bail!(
                "refresh: /sessions/{}/refresh returned empty relay_chain_tokens",
                cfg.session_id
            );
        }
        let mut v = Vec::with_capacity(tok.relay_chain_tokens.len());
        for (i, hex_str) in tok.relay_chain_tokens.iter().enumerate() {
            let bytes: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] = decode_hex_n(
                hex_str,
                &format!("relay_chain_tokens[{}]", i),
                ENCRYPTED_ROUTE_TOKEN_BYTES,
            )?
            .try_into()
            .map_err(|_| anyhow::anyhow!("relay_chain_tokens[{}]: wrong length", i))?;
            v.push(bytes);
        }
        v
    };

    Ok(RefreshedRouteData {
        session_id: tok.session_id,
        session_version: tok.session_version,
        session_private_key,
        client_route_token,
        relay_chain_tokens,
        ping_key,
        magic,
    })
}

fn fetch_bench_token(
    admin_url: &str,
    relay_chain: &[String],
    bench_server_addr: &str,
) -> Result<BenchTokenResponse> {
    let host_port = url_host_port(admin_url);
    // Both query values contain only digits/dots/colons - no encoding needed.
    let path = if relay_chain.len() > 1 {
        // Multi-hop: use relay_chain param (comma-separated).
        format!(
            "/bench_token?relay_chain={}&bench_server_addr={}",
            relay_chain.join(","),
            bench_server_addr
        )
    } else {
        // Single-hop: use relay_addr param for backward compat with older backends.
        format!(
            "/bench_token?relay_addr={}&bench_server_addr={}",
            relay_chain[0], bench_server_addr
        )
    };
    let body = http_get_body(host_port, &path)
        .with_context(|| format!("GET /bench_token from {}", admin_url))?;
    serde_json::from_str(&body).with_context(|| format!("parse /bench_token response: {}", body))
}

// ── RTT stats ─────────────────────────────────────────────────────────────────
//
// Implementation: Vec<u64> drain + sort_unstable each 1 Hz tick.
//
// Capacity analysis (evaluated 2026-05-09):
//   TARGET_PPS  | samples/tick | sort time (est) | heap/tick | verdict
//   -----------   -----------   ----------------   ---------   -------
//   1 000       | 1 K          | ~0.02 ms        | 8 KB      | ok
//   10 000      | 10 K         | ~0.3 ms         | 80 KB     | ok
//   50 000      | 50 K         | ~1.7 ms         | 400 KB    | borderline
//   100 000     | 100 K        | ~3.5 ms         | 800 KB    | replace
//
// If TARGET_PPS ever exceeds ~50 K, replace Vec<u64> sort with the
// `hdrhistogram` crate: O(1) record time, O(1) percentile reads,
// fixed ~120 KB memory.  Default TARGET_PPS is 1 000, so no change needed.

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

/// Ping keys that rotate during a long run. Both the network thread (reads)
/// and the route refresh task (writes) share this struct via Arc<Mutex<>>.
/// The lock is held only for the duration of the copy - never while doing I/O.
struct PingerRefreshKeys {
    ping_key: [u8; PING_KEY_BYTES],
    magic: [u8; 8],
}

/// Pinger state passed to network_thread. When `Some`, the network thread
/// rebuilds + sends a CLIENT_PING every `interval` seconds using the bound
/// UDP socket. Required so the relay's whitelist_map keeps an entry for the
/// bench_client IP:port (otherwise eBPF drops every non-ping packet from us).
struct PingerState {
    relay_addr: std::net::SocketAddr,
    session_id: u64,
    client_ip: [u8; 4],
    relay_ip: [u8; 4],
    relay_port_be: u16,
    interval: Duration,
    /// Refreshed every ROUTE_REFRESH_INTERVAL_SECS by the background task.
    /// Network thread reads under the lock only when building a CLIENT_PING.
    keys: Arc<Mutex<PingerRefreshKeys>>,
}

impl PingerState {
    fn build_packet(&self, expire_ts: u64) -> [u8; CLIENT_PING_BYTES] {
        let k = self.keys.lock().unwrap();
        build_client_ping_packet(
            &k.ping_key,
            self.session_id,
            expire_ts,
            self.client_ip,
            self.relay_ip,
            self.relay_port_be,
            &k.magic,
        )
    }
}

/// Config shared with the background route refresh tokio task.
/// Wrapped in Arc so it can be moved into the async closure cheaply.
struct RouteRefreshConfig {
    /// relay-backend admin URL (e.g. "http://1.2.3.4:8091")
    admin_url: String,
    /// Full relay chain (len >= 1). [0] is the first hop.
    relay_chain: Vec<String>,
    /// bench_server HTTP address "IP:PORT" for /register_session
    bench_server_http: String,
    /// bench_server UDP address "IP:PORT" for /bench_token + register_session
    bench_server_udp: String,
    /// bench_client UDP bind address - used as client_ext in route_update
    client_udp_addr: String,
    /// Shared with PingerState in network_thread. Refresh task writes here;
    /// network thread reads when building CLIENT_PING.
    keys: Arc<Mutex<PingerRefreshKeys>>,
}

/// Data returned by a single successful route refresh cycle.
struct RefreshedRouteData {
    session_id: u64,
    #[allow(dead_code)]
    session_version: u8,
    #[allow(dead_code)]
    session_private_key: [u8; SESSION_PRIVATE_KEY_BYTES],
    client_route_token: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES],
    /// Wire tokens for each relay hop. len == relay_chain.len().
    /// Token[i+1] is relay_chain_tokens[i] (encrypted with relay[i]'s key).
    relay_chain_tokens: Vec<[u8; ENCRYPTED_ROUTE_TOKEN_BYTES]>,
    ping_key: [u8; PING_KEY_BYTES],
    magic: [u8; 8],
}

/// Perform one route refresh cycle (blocking I/O - run via spawn_blocking):
///   1. GET /bench_token from relay-backend -> new session + tokens + ping_key
///   2. POST /register_session to bench_server with the new session
///
/// The caller is responsible for updating shared keys and calling route_update
/// on the Client after this returns.
fn do_refresh(cfg: &RouteRefreshConfig) -> Result<RefreshedRouteData> {
    let tok = fetch_bench_token(&cfg.admin_url, &cfg.relay_chain, &cfg.bench_server_udp)
        .context("refresh: GET /bench_token")?;

    if tok.relay_secret_key.is_empty() || tok.client_route_token.is_empty() {
        bail!("refresh: /bench_token missing relay token fields");
    }

    let session_private_key = decode_hex_32(&tok.session_private_key, "session_private_key")?;
    let ping_key = decode_hex_32(&tok.ping_key, "ping_key")?;
    let magic = decode_hex_8(&tok.current_magic, "current_magic")?;

    let client_route_token_vec = decode_hex_n(
        &tok.client_route_token,
        "client_route_token",
        ENCRYPTED_ROUTE_TOKEN_BYTES,
    )?;
    let client_route_token: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] =
        client_route_token_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("client_route_token: wrong length"))?;

    // Normalize relay_chain_tokens from the response.
    // Multi-hop response: relay_chain_tokens has N entries (one per relay).
    // Legacy 1-hop response: relay_chain_tokens is empty; use wire_route_token.
    let relay_chain_tokens: Vec<[u8; ENCRYPTED_ROUTE_TOKEN_BYTES]> =
        if !tok.relay_chain_tokens.is_empty() {
            let mut v = Vec::with_capacity(tok.relay_chain_tokens.len());
            for (i, hex) in tok.relay_chain_tokens.iter().enumerate() {
                let bytes: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] = decode_hex_n(
                    hex,
                    &format!("relay_chain_tokens[{}]", i),
                    ENCRYPTED_ROUTE_TOKEN_BYTES,
                )?
                .try_into()
                .map_err(|_| anyhow::anyhow!("relay_chain_tokens[{}]: wrong length", i))?;
                v.push(bytes);
            }
            v
        } else if !tok.wire_route_token.is_empty() {
            // Legacy 1-hop path: wire_route_token is Token[1].
            let bytes: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] = decode_hex_n(
                &tok.wire_route_token,
                "wire_route_token",
                ENCRYPTED_ROUTE_TOKEN_BYTES,
            )?
            .try_into()
            .map_err(|_| anyhow::anyhow!("wire_route_token: wrong length"))?;
            vec![bytes]
        } else {
            bail!("refresh: /bench_token missing both relay_chain_tokens and wire_route_token");
        };

    // Register the new session with bench_server so it can:
    //   - synthesise ROUTE_RESPONSE for the new ROUTE_REQUEST
    //   - accept CLIENT_TO_SERVER packets stamped with the new session_private_key
    //   - send updated SERVER_PING with fresh ping_key/magic
    // bench_server must ping the LAST relay in the chain - that is the relay
    // directly forwarding packets to bench_server. SERVER_PING from bench_server
    // populates the last relay's whitelist entry for bench_server's IP:port,
    // which allows the last relay to forward ROUTE_REQUEST to bench_server.
    // For single-hop this is identical to relay_chain[0].
    let server_relay = cfg
        .relay_chain
        .last()
        .expect("relay_chain is non-empty (validated at startup)");
    register_session(
        &cfg.bench_server_http,
        tok.session_id,
        tok.session_version,
        &session_private_key,
        server_relay,
        Some(&tok.ping_key),
        Some(&tok.current_magic),
        Some(&cfg.bench_server_udp),
    )
    .context("refresh: POST /register_session to bench_server")?;

    Ok(RefreshedRouteData {
        session_id: tok.session_id,
        session_version: tok.session_version,
        session_private_key,
        client_route_token,
        relay_chain_tokens,
        ping_key,
        magic,
    })
}

struct RelaySetup {
    session_id: u64,
    session_version: u8,
    session_private_key: [u8; SESSION_PRIVATE_KEY_BYTES],
    // Per-relay XChaCha20-Poly1305 symmetric key derived by the backend.
    // Always relay[0]'s key - used by RouteManager to decrypt Token[0].
    relay_secret_key: [u8; XCHACHA_KEY_BYTES],
    // Token[0] (client view): next_address = relay[0]. SDK uses this to send
    // CLIENT_TO_SERVER packets to the first relay.
    client_route_token: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES],
    // Wire tokens: relay_chain_tokens[i] = Token[i+1], encrypted with relay[i]'s key.
    // len == relay_chain.len() (one token per relay in the chain).
    relay_chain_tokens: Vec<[u8; ENCRYPTED_ROUTE_TOKEN_BYTES]>,
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
    // Parse relay addr (only used for logging here - next_address is already
    // baked into the backend-encrypted RouteToken).
    let _: std::net::SocketAddr = relay_addr
        .parse()
        .with_context(|| format!("parse relay addr: {}", relay_addr))?;

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

    // Tokens vec layout (N = rs.relay_chain_tokens.len()):
    //   Token[0]     = client_route_token (next = relay[0])     - decrypted locally
    //   Token[1..N]  = relay_chain_tokens                       - decrypted by relay[i]
    //   Token[N+1]   = zeros (terminator / trailing pad)
    //
    // Wire bytes sent by the SDK = tokens[111..] = Token[1..N+1].
    // Each relay strips its token via bpf_xdp_adjust_head and forwards the rest.
    let n = rs.relay_chain_tokens.len();
    let num_tokens = n + 2; // client_view(1) + wire_tokens(N) + zeros_pad(1)
    let mut tokens = Vec::with_capacity(ENCRYPTED_ROUTE_TOKEN_BYTES * num_tokens);
    tokens.extend_from_slice(&rs.client_route_token);
    for chain_tok in &rs.relay_chain_tokens {
        tokens.extend_from_slice(chain_tok);
    }
    tokens.extend_from_slice(&[0u8; ENCRYPTED_ROUTE_TOKEN_BYTES]);

    // client_secret_key = relay_secret_key so RouteManager.begin_next_route
    // can decrypt Token[0] to read session_id / session_private_key / next_address.
    client.open_session(server_sdk, rs.relay_secret_key);
    inner.pump_commands();

    // Deliver route update -> RouteManager enters pending state and pre-builds
    // the ROUTE_REQUEST packet (sent on first Tick in the network thread).
    client.route_update(UPDATE_TYPE_ROUTE, num_tokens, tokens, rs.magic, client_ext);
    inner.pump_commands();

    log::info!(
        "relay route pending: session={:016x} relay={} server={} hops={}",
        rs.session_id,
        relay_addr,
        server_udp_addr,
        n
    );
    let _ = rs.session_version; // silence unused field warnings
    let _ = rs.session_private_key;
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
    pinger: Option<PingerState>,
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

    // Send a burst of CLIENT_PINGs at startup so the relay populates the
    // whitelist before the SDK begins firing ROUTE_REQUEST. Without this the
    // relay drops every non-ping packet from this socket and ROUTE_RESPONSE
    // never arrives.
    if let Some(p) = pinger.as_ref() {
        for i in 0..3 {
            let expire_ts = unix_now_secs() + 120;
            let pkt = p.build_packet(expire_ts);
            match sock.send_to(&pkt, p.relay_addr) {
                Ok(_) => log::info!(
                    "bench_client: sent initial CLIENT_PING #{} to {}",
                    i + 1,
                    p.relay_addr
                ),
                Err(e) => log::warn!("bench_client: initial CLIENT_PING send failed: {}", e),
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    let mut recv_buf = [0u8; MAX_PACKET_BYTES];
    let mut last_tick = Instant::now();
    let mut last_ping = Instant::now();

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

        // 6. Periodic CLIENT_PING refresh. WHITELIST_TIMEOUT is 1000s but the
        //    backend's ping_key rotates every 10s, so we resend on a short
        //    interval to keep the relay's whitelist alive even if our ping_key
        //    snapshot is stale (in which case verification fails - acceptable
        //    once the initial ping has succeeded).
        if let Some(p) = pinger.as_ref() {
            if now.duration_since(last_ping) >= p.interval {
                let expire_ts = unix_now_secs() + 120;
                let pkt = p.build_packet(expire_ts);
                if let Err(e) = sock.send_to(&pkt, p.relay_addr) {
                    log::warn!("bench_client: periodic CLIENT_PING send failed: {}", e);
                }
                last_ping = now;
            }
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

// ── CLIENT_PING construction (74 bytes) ───────────────────────────────────────
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Wire layout (matches relay-xdp-ebpf::handle_client_ping):
//   [0]      packet type = 9 (RELAY_CLIENT_PING_PACKET)
//   [1..18]  pittle/chonkle DDoS filter bytes (filled by stamp_packet)
//   [18..26] echo (8B, arbitrary)
//   [26..34] session_id (8B little-endian)
//   [34..42] expire_timestamp (8B little-endian)
//   [42..74] SHA-256 token (32B) computed over PingTokenData
//
// PingTokenData (52B, repr(C, packed)) fed to SHA-256:
//   [0..32]  ping_key
//   [32..40] expire_timestamp (LE u64; comment in common says "native, not htonl")
//   [40..44] source_address (network byte order = client public IP octets)
//   [44..48] dest_address   (relay public IP octets)
//   [48..50] source_port    (BE u16; CLIENT_PING uses 0 - NAT workaround)
//   [50..52] dest_port      (BE u16; UDP destination port = relay port)
fn build_ping_token(
    ping_key: &[u8; PING_KEY_BYTES],
    expire_ts: u64,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port_be: u16, // network byte order; 0 for CLIENT_PING
    dst_port_be: u16, // network byte order
) -> [u8; PING_TOKEN_BYTES] {
    let mut td = [0u8; 52];
    td[0..32].copy_from_slice(ping_key);
    td[32..40].copy_from_slice(&expire_ts.to_le_bytes());
    td[40..44].copy_from_slice(&src_ip);
    td[44..48].copy_from_slice(&dst_ip);
    td[48..50].copy_from_slice(&src_port_be.to_le_bytes());
    td[50..52].copy_from_slice(&dst_port_be.to_le_bytes());
    hash_sha256(&td)
}

#[allow(clippy::too_many_arguments)]
fn build_client_ping_packet(
    ping_key: &[u8; PING_KEY_BYTES],
    session_id: u64,
    expire_ts: u64,
    client_ip: [u8; 4],
    relay_ip: [u8; 4],
    relay_port_be: u16,
    magic: &[u8; 8],
) -> [u8; CLIENT_PING_BYTES] {
    // Note: source_port = 0 (NAT workaround in eBPF).
    // dest_port = relay UDP destination port in network byte order.
    let token = build_ping_token(ping_key, expire_ts, client_ip, relay_ip, 0, relay_port_be);

    let mut buf = [0u8; CLIENT_PING_BYTES];
    buf[0] = RELAY_CLIENT_PING_PACKET;
    // bytes [1..18] filled by stamp_packet below
    // bytes [18..26] echo - leave zero
    buf[26..34].copy_from_slice(&session_id.to_le_bytes());
    buf[34..42].copy_from_slice(&expire_ts.to_le_bytes());
    buf[42..74].copy_from_slice(&token);

    stamp_packet(&mut buf, magic, &client_ip, &relay_ip);
    buf
}

// ── POST /register_session to bench_server ────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn register_session(
    bench_server_http: &str,
    session_id: u64,
    session_version: u8,
    session_private_key: &[u8; SESSION_PRIVATE_KEY_BYTES],
    relay_address: &str,
    // The following fields are populated only in relay mode; bench_server uses
    // them to send periodic SERVER_PING packets so the relay's whitelist_map
    // contains the bench_server's IP:port (required for ROUTE_REQUEST forwarding
    // and CLIENT_TO_SERVER redirection).
    ping_key_hex: Option<&str>,
    current_magic_hex: Option<&str>,
    server_public_address: Option<&str>, // "IP:PORT" - server's externally visible UDP addr
) -> Result<()> {
    let mut body = serde_json::json!({
        "session_id":              session_id,
        "session_version":         session_version,
        "session_private_key_hex": hex::encode(session_private_key),
        "relay_address":           relay_address,
    });
    if let (Some(pk), Some(mg), Some(sa)) = (ping_key_hex, current_magic_hex, server_public_address)
    {
        body["ping_key_hex"] = serde_json::Value::String(pk.to_string());
        body["current_magic_hex"] = serde_json::Value::String(mg.to_string());
        body["server_public_address"] = serde_json::Value::String(sa.to_string());
    }
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
        BenchMode::Relay { relay_chain, .. } => {
            if relay_chain.len() > 1 {
                "relay-multi-hop"
            } else {
                "relay"
            }
        }
        BenchMode::ServerBackend { .. } => "server-backend",
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

    // Pinger state - only set in relay mode. The network thread sends
    // CLIENT_PING packets at a steady cadence so the relay's whitelist_map
    // accepts our IP:port for ROUTE_REQUEST and CLIENT_TO_SERVER traffic.
    let mut pinger: Option<PingerState> = None;

    // Route refresh config - only set in relay mode. Used by the background
    // task that re-fetches /bench_token and calls route_update every
    // ROUTE_REFRESH_INTERVAL_SECS to keep CLIENT_ROUTE_TIMEOUT from firing.
    let mut refresh_cfg: Option<Arc<RouteRefreshConfig>> = None;

    // Server-backend refresh config - only set in server-backend mode.
    let mut sb_refresh_cfg: Option<Arc<ServerBackendRefreshConfig>> = None;

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
                None,
                None,
                None,
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
            relay_chain,
            backend_admin,
        } => {
            // relay_addr = first hop (relay-sdk connects to this as the initial relay).
            let relay_addr = &relay_chain[0];

            // server_relay = last hop (bench_server sends SERVER_PING here to keep
            // its IP:port whitelisted on the last relay so ROUTE_REQUEST can be
            // forwarded all the way through to bench_server).
            // For single-hop this equals relay_addr.
            let server_relay = relay_chain
                .last()
                .expect("relay_chain is non-empty (validated above)");

            // 1. Fetch bench_token from relay-backend admin. Backend now also
            //    derives the per-relay symmetric key and returns pre-encrypted
            //    111-byte RouteTokens (since bench_client cannot derive the keys).
            let tok = fetch_bench_token(backend_admin, relay_chain, &cfg.bench_server_udp)
                .context("GET /bench_token from relay-backend admin")?;

            log::info!(
                "bench_token: session_id={} version={} relay={} hops={}",
                tok.session_id,
                tok.session_version,
                tok.relay_address,
                relay_chain.len()
            );

            // 2. Decode hex fields from JSON response.
            let session_private_key =
                decode_hex_32(&tok.session_private_key, "session_private_key")?;

            if tok.relay_secret_key.is_empty() || tok.client_route_token.is_empty() {
                bail!(
                    "/bench_token did not return relay_secret_key + client_route_token. \
                     Backend likely could not look up the relay or derive its per-relay key. \
                     Check that {} is a known relay in relays.json on the backend.",
                    relay_addr
                );
            }

            let relay_secret_key = decode_hex_32(&tok.relay_secret_key, "relay_secret_key")?;

            let client_route_token: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] = decode_hex_n(
                &tok.client_route_token,
                "client_route_token",
                ENCRYPTED_ROUTE_TOKEN_BYTES,
            )?
            .try_into()
            .map_err(|_| anyhow::anyhow!("client_route_token: wrong length"))?;

            // Normalize wire tokens from the response.
            // Multi-hop: relay_chain_tokens has N entries (one per relay in chain).
            // Legacy 1-hop: relay_chain_tokens is empty; use wire_route_token.
            let relay_chain_tokens: Vec<[u8; ENCRYPTED_ROUTE_TOKEN_BYTES]> =
                if !tok.relay_chain_tokens.is_empty() {
                    let mut v = Vec::with_capacity(tok.relay_chain_tokens.len());
                    for (i, hex) in tok.relay_chain_tokens.iter().enumerate() {
                        let bytes: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] = decode_hex_n(
                            hex,
                            &format!("relay_chain_tokens[{}]", i),
                            ENCRYPTED_ROUTE_TOKEN_BYTES,
                        )?
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("relay_chain_tokens[{}]: wrong length", i))?;
                        v.push(bytes);
                    }
                    v
                } else if !tok.wire_route_token.is_empty() {
                    // Legacy 1-hop: wire_route_token is Token[1].
                    let bytes: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] = decode_hex_n(
                        &tok.wire_route_token,
                        "wire_route_token",
                        ENCRYPTED_ROUTE_TOKEN_BYTES,
                    )?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("wire_route_token: wrong length"))?;
                    vec![bytes]
                } else {
                    bail!(
                        "/bench_token missing both relay_chain_tokens and wire_route_token. \
                         Check that {} is a known relay in relays.json on the backend.",
                        relay_addr
                    );
                };

            let magic = decode_hex_8(&tok.current_magic, "current_magic")?;
            let ping_key = decode_hex_32(&tok.ping_key, "ping_key")?;

            // Parse client public IPv4 (returned by backend via ConnectInfo).
            // Used as PingTokenData.source_address - must match the saddr the
            // relay sees post-NAT, otherwise SHA-256 verification fails.
            let client_pub_octets: [u8; 4] = match tok.client_public_address.parse::<Ipv4Addr>() {
                Ok(v4) => v4.octets(),
                Err(e) => bail!(
                    "invalid client_public_address '{}': {}",
                    tok.client_public_address,
                    e
                ),
            };

            // Parse RELAY_ADDR (first hop) for relay IP / port octets.
            let relay_sa_for_ping: std::net::SocketAddr = relay_addr
                .parse()
                .with_context(|| format!("parse relay addr: {}", relay_addr))?;
            let relay_octets = match relay_sa_for_ping.ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                _ => bail!("bench only supports IPv4 relay addresses"),
            };
            let relay_port_be = relay_sa_for_ping.port().to_be();

            log::info!(
                "bench_client: client_public_address={} relay_addr={}",
                tok.client_public_address,
                relay_addr
            );

            // Shared refreshable keys - network thread reads, refresh task writes.
            let keys_arc: Arc<Mutex<PingerRefreshKeys>> =
                Arc::new(Mutex::new(PingerRefreshKeys { ping_key, magic }));

            pinger = Some(PingerState {
                relay_addr: relay_sa_for_ping,
                session_id: tok.session_id,
                client_ip: client_pub_octets,
                relay_ip: relay_octets,
                relay_port_be,
                interval: Duration::from_secs(3),
                keys: Arc::clone(&keys_arc),
            });

            // Store refresh config for the background task (spawned after
            // network thread).
            refresh_cfg = Some(Arc::new(RouteRefreshConfig {
                admin_url: backend_admin.clone(),
                relay_chain: relay_chain.clone(),
                bench_server_http: cfg.bench_server_http.clone(),
                bench_server_udp: cfg.bench_server_udp.clone(),
                client_udp_addr: cfg.bench_client_udp.clone(),
                keys: Arc::clone(&keys_arc),
            }));

            let rs = RelaySetup {
                session_id: tok.session_id,
                session_version: tok.session_version,
                session_private_key,
                relay_secret_key,
                client_route_token,
                relay_chain_tokens,
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

            // 4. Register session with bench_server. Pass ping_key + magic +
            //    server_relay (= last relay in chain) so bench_server sends
            //    SERVER_PING to the last relay, populating that relay's whitelist
            //    entry for bench_server's IP:port (otherwise the last relay drops
            //    ROUTE_REQUEST when forwarding to bench_server).
            register_session(
                &cfg.bench_server_http,
                tok.session_id,
                tok.session_version,
                &session_private_key,
                server_relay,
                Some(&tok.ping_key),
                Some(&tok.current_magic),
                Some(&cfg.bench_server_udp),
            )
            .context("register_session with bench_server")?;

            log::info!(
                "relay mode: session {:016x} registered, relay={} server_relay={} server={} hops={}",
                tok.session_id,
                relay_addr,
                server_relay,
                cfg.bench_server_http,
                relay_chain.len()
            );
            // route_active stays false; network thread sets it after receiving
            // ROUTE_RESPONSE from relay-xdp.
        }

        BenchMode::ServerBackend {
            server_backend_url,
            server_id,
            client_lat,
            client_lng,
        } => {
            // 1. Create session via server-backend.
            //    server-backend auto-selects the relay chain, mints tokens via
            //    relay-backend, and calls POST /notify_session on bench_server
            //    before returning - bench_client does NOT call /register_session.
            let tok =
                create_session_via_sb(server_backend_url, server_id, *client_lat, *client_lng)
                    .await
                    .context("POST /sessions to server-backend")?;

            log::info!(
                "server-backend session: session_id={} version={} relay={} hops={}",
                tok.session_id,
                tok.session_version,
                tok.relay_chain
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("(none)"),
                tok.relay_chain.len()
            );

            if tok.relay_chain.is_empty() {
                bail!("server-backend returned empty relay_chain");
            }
            if tok.relay_secret_key.is_empty() || tok.client_route_token.is_empty() {
                bail!("server-backend /sessions response missing relay token fields");
            }

            let relay_addr = &tok.relay_chain[0];

            // 2. Decode keys from SessionResponse.
            let session_private_key =
                decode_hex_32(&tok.session_private_key, "session_private_key")?;
            let relay_secret_key = decode_hex_32(&tok.relay_secret_key, "relay_secret_key")?;
            let magic = decode_hex_8(&tok.current_magic, "current_magic")?;
            let ping_key = decode_hex_32(&tok.ping_key, "ping_key")?;

            let client_route_token: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] = decode_hex_n(
                &tok.client_route_token,
                "client_route_token",
                ENCRYPTED_ROUTE_TOKEN_BYTES,
            )?
            .try_into()
            .map_err(|_| anyhow::anyhow!("client_route_token: wrong length"))?;

            let relay_chain_tokens: Vec<[u8; ENCRYPTED_ROUTE_TOKEN_BYTES]> = {
                if tok.relay_chain_tokens.is_empty() {
                    bail!("server-backend /sessions returned empty relay_chain_tokens");
                }
                let mut v = Vec::with_capacity(tok.relay_chain_tokens.len());
                for (i, hex_str) in tok.relay_chain_tokens.iter().enumerate() {
                    let bytes: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] = decode_hex_n(
                        hex_str,
                        &format!("relay_chain_tokens[{}]", i),
                        ENCRYPTED_ROUTE_TOKEN_BYTES,
                    )?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("relay_chain_tokens[{}]: wrong length", i))?;
                    v.push(bytes);
                }
                v
            };

            // 3. Parse client public IPv4.
            let client_pub_octets: [u8; 4] = match tok.client_public_address.parse::<Ipv4Addr>() {
                Ok(v4) => v4.octets(),
                Err(e) => bail!(
                    "invalid client_public_address '{}': {}",
                    tok.client_public_address,
                    e
                ),
            };

            // 4. Parse relay addr for pinger.
            let relay_sa_for_ping: std::net::SocketAddr = relay_addr
                .parse()
                .with_context(|| format!("parse relay addr: {}", relay_addr))?;
            let relay_octets = match relay_sa_for_ping.ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                _ => bail!("bench only supports IPv4 relay addresses"),
            };
            let relay_port_be = relay_sa_for_ping.port().to_be();

            log::info!(
                "bench_client: client_public_address={} relay_addr={}",
                tok.client_public_address,
                relay_addr
            );

            // 5. Setup pinger (same as relay mode).
            let keys_arc: Arc<Mutex<PingerRefreshKeys>> =
                Arc::new(Mutex::new(PingerRefreshKeys { ping_key, magic }));

            pinger = Some(PingerState {
                relay_addr: relay_sa_for_ping,
                session_id: tok.session_id,
                client_ip: client_pub_octets,
                relay_ip: relay_octets,
                relay_port_be,
                interval: Duration::from_secs(3),
                keys: Arc::clone(&keys_arc),
            });

            // 6. Store server-backend refresh config.
            sb_refresh_cfg = Some(Arc::new(ServerBackendRefreshConfig {
                server_backend_url: server_backend_url.clone(),
                session_id: tok.session_id,
                client_lat: *client_lat,
                client_lng: *client_lng,
                client_udp_addr: cfg.bench_client_udp.clone(),
                keys: Arc::clone(&keys_arc),
            }));

            // 7. Setup relay route (same as relay mode).
            let rs = RelaySetup {
                session_id: tok.session_id,
                session_version: tok.session_version,
                session_private_key,
                relay_secret_key,
                client_route_token,
                relay_chain_tokens,
                magic,
            };

            setup_relay_route(
                &mut inner,
                &mut client_arc.lock().unwrap(),
                &rs,
                relay_addr,
                &tok.server_udp_addr,
                &cfg.bench_client_udp,
            )?;

            // DO NOT call register_session on bench_server - server-backend
            // already sent POST /notify_session as part of POST /sessions.

            log::info!(
                "server-backend mode: session {:016x} ready, relay={} server={} hops={}",
                tok.session_id,
                relay_addr,
                tok.server_udp_addr,
                tok.relay_chain.len()
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
        let pinger_net = pinger.take();
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
                    pinger_net,
                )
            })
            .expect("failed to spawn network thread");
    }

    // In relay / server-backend mode: wait for the network thread to receive a
    // real ROUTE_RESPONSE from relay-xdp before starting load generation.
    if matches!(
        cfg.mode,
        BenchMode::Relay { .. } | BenchMode::ServerBackend { .. }
    ) {
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

        // Spawn background route refresh task. Fires every ROUTE_REFRESH_INTERVAL_SECS,
        // skipping the first immediate tick (initial route was just confirmed above).
        //
        // Each iteration:
        //   1. Blocking: GET /bench_token -> new session + pre-encrypted tokens
        //   2. Blocking: POST /register_session to bench_server (new session)
        //   3. Async: update shared ping_key + magic (PingerRefreshKeys)
        //   4. Async: call route_update(UPDATE_TYPE_ROUTE) on Client
        //
        // The SDK's route_manager.update() resets last_route_update_time (preventing
        // FLAGS_ROUTE_TIMED_OUT at CLIENT_ROUTE_TIMEOUT=20s). When the relay's
        // ROUTE_RESPONSE arrives, confirm_pending_route extends current_route_expire_time
        // by 2*SLICE_SECONDS=20s, keeping the route alive indefinitely.
        if let Some(rf) = refresh_cfg {
            let refresh_client = Arc::clone(&client_arc);
            let refresh_shutdown = Arc::clone(&shutdown);
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(Duration::from_secs(ROUTE_REFRESH_INTERVAL_SECS));
                // The interval fires immediately on first tick; skip it.
                interval.tick().await;

                while !refresh_shutdown.load(Ordering::Relaxed) {
                    interval.tick().await;
                    if refresh_shutdown.load(Ordering::Relaxed) {
                        break;
                    }

                    let rfc = Arc::clone(&rf);
                    let result = tokio::task::spawn_blocking(move || do_refresh(&rfc)).await;

                    let refreshed = match result {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) => {
                            log::warn!("bench_client: route refresh failed: {}", e);
                            continue;
                        }
                        Err(e) => {
                            log::warn!("bench_client: route refresh task panicked: {}", e);
                            continue;
                        }
                    };

                    // Update shared ping/magic keys used by the network thread
                    // when building periodic CLIENT_PING packets.
                    {
                        let mut keys = rf.keys.lock().unwrap();
                        keys.ping_key = refreshed.ping_key;
                        keys.magic = refreshed.magic;
                    }

                    // Build new token vec:
                    //   [Token[0] client view] + [Token[1..N] wire tokens] + [Token[N+1] zeros]
                    let n = refreshed.relay_chain_tokens.len();
                    let num_tokens = n + 2;
                    let mut tokens = Vec::with_capacity(ENCRYPTED_ROUTE_TOKEN_BYTES * num_tokens);
                    tokens.extend_from_slice(&refreshed.client_route_token);
                    for chain_tok in &refreshed.relay_chain_tokens {
                        tokens.extend_from_slice(chain_tok);
                    }
                    tokens.extend_from_slice(&[0u8; ENCRYPTED_ROUTE_TOKEN_BYTES]);

                    // Parse client_ext from the configured UDP bind address.
                    let client_ext = {
                        let sa: std::net::SocketAddr = rf
                            .client_udp_addr
                            .parse()
                            .unwrap_or_else(|_| "127.0.0.1:17778".parse().unwrap());
                        Address::from(sa)
                    };

                    refresh_client.lock().unwrap().route_update(
                        UPDATE_TYPE_ROUTE,
                        num_tokens,
                        tokens,
                        refreshed.magic,
                        client_ext,
                    );

                    log::info!(
                        "bench_client: route refreshed: new_session={:016x} magic={}",
                        refreshed.session_id,
                        hex::encode(refreshed.magic),
                    );
                }
            });
        }

        // Server-backend refresh task: calls POST /sessions/{id}/refresh
        // every ROUTE_REFRESH_INTERVAL_SECS. server-backend calls the game
        // server webhook automatically on each refresh (no /register_session).
        //
        // Uses async reqwest::Client (not spawn_blocking + reqwest::blocking)
        // to avoid the 13+ second latency caused by repeated runtime creation
        // inside blocking threads when the outer tokio runtime is active.
        if let Some(sbrf) = sb_refresh_cfg {
            let refresh_client = Arc::clone(&client_arc);
            let refresh_shutdown = Arc::clone(&shutdown);
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(Duration::from_secs(ROUTE_REFRESH_INTERVAL_SECS));
                // Skip first immediate tick - initial route is already confirmed.
                interval.tick().await;

                while !refresh_shutdown.load(Ordering::Relaxed) {
                    interval.tick().await;
                    if refresh_shutdown.load(Ordering::Relaxed) {
                        break;
                    }

                    let refreshed = match do_refresh_via_sb(&sbrf).await {
                        Ok(r) => r,
                        Err(e) => {
                            log::warn!("bench_client: server-backend route refresh failed: {}", e);
                            continue;
                        }
                    };

                    // Update shared ping/magic keys used by the network thread.
                    {
                        let mut keys = sbrf.keys.lock().unwrap();
                        keys.ping_key = refreshed.ping_key;
                        keys.magic = refreshed.magic;
                    }

                    // Build new token vec (same layout as relay mode).
                    let n = refreshed.relay_chain_tokens.len();
                    let num_tokens = n + 2;
                    let mut tokens = Vec::with_capacity(ENCRYPTED_ROUTE_TOKEN_BYTES * num_tokens);
                    tokens.extend_from_slice(&refreshed.client_route_token);
                    for chain_tok in &refreshed.relay_chain_tokens {
                        tokens.extend_from_slice(chain_tok);
                    }
                    tokens.extend_from_slice(&[0u8; ENCRYPTED_ROUTE_TOKEN_BYTES]);

                    let client_ext = {
                        let sa: std::net::SocketAddr = sbrf
                            .client_udp_addr
                            .parse()
                            .unwrap_or_else(|_| "127.0.0.1:17778".parse().unwrap());
                        Address::from(sa)
                    };

                    refresh_client.lock().unwrap().route_update(
                        UPDATE_TYPE_ROUTE,
                        num_tokens,
                        tokens,
                        refreshed.magic,
                        client_ext,
                    );

                    log::info!(
                        "bench_client: server-backend route refreshed: \
                         new_session={:016x} magic={}",
                        refreshed.session_id,
                        hex::encode(refreshed.magic),
                    );
                }
            });
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

// -- Tests --------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Global mutex - read_config() touches process-wide env vars, so the tests
    // below must not run in parallel.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_bench_env() {
        for k in [
            "BENCH_MODE",
            "SERVER_BACKEND_URL",
            "SERVER_ID",
            "CLIENT_LAT",
            "CLIENT_LNG",
            "RELAY_CHAIN",
            "RELAY_ADDR",
            "BACKEND_ADMIN",
            "BENCH_SERVER_HTTP",
            "BENCH_SERVER_UDP",
            "BENCH_CLIENT_UDP",
            "TARGET_PPS",
            "PAYLOAD_BYTES",
            "DURATION_SECS",
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn read_config_server_backend_mode_parses_required_env_vars() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_bench_env();
        std::env::set_var("BENCH_MODE", "server-backend");
        std::env::set_var("SERVER_BACKEND_URL", "http://127.0.0.1:8180");
        std::env::set_var("SERVER_ID", "11111111-2222-3333-4444-555555555555");
        std::env::set_var("CLIENT_LAT", "37.7749");
        std::env::set_var("CLIENT_LNG", "-122.4194");

        let cfg = read_config().expect("read_config should succeed");
        match cfg.mode {
            BenchMode::ServerBackend {
                server_backend_url,
                server_id,
                client_lat,
                client_lng,
            } => {
                assert_eq!(server_backend_url, "http://127.0.0.1:8180");
                assert_eq!(server_id, "11111111-2222-3333-4444-555555555555");
                assert!((client_lat - 37.7749).abs() < 1e-9);
                assert!((client_lng - (-122.4194)).abs() < 1e-9);
            }
            _ => panic!("expected ServerBackend mode"),
        }
        clear_bench_env();
    }

    #[test]
    fn read_config_server_backend_mode_missing_url_errors() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_bench_env();
        std::env::set_var("BENCH_MODE", "server-backend");
        // Intentionally do not set SERVER_BACKEND_URL.
        std::env::set_var("SERVER_ID", "id");

        let err = match read_config() {
            Err(e) => e,
            Ok(_) => panic!("missing SERVER_BACKEND_URL must error"),
        };
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("SERVER_BACKEND_URL"),
            "error must mention SERVER_BACKEND_URL: {}",
            msg
        );
        clear_bench_env();
    }

    #[test]
    fn read_config_server_backend_mode_missing_server_id_errors() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_bench_env();
        std::env::set_var("BENCH_MODE", "server-backend");
        std::env::set_var("SERVER_BACKEND_URL", "http://127.0.0.1:8180");
        // Intentionally do not set SERVER_ID.

        let err = match read_config() {
            Err(e) => e,
            Ok(_) => panic!("missing SERVER_ID must error"),
        };
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("SERVER_ID"),
            "error must mention SERVER_ID: {}",
            msg
        );
        clear_bench_env();
    }

    #[test]
    fn read_config_server_backend_mode_lat_lng_default_zero() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_bench_env();
        std::env::set_var("BENCH_MODE", "server-backend");
        std::env::set_var("SERVER_BACKEND_URL", "http://x:1");
        std::env::set_var("SERVER_ID", "s");
        // Omit CLIENT_LAT / CLIENT_LNG - should default to 0.0.

        let cfg = read_config().expect("read_config should succeed");
        match cfg.mode {
            BenchMode::ServerBackend {
                client_lat,
                client_lng,
                ..
            } => {
                assert_eq!(client_lat, 0.0);
                assert_eq!(client_lng, 0.0);
            }
            _ => panic!("expected ServerBackend mode"),
        }
        clear_bench_env();
    }

    #[test]
    fn read_config_unknown_mode_falls_back_to_direct() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_bench_env();
        std::env::set_var("BENCH_MODE", "totally-bogus");
        let cfg = read_config().expect("direct fallback should not error");
        assert!(matches!(cfg.mode, BenchMode::Direct));
        clear_bench_env();
    }
}
