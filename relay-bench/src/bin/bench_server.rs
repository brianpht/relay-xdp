// bench_server - UDP game relay benchmark server.
//
// Listens for CLIENT_TO_SERVER packets from bench_client (via relay or direct),
// echoes the payload back as SERVER_TO_CLIENT to the session's relay_address.
//
// Architecture:
//   tokio runtime:
//     axum  POST /register_session - registers a session with ServerInner
//     stats task  1 Hz -> stdout JSON
//   std::thread (network):
//     ServerInner pump_commands + recv_from loop + echo
//
// IPC: Arc<Mutex<Server>> shared between tokio and network thread.
//
// Env vars:
//   BENCH_HTTP_PORT  (default: 18080) - axum listen port
//   BENCH_UDP_PORT   (default: 17777) - UDP listen port

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use serde::Deserialize;

use relay_sdk::address::Address;
use relay_sdk::constants::{MAX_PACKET_BYTES, SESSION_PRIVATE_KEY_BYTES};
use relay_sdk::crypto::hash_sha256;
use relay_sdk::route::stamp_packet;
use relay_sdk::server::{Server, ServerInner};

// ── Wire-format constants ─────────────────────────────────────────────────────

const RELAY_SERVER_PING_PACKET: u8 = 13;
const SERVER_PING_BYTES: usize = 66;
const PING_KEY_BYTES: usize = 32;

// ── HTTP request body ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterSessionBody {
    session_id: u64,
    session_version: u8,
    /// Hex-encoded 32-byte session private key.
    session_private_key_hex: String,
    /// Address bench_server uses as relay_address - where SERVER_TO_CLIENT is sent.
    /// In direct mode this is the bench_client UDP bind addr.
    /// In relay mode this is the relay's last-hop address.
    relay_address: String,
    // ── Relay mode ping params (optional - only set in relay mode) ────────
    /// Hex-encoded 32B ping_key from relay-backend (bench_client forwards it).
    ping_key_hex: Option<String>,
    /// Hex-encoded 8B current_magic for pittle/chonkle stamping.
    current_magic_hex: Option<String>,
    /// "IP:PORT" - bench_server's externally visible UDP address. Required so
    /// PingTokenData.source_address matches the saddr the relay sees post-NAT.
    server_public_address: Option<String>,
}

// ── SERVER_PING construction (66 bytes) ───────────────────────────────────────
//
// Wire layout (matches relay-xdp-ebpf::handle_server_ping):
//   [0]      packet type = 13 (RELAY_SERVER_PING_PACKET)
//   [1..18]  pittle/chonkle DDoS filter bytes
//   [18..26] echo (8B)
//   [26..34] expire_timestamp (8B little-endian)
//   [34..66] SHA-256 token (32B) computed over PingTokenData
//
// Unlike CLIENT_PING, source_port = real UDP source port (no NAT workaround).
fn build_ping_token(
    ping_key: &[u8; PING_KEY_BYTES],
    expire_ts: u64,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port_be: u16,
    dst_port_be: u16,
) -> [u8; 32] {
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
fn build_server_ping_packet(
    ping_key: &[u8; PING_KEY_BYTES],
    expire_ts: u64,
    server_ip: [u8; 4],
    server_port_be: u16,
    relay_ip: [u8; 4],
    relay_port_be: u16,
    magic: &[u8; 8],
) -> [u8; SERVER_PING_BYTES] {
    let token = build_ping_token(
        ping_key,
        expire_ts,
        server_ip,
        relay_ip,
        server_port_be,
        relay_port_be,
    );
    let mut buf = [0u8; SERVER_PING_BYTES];
    buf[0] = RELAY_SERVER_PING_PACKET;
    // bytes [18..26] echo - leave zero
    buf[26..34].copy_from_slice(&expire_ts.to_le_bytes());
    buf[34..66].copy_from_slice(&token);
    stamp_packet(&mut buf, magic, &server_ip, &relay_ip);
    buf
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Pinger state shared between HTTP handler (writes) and network thread (reads).
struct ServerPingerState {
    relay_addr: SocketAddr,
    ping_key: [u8; PING_KEY_BYTES],
    server_ip: [u8; 4],
    server_port_be: u16,
    relay_ip: [u8; 4],
    relay_port_be: u16,
    magic: [u8; 8],
}

// ── Shared axum state ─────────────────────────────────────────────────────────

struct BenchState {
    server: Arc<Mutex<Server>>,
    /// Populated by register_session in relay mode. Read by network_thread on a
    /// timer to send periodic SERVER_PING packets to the relay.
    pinger: Arc<Mutex<Option<ServerPingerState>>>,
}

// ── HTTP handler ──────────────────────────────────────────────────────────────

async fn register_session_handler(
    State(state): State<Arc<BenchState>>,
    Json(body): Json<RegisterSessionBody>,
) -> impl IntoResponse {
    let key_bytes = match hex::decode(&body.session_private_key_hex) {
        Ok(b) if b.len() == SESSION_PRIVATE_KEY_BYTES => {
            let mut arr = [0u8; SESSION_PRIVATE_KEY_BYTES];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => {
            log::warn!(
                "register_session: bad key length {} (expected {})",
                b.len(),
                SESSION_PRIVATE_KEY_BYTES
            );
            return (
                StatusCode::BAD_REQUEST,
                "invalid session_private_key_hex length",
            )
                .into_response();
        }
        Err(e) => {
            log::warn!("register_session: hex decode error: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                "invalid session_private_key_hex hex",
            )
                .into_response();
        }
    };

    let relay_addr: Address = match body.relay_address.parse() {
        Ok(a) => a,
        Err(e) => {
            log::warn!(
                "register_session: bad relay_address '{}': {}",
                body.relay_address,
                e
            );
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid relay_address: {}", e),
            )
                .into_response();
        }
    };

    {
        let mut srv = state.server.lock().unwrap();
        srv.register_session(body.session_id, body.session_version, key_bytes, relay_addr);
    }

    // If relay-mode ping params were supplied, install pinger state so the
    // network thread starts sending SERVER_PING. Required for the relay to
    // whitelist this bench_server's IP:port (otherwise relay drops every
    // forwarded ROUTE_REQUEST and CLIENT_TO_SERVER targeting us).
    if let (Some(pk_hex), Some(magic_hex), Some(server_pub)) = (
        body.ping_key_hex.as_deref(),
        body.current_magic_hex.as_deref(),
        body.server_public_address.as_deref(),
    ) {
        match install_pinger(
            &state.pinger,
            pk_hex,
            magic_hex,
            server_pub,
            &body.relay_address,
        ) {
            Ok(()) => log::info!(
                "register_session: pinger installed (server_pub={} relay={})",
                server_pub,
                body.relay_address
            ),
            Err(e) => log::warn!("register_session: pinger install failed: {}", e),
        }
    }

    log::info!(
        "registered session {:016x} v={} relay={}",
        body.session_id,
        body.session_version,
        body.relay_address
    );

    (StatusCode::OK, "registered").into_response()
}

fn install_pinger(
    slot: &Arc<Mutex<Option<ServerPingerState>>>,
    ping_key_hex: &str,
    magic_hex: &str,
    server_public_address: &str,
    relay_address: &str,
) -> Result<()> {
    let ping_key_vec = hex::decode(ping_key_hex)?;
    if ping_key_vec.len() != PING_KEY_BYTES {
        anyhow::bail!("ping_key length");
    }
    let mut ping_key = [0u8; PING_KEY_BYTES];
    ping_key.copy_from_slice(&ping_key_vec);

    let magic_vec = hex::decode(magic_hex)?;
    if magic_vec.len() != 8 {
        anyhow::bail!("magic length");
    }
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&magic_vec);

    let server_sa: SocketAddr = server_public_address.parse()?;
    let server_ip = match server_sa.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => anyhow::bail!("server_public_address must be IPv4"),
    };
    let server_port_be = server_sa.port().to_be();

    let relay_sa: SocketAddr = relay_address.parse()?;
    let relay_ip = match relay_sa.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => anyhow::bail!("relay_address must be IPv4"),
    };
    let relay_port_be = relay_sa.port().to_be();

    *slot.lock().unwrap() = Some(ServerPingerState {
        relay_addr: relay_sa,
        ping_key,
        server_ip,
        server_port_be,
        relay_ip,
        relay_port_be,
        magic,
    });
    Ok(())
}

// ── Network thread ────────────────────────────────────────────────────────────

fn network_thread(
    mut inner: ServerInner,
    server_arc: Arc<Mutex<Server>>,
    pkt_recv: Arc<AtomicU64>,
    pkt_sent: Arc<AtomicU64>,
    udp_port: u16,
    shutdown: Arc<AtomicBool>,
    pinger: Arc<Mutex<Option<ServerPingerState>>>,
) {
    let sock = match UdpSocket::bind(format!("0.0.0.0:{}", udp_port)) {
        Ok(s) => s,
        Err(e) => {
            log::error!("bench_server: UDP bind 0.0.0.0:{} failed: {}", udp_port, e);
            return;
        }
    };
    sock.set_read_timeout(Some(Duration::from_millis(1)))
        .expect("set_read_timeout");

    log::info!("bench_server: UDP listening on :{}", udp_port);

    let mut recv_buf = [0u8; MAX_PACKET_BYTES];
    let mut last_ping = Instant::now() - Duration::from_secs(60);
    let ping_interval = Duration::from_secs(3);

    while !shutdown.load(Ordering::Relaxed) {
        // 1. Drain pending commands (RegisterSession, Open, etc.)
        inner.pump_commands();

        // 1b. Periodic SERVER_PING refresh. Required so the relay's whitelist
        //     map keeps an entry for our IP:port. Without it the relay drops
        //     every forwarded ROUTE_REQUEST / CLIENT_TO_SERVER destined here.
        //     The ping_key snapshot may go stale (rotates every 10s on backend)
        //     but that just causes ping verification to fail silently after a
        //     while - the bench_client refreshes the session well before then.
        if last_ping.elapsed() >= ping_interval {
            if let Some(p) = pinger.lock().unwrap().as_ref() {
                let expire_ts = unix_now_secs() + 120;
                let pkt = build_server_ping_packet(
                    &p.ping_key,
                    expire_ts,
                    p.server_ip,
                    p.server_port_be,
                    p.relay_ip,
                    p.relay_port_be,
                    &p.magic,
                );
                if let Err(e) = sock.send_to(&pkt, p.relay_addr) {
                    log::warn!("bench_server: SERVER_PING send failed: {}", e);
                } else {
                    log::debug!("bench_server: sent SERVER_PING to {}", p.relay_addr);
                }
            }
            last_ping = Instant::now();
        }

        // 2. Receive a packet.
        let (n, from) = match sock.recv_from(&mut recv_buf) {
            Ok(r) => r,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => {
                log::error!("bench_server: recv_from error: {}", e);
                continue;
            }
        };

        // 3. Process incoming: expects CLIENT_TO_SERVER.
        let Some((session_id, payload)) = inner.process_incoming(&recv_buf[..n]) else {
            continue;
        };
        pkt_recv.fetch_add(1, Ordering::Relaxed);

        // 4. Echo payload back to client via session's relay_address.
        //    from_address is used for pittle/chonkle stamping only.
        let from_addr = Address::from(from);
        {
            let mut srv = server_arc.lock().unwrap();
            srv.send_packet(session_id, &payload, [0u8; 8], from_addr);
        }

        // 5. Process the SendPacket command just queued.
        inner.pump_commands();

        // 6. Dispatch all SendRaw packets.
        loop {
            let outbound = { server_arc.lock().unwrap().pop_send_raw() };
            match outbound {
                Some((to, data)) => {
                    if let Some(to_addr) = Option::<std::net::SocketAddr>::from(to) {
                        if sock.send_to(&data, to_addr).is_ok() {
                            pkt_sent.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                None => break,
            }
        }
    }

    log::info!("bench_server: network thread exiting");
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let http_port: u16 = std::env::var("BENCH_HTTP_PORT")
        .unwrap_or_else(|_| "18080".into())
        .parse()
        .unwrap_or(18080);

    let udp_port: u16 = std::env::var("BENCH_UDP_PORT")
        .unwrap_or_else(|_| "17777".into())
        .parse()
        .unwrap_or(17777);

    log::info!(
        "bench_server starting (HTTP:{} UDP:{})",
        http_port,
        udp_port
    );

    // Create the ServerInner / Server pair.
    let (inner, server) = ServerInner::create();
    let server_arc = Arc::new(Mutex::new(server));

    // Open the server - command will be picked up by network thread.
    {
        let mut srv = server_arc.lock().unwrap();
        srv.open(Address::V4 {
            octets: [0, 0, 0, 0],
            port: udp_port,
        });
    }

    // Atomic counters visible to both network thread and stats task.
    let pkt_recv = Arc::new(AtomicU64::new(0));
    let pkt_sent = Arc::new(AtomicU64::new(0));
    let shutdown = Arc::new(AtomicBool::new(false));
    let pinger: Arc<Mutex<Option<ServerPingerState>>> = Arc::new(Mutex::new(None));

    // Spawn network thread.
    {
        let server_net = Arc::clone(&server_arc);
        let recv_net = Arc::clone(&pkt_recv);
        let sent_net = Arc::clone(&pkt_sent);
        let shutdown_net = Arc::clone(&shutdown);
        let pinger_net = Arc::clone(&pinger);
        std::thread::Builder::new()
            .name("bench_server_net".into())
            .spawn(move || {
                network_thread(
                    inner,
                    server_net,
                    recv_net,
                    sent_net,
                    udp_port,
                    shutdown_net,
                    pinger_net,
                )
            })
            .expect("failed to spawn network thread");
    }

    // Stats printer task: 1 Hz -> stdout JSON.
    {
        let pkt_recv_s = Arc::clone(&pkt_recv);
        let pkt_sent_s = Arc::clone(&pkt_sent);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let ts_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let recv = pkt_recv_s.swap(0, Ordering::Relaxed);
                let sent = pkt_sent_s.swap(0, Ordering::Relaxed);
                println!(
                    "{}",
                    serde_json::json!({
                        "ts_ms":    ts_ms,
                        "role":     "server",
                        "pkt_recv": recv,
                        "pkt_sent": sent,
                    })
                );
            }
        });
    }

    // Start axum server.
    let state = Arc::new(BenchState {
        server: Arc::clone(&server_arc),
        pinger: Arc::clone(&pinger),
    });
    let app = Router::new()
        .route("/register_session", post(register_session_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", http_port)).await?;
    log::info!("bench_server: HTTP listening on :{}", http_port);

    axum::serve(listener, app).await?;

    shutdown.store(true, Ordering::Relaxed);
    Ok(())
}
