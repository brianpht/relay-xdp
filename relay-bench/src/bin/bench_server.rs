// bench_server - UDP game relay benchmark server.
//
// Listens for CLIENT_TO_SERVER packets from bench_client (via relay or direct),
// echoes the payload back as SERVER_TO_CLIENT to the session's relay_address.
//
// Architecture:
//   tokio runtime:
//     axum  POST /register_session - registers a session with ServerInner (direct / relay mode)
//     axum  POST /notify_session   - webhook from server-backend (server-backend mode)
//     stats task  1 Hz -> stdout JSON
//   std::thread (network):
//     ServerInner pump_commands + recv_from loop + echo
//
// IPC: Arc<Mutex<Server>> shared between tokio and network thread.
//
// Env vars:
//   BENCH_HTTP_PORT       (default: 18080)   - axum listen port
//   BENCH_UDP_PORT        (default: 17777)   - UDP listen port
//   SERVER_PUBLIC_ADDR    (optional)         - "IP:PORT" server externally visible UDP addr;
//                                              used for pinger/responder in notify_session
//   SERVER_BACKEND_URL    (optional)         - base URL of server-backend; when set,
//                                              bench_server calls POST /servers at startup and
//                                              DELETE /servers/{id} on graceful shutdown
//   SERVER_LAT            (optional)         - decimal latitude for server-backend registration
//   SERVER_LNG            (optional)         - decimal longitude for server-backend registration
//   SERVER_CALLBACK_URL   (optional)         - base URL server-backend uses to call
//                                              /notify_session; defaults to
//                                              http://127.0.0.1:BENCH_HTTP_PORT
use anyhow::Result;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use relay_sdk::address::Address;
use relay_sdk::constants::{
    MAX_PACKET_BYTES, PACKET_TYPE_ROUTE_RESPONSE, SESSION_PRIVATE_KEY_BYTES,
};
use relay_sdk::crypto::hash_sha256;
use relay_sdk::route::{stamp_packet, write_header, HEADER_BYTES};
use relay_sdk::server::{Server, ServerInner};
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
// -- Wire-format constants ----------------------------------------------------
const RELAY_SERVER_PING_PACKET: u8 = 13;
const RELAY_ROUTE_REQUEST_PACKET: u8 = 1;
const SERVER_PING_BYTES: usize = 66;
/// ROUTE_RESPONSE: [type 1B][pittle 2B][chonkle 15B][RELAY_HEADER 25B] = 43B
const ROUTE_RESPONSE_BYTES: usize = 18 + HEADER_BYTES;
const PING_KEY_BYTES: usize = 32;
// -- HTTP request / response types --------------------------------------------
/// Body for POST /register_session (direct / relay mode - called by bench_client).
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
    // -- Relay mode ping params (optional - only set in relay mode) ----------
    /// Hex-encoded 32B ping_key from relay-backend (bench_client forwards it).
    ping_key_hex: Option<String>,
    /// Hex-encoded 8B current_magic for pittle/chonkle stamping.
    current_magic_hex: Option<String>,
    /// "IP:PORT" - bench_server's externally visible UDP address. Required so
    /// PingTokenData.source_address matches the saddr the relay sees post-NAT.
    server_public_address: Option<String>,
}
/// Webhook body posted by server-backend to POST /notify_session.
/// Mirrors server-backend::handlers::WebhookPayload (server-backend outgoing).
#[derive(Deserialize)]
struct NotifySessionBody {
    session_id: u64,
    session_version: u8,
    /// Hex-encoded 32B session private key.
    session_private_key_hex: String,
    /// First relay address in the chain ("IP:PORT").
    relay_address: String,
    /// Hex-encoded 32B ping_key.
    ping_key_hex: String,
    /// Hex-encoded 8B current_magic.
    current_magic_hex: String,
}
/// Request body for POST /servers - self-register bench_server with server-backend.
#[derive(Serialize)]
struct SbRegisterServerRequest {
    udp_addr: String,
    lat: f64,
    lng: f64,
    callback_url: String,
}
/// Response body from POST /servers.
#[derive(Deserialize)]
struct SbRegisterServerResponse {
    server_id: String,
}
// -- SERVER_PING construction (66 bytes) --------------------------------------
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
/// State required to synthesize a ROUTE_RESPONSE in reply to a relay-forwarded
/// ROUTE_REQUEST. Populated by /register_session in relay mode.
///
/// In the deployed bench topology nothing else generates ROUTE_RESPONSE: the
/// eBPF data plane only forwards ROUTE_REQUEST -> next_hop and forwards
/// ROUTE_RESPONSE in the reverse direction (it does not synthesize one). The
/// smoke test fakes ROUTE_RESPONSE in-process; here bench_server takes that
/// role so the relay's session_map entry can transition to "confirmed" and
/// CLIENT_TO_SERVER traffic starts flowing.
struct RouteResponderState {
    session_id: u64,
    session_version: u8,
    session_private_key: [u8; SESSION_PRIVATE_KEY_BYTES],
    server_ip: [u8; 4],
    magic: [u8; 8],
    /// Monotonic packet sequence per ROUTE_RESPONSE sent. The relay rejects
    /// any sequence <= session.special_server_to_client_sequence, so we
    /// strictly increment on every send. Starts at 1.
    next_sequence: u64,
}
// -- Shared axum state --------------------------------------------------------
struct BenchState {
    server: Arc<Mutex<Server>>,
    /// Populated by register_session in relay mode. Read by network_thread on a
    /// timer to send periodic SERVER_PING packets to the relay.
    pinger: Arc<Mutex<Option<ServerPingerState>>>,
    /// Populated by register_session in relay mode. Read by network_thread on
    /// every inbound ROUTE_REQUEST packet to synthesize a ROUTE_RESPONSE back
    /// to the relay (so the relay's session_map entry confirms).
    responder: Arc<Mutex<Option<RouteResponderState>>>,
    /// Server external UDP "IP:PORT" (SERVER_PUBLIC_ADDR env var).
    /// Used when installing pinger/responder from notify_session_handler so the
    /// relay can whitelist bench_server's public address for ROUTE_REQUEST
    /// forwarding. None if SERVER_PUBLIC_ADDR was not set at startup.
    server_public_addr: Option<String>,
}
// -- HTTP handler: POST /register_session -------------------------------------
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
        // Also install the responder state so the network thread can synthesize
        // ROUTE_RESPONSE packets in reply to relay-forwarded ROUTE_REQUEST.
        match install_responder(
            &state.responder,
            body.session_id,
            body.session_version,
            &key_bytes,
            magic_hex,
            server_pub,
        ) {
            Ok(()) => log::info!(
                "register_session: responder installed (session={:016x})",
                body.session_id
            ),
            Err(e) => log::warn!("register_session: responder install failed: {}", e),
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
// -- HTTP handler: POST /notify_session ---------------------------------------
//
// Receives webhook from server-backend after POST /sessions or
// POST /sessions/{id}/refresh. Routes to the same install_pinger +
// install_responder + register_session logic as register_session_handler
// (relay mode path). bench_client in server-backend mode does NOT call
// /register_session directly - server-backend sends this webhook instead.
async fn notify_session_handler(
    State(state): State<Arc<BenchState>>,
    Json(body): Json<NotifySessionBody>,
) -> impl IntoResponse {
    let key_bytes = match hex::decode(&body.session_private_key_hex) {
        Ok(b) if b.len() == SESSION_PRIVATE_KEY_BYTES => {
            let mut arr = [0u8; SESSION_PRIVATE_KEY_BYTES];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => {
            log::warn!(
                "notify_session: bad key length {} (expected {})",
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
            log::warn!("notify_session: hex decode error: {}", e);
            return (StatusCode::BAD_REQUEST, "invalid session_private_key_hex").into_response();
        }
    };
    let relay_addr: Address = match body.relay_address.parse() {
        Ok(a) => a,
        Err(e) => {
            log::warn!(
                "notify_session: bad relay_address '{}': {}",
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
    // Install pinger + responder using the server's public address stored at
    // startup from SERVER_PUBLIC_ADDR env var. Without a public address we
    // still register the session (SDK-level crypto works) but skip pinger/
    // responder installation - the relay will not whitelist bench_server and
    // will drop every forwarded ROUTE_REQUEST + CLIENT_TO_SERVER.
    if let Some(server_pub) = state.server_public_addr.as_deref() {
        match install_pinger(
            &state.pinger,
            &body.ping_key_hex,
            &body.current_magic_hex,
            server_pub,
            &body.relay_address,
        ) {
            Ok(()) => log::info!(
                "notify_session: pinger installed (server_pub={} relay={})",
                server_pub,
                body.relay_address
            ),
            Err(e) => log::warn!("notify_session: pinger install failed: {}", e),
        }
        match install_responder(
            &state.responder,
            body.session_id,
            body.session_version,
            &key_bytes,
            &body.current_magic_hex,
            server_pub,
        ) {
            Ok(()) => log::info!(
                "notify_session: responder installed (session={:016x})",
                body.session_id
            ),
            Err(e) => log::warn!("notify_session: responder install failed: {}", e),
        }
    } else {
        log::warn!(
            "notify_session: SERVER_PUBLIC_ADDR not set - pinger/responder not installed. \
             Set SERVER_PUBLIC_ADDR=<IP>:<UDP_PORT> so the relay whitelists bench_server."
        );
    }
    log::info!(
        "notify_session: registered session {:016x} v={} relay={}",
        body.session_id,
        body.session_version,
        body.relay_address
    );
    (StatusCode::OK, "ok").into_response()
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
fn install_responder(
    slot: &Arc<Mutex<Option<RouteResponderState>>>,
    session_id: u64,
    session_version: u8,
    session_private_key: &[u8; SESSION_PRIVATE_KEY_BYTES],
    magic_hex: &str,
    server_public_address: &str,
) -> Result<()> {
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
    *slot.lock().unwrap() = Some(RouteResponderState {
        session_id,
        session_version,
        session_private_key: *session_private_key,
        server_ip,
        magic,
        next_sequence: 1,
    });
    Ok(())
}
/// Build a 43-byte ROUTE_RESPONSE packet (matches relay-xdp-ebpf::handle_route_response).
///
/// Wire layout:
///   [0]      packet type = 2 (RELAY_ROUTE_RESPONSE_PACKET)
///   [1..18]  pittle/chonkle (filled by stamp_packet)
///   [18..26] packet_sequence (LE u64)
///   [26..34] session_id      (LE u64)
///   [34]     session_version (u8)
///   [35..43] header MAC: SHA-256(private_key || type || seq || sid || ver)[..8]
///
/// `relay_ip` is the relay's IPv4 octets (destination of this UDP packet) used
/// only for pittle/chonkle stamping.
fn build_route_response_packet(
    server_ip: &[u8; 4],
    relay_ip: &[u8; 4],
    session_private_key: &[u8; SESSION_PRIVATE_KEY_BYTES],
    session_id: u64,
    session_version: u8,
    sequence: u64,
    magic: &[u8; 8],
) -> [u8; ROUTE_RESPONSE_BYTES] {
    let mut buf = [0u8; ROUTE_RESPONSE_BYTES];
    buf[0] = PACKET_TYPE_ROUTE_RESPONSE;
    // RELAY_HEADER_BYTES = HEADER_BYTES = 25 starts at offset 18.
    let mut header = [0u8; HEADER_BYTES];
    write_header(
        PACKET_TYPE_ROUTE_RESPONSE,
        sequence,
        session_id,
        session_version,
        session_private_key,
        &mut header,
    );
    buf[18..18 + HEADER_BYTES].copy_from_slice(&header);
    stamp_packet(&mut buf, magic, server_ip, relay_ip);
    buf
}
// -- Network thread -----------------------------------------------------------
#[allow(clippy::too_many_arguments)]
fn network_thread(
    mut inner: ServerInner,
    server_arc: Arc<Mutex<Server>>,
    pkt_recv: Arc<AtomicU64>,
    pkt_sent: Arc<AtomicU64>,
    udp_port: u16,
    shutdown: Arc<AtomicBool>,
    pinger: Arc<Mutex<Option<ServerPingerState>>>,
    responder: Arc<Mutex<Option<RouteResponderState>>>,
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
        // 3a. ROUTE_REQUEST forwarded by the relay reaches us with type=1 and
        //     one trailing encrypted token. ServerInner does not handle this
        //     packet type, so we synthesize a ROUTE_RESPONSE locally and send
        //     it back to the relay (the source address of the UDP datagram).
        //     The relay then verifies the header MAC, marks the session_map
        //     entry confirmed, and forwards the response to bench_client.
        if n >= 1 && recv_buf[0] == RELAY_ROUTE_REQUEST_PACKET {
            pkt_recv.fetch_add(1, Ordering::Relaxed);
            let snapshot = responder.lock().unwrap().as_ref().map(|r| {
                (
                    r.session_id,
                    r.session_version,
                    r.session_private_key,
                    r.server_ip,
                    r.magic,
                )
            });
            if let Some((sid, sver, spk, server_ip, magic)) = snapshot {
                // Allocate sequence under the lock so concurrent ROUTE_REQUESTs
                // get strictly increasing values.
                let seq = {
                    let mut g = responder.lock().unwrap();
                    if let Some(r) = g.as_mut() {
                        let s = r.next_sequence;
                        r.next_sequence = r.next_sequence.wrapping_add(1);
                        s
                    } else {
                        1
                    }
                };
                let relay_ip = match from.ip() {
                    std::net::IpAddr::V4(v4) => v4.octets(),
                    _ => {
                        log::warn!("bench_server: ROUTE_REQUEST from non-IPv4 source: {}", from);
                        continue;
                    }
                };
                let pkt = build_route_response_packet(
                    &server_ip, &relay_ip, &spk, sid, sver, seq, &magic,
                );
                match sock.send_to(&pkt, from) {
                    Ok(_) => {
                        pkt_sent.fetch_add(1, Ordering::Relaxed);
                        log::info!(
                            "bench_server: sent ROUTE_RESPONSE seq={} to relay {}",
                            seq,
                            from
                        );
                    }
                    Err(e) => log::warn!(
                        "bench_server: ROUTE_RESPONSE send to {} failed: {}",
                        from,
                        e
                    ),
                }
            } else {
                log::warn!(
                    "bench_server: received ROUTE_REQUEST from {} but no responder state \
                     installed (was /register_session called with relay-mode params?)",
                    from
                );
            }
            continue;
        }
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
// -- Main ---------------------------------------------------------------------
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
    // -- Server-backend integration env vars ----------------------------------
    let server_backend_url = std::env::var("SERVER_BACKEND_URL").unwrap_or_default();
    let server_public_addr: Option<String> = std::env::var("SERVER_PUBLIC_ADDR").ok();
    log::info!(
        "bench_server starting (HTTP:{} UDP:{})",
        http_port,
        udp_port
    );
    // -- Optional startup self-registration with server-backend ---------------
    // When SERVER_BACKEND_URL is set, register this bench_server as a game
    // server so bench_client (in server-backend mode) can call POST /sessions
    // and server-backend will select a relay chain and call POST /notify_session
    // back here before returning tokens to the client.
    let mut registered_server_id: Option<String> = None;
    if !server_backend_url.is_empty() {
        let server_lat: f64 = std::env::var("SERVER_LAT")
            .unwrap_or_else(|_| "0.0".into())
            .parse()
            .unwrap_or(0.0);
        let server_lng: f64 = std::env::var("SERVER_LNG")
            .unwrap_or_else(|_| "0.0".into())
            .parse()
            .unwrap_or(0.0);
        let server_callback_url = std::env::var("SERVER_CALLBACK_URL")
            .unwrap_or_else(|_| format!("http://127.0.0.1:{}", http_port));
        // udp_addr: prefer SERVER_PUBLIC_ADDR (game traffic arrives here);
        // fall back to loopback when not set (local-only testing).
        let udp_addr = server_public_addr
            .clone()
            .unwrap_or_else(|| format!("127.0.0.1:{}", udp_port));
        let req = SbRegisterServerRequest {
            udp_addr,
            lat: server_lat,
            lng: server_lng,
            callback_url: server_callback_url,
        };
        let http = reqwest::Client::new();
        match http
            .post(format!("{}/servers", server_backend_url))
            .json(&req)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<SbRegisterServerResponse>().await {
                    Ok(r) => {
                        log::info!(
                            "bench_server: registered with server-backend server_id={}",
                            r.server_id
                        );
                        registered_server_id = Some(r.server_id);
                    }
                    Err(e) => {
                        log::warn!(
                            "bench_server: server-backend POST /servers response parse failed: {}",
                            e
                        );
                    }
                }
            }
            Ok(resp) => {
                log::warn!(
                    "bench_server: server-backend POST /servers returned HTTP {}",
                    resp.status()
                );
            }
            Err(e) => {
                log::warn!("bench_server: server-backend POST /servers failed: {}", e);
            }
        }
    }
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
    let responder: Arc<Mutex<Option<RouteResponderState>>> = Arc::new(Mutex::new(None));
    // Spawn network thread.
    {
        let server_net = Arc::clone(&server_arc);
        let recv_net = Arc::clone(&pkt_recv);
        let sent_net = Arc::clone(&pkt_sent);
        let shutdown_net = Arc::clone(&shutdown);
        let pinger_net = Arc::clone(&pinger);
        let responder_net = Arc::clone(&responder);
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
                    responder_net,
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
        responder: Arc::clone(&responder),
        server_public_addr,
    });
    let app = Router::new()
        .route("/register_session", post(register_session_handler))
        .route("/notify_session", post(notify_session_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", http_port)).await?;
    log::info!("bench_server: HTTP listening on :{}", http_port);
    // Graceful shutdown: signal the network thread and optionally deregister
    // from server-backend (DELETE /servers/{id}) before the process exits.
    let shutdown_net = Arc::clone(&shutdown);
    let sb_url_shutdown = server_backend_url.clone();
    let sb_id_shutdown = registered_server_id.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.ok();
            shutdown_net.store(true, Ordering::Relaxed);
            if !sb_url_shutdown.is_empty() {
                if let Some(sid) = &sb_id_shutdown {
                    let http = reqwest::Client::new();
                    let url = format!("{}/servers/{}", sb_url_shutdown, sid);
                    match http.delete(&url).send().await {
                        Ok(_) => log::info!(
                            "bench_server: deregistered server {} from server-backend",
                            sid
                        ),
                        Err(e) => {
                            log::warn!("bench_server: DELETE /servers/{} failed: {}", sid, e)
                        }
                    }
                }
            }
        })
        .await?;
    Ok(())
}

// -- Tests --------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_state(server_public_addr: Option<&str>) -> Arc<BenchState> {
        let (_inner, server) = ServerInner::create();
        Arc::new(BenchState {
            server: Arc::new(Mutex::new(server)),
            pinger: Arc::new(Mutex::new(None)),
            responder: Arc::new(Mutex::new(None)),
            server_public_addr: server_public_addr.map(|s| s.to_string()),
        })
    }

    fn valid_body() -> NotifySessionBody {
        NotifySessionBody {
            session_id: 0x1234_5678_9abc_def0,
            session_version: 1,
            session_private_key_hex: "11".repeat(SESSION_PRIVATE_KEY_BYTES),
            relay_address: "10.0.0.1:40000".to_string(),
            ping_key_hex: "22".repeat(PING_KEY_BYTES),
            current_magic_hex: "33".repeat(8),
        }
    }

    async fn status_of(resp: axum::response::Response) -> StatusCode {
        resp.status()
    }

    #[tokio::test]
    async fn notify_session_valid_body_installs_pinger_and_responder() {
        let state = fresh_state(Some("203.0.113.5:17777"));
        let body = valid_body();
        let resp = notify_session_handler(State(Arc::clone(&state)), Json(body))
            .await
            .into_response();
        assert_eq!(status_of(resp).await, StatusCode::OK);
        assert!(
            state.pinger.lock().unwrap().is_some(),
            "pinger should be installed when server_public_addr is set"
        );
        assert!(
            state.responder.lock().unwrap().is_some(),
            "responder should be installed when server_public_addr is set"
        );
    }

    #[tokio::test]
    async fn notify_session_valid_body_without_public_addr_skips_pinger() {
        let state = fresh_state(None);
        let body = valid_body();
        let resp = notify_session_handler(State(Arc::clone(&state)), Json(body))
            .await
            .into_response();
        // Session still registered (200 OK) but pinger/responder skipped.
        assert_eq!(status_of(resp).await, StatusCode::OK);
        assert!(state.pinger.lock().unwrap().is_none());
        assert!(state.responder.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn notify_session_bad_key_hex_returns_400() {
        let state = fresh_state(Some("203.0.113.5:17777"));
        let mut body = valid_body();
        body.session_private_key_hex = "zz".repeat(SESSION_PRIVATE_KEY_BYTES);
        let resp = notify_session_handler(State(state), Json(body))
            .await
            .into_response();
        assert_eq!(status_of(resp).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn notify_session_bad_key_length_returns_400() {
        let state = fresh_state(Some("203.0.113.5:17777"));
        let mut body = valid_body();
        body.session_private_key_hex = "11".repeat(SESSION_PRIVATE_KEY_BYTES - 1);
        let resp = notify_session_handler(State(state), Json(body))
            .await
            .into_response();
        assert_eq!(status_of(resp).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn notify_session_bad_relay_address_returns_400() {
        let state = fresh_state(Some("203.0.113.5:17777"));
        let mut body = valid_body();
        body.relay_address = "not-an-address".to_string();
        let resp = notify_session_handler(State(state), Json(body))
            .await
            .into_response();
        assert_eq!(status_of(resp).await, StatusCode::BAD_REQUEST);
    }
}
