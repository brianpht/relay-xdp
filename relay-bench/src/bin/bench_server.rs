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
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use serde::Deserialize;

use relay_sdk::address::Address;
use relay_sdk::constants::{MAX_PACKET_BYTES, SESSION_PRIVATE_KEY_BYTES};
use relay_sdk::server::{Server, ServerInner};

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
}

// ── Shared axum state ─────────────────────────────────────────────────────────

struct BenchState {
    server: Arc<Mutex<Server>>,
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

    log::info!(
        "registered session {:016x} v={} relay={}",
        body.session_id,
        body.session_version,
        body.relay_address
    );

    (StatusCode::OK, "registered").into_response()
}

// ── Network thread ────────────────────────────────────────────────────────────

fn network_thread(
    mut inner: ServerInner,
    server_arc: Arc<Mutex<Server>>,
    pkt_recv: Arc<AtomicU64>,
    pkt_sent: Arc<AtomicU64>,
    udp_port: u16,
    shutdown: Arc<AtomicBool>,
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

    while !shutdown.load(Ordering::Relaxed) {
        // 1. Drain pending commands (RegisterSession, Open, etc.)
        inner.pump_commands();

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

    // Spawn network thread.
    {
        let server_net = Arc::clone(&server_arc);
        let recv_net = Arc::clone(&pkt_recv);
        let sent_net = Arc::clone(&pkt_sent);
        let shutdown_net = Arc::clone(&shutdown);
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
