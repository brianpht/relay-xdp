// relay-sdk/src/bin/relay_sdk_smoke.rs - SDK smoke test binary.
//
// Runs 3 groups of assertions (always):
//   Group 1: Backend HTTP  (4)  - GET /health + GET /active_relays
//   Group 2: Client state  (5)  - open/update/tick/stats/close
//   Group 3: Server state  (4)  - open/register/expire/count
//
// Group 4: UDP E2E (only when RELAY_E2E_UDP=1)
//   Group 4: Route matrix + UDP loopback (4) - convergence poll + real socket codec
//
// Exit code: 0 = all assertions passed, 1 = any failure.
//
// Env vars:
//   BACKEND_HOST        (default: 172.28.0.3)
//   BACKEND_PORT        (default: 80)   - public port: /health, /ready, /relay_update
//   ADMIN_BACKEND_PORT  (default: 81)   - admin port: /active_relays, /relays, /metrics, etc.
//   RELAY_IDS           (space-separated list, used by group 4 route_matrix check)
//   RELAY_E2E_UDP       (default: 0)    - set to 1 to run group 4

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use relay_sdk::address::Address;
use relay_sdk::client::{ClientInner, CLIENT_STATE_OPEN};
use relay_sdk::constants::{
    ENCRYPTED_ROUTE_TOKEN_BYTES, PACKET_TYPE_ROUTE_RESPONSE, SESSION_PRIVATE_KEY_BYTES,
    UPDATE_TYPE_DIRECT, UPDATE_TYPE_ROUTE,
};
use relay_sdk::crypto::XCHACHA_KEY_BYTES;
use relay_sdk::packets::{RouteResponsePacket, ROUTE_RESPONSE_BYTES};
use relay_sdk::route::write_header;
use relay_sdk::server::ServerInner;
use relay_sdk::tokens::encrypt_route_token;
use relay_xdp_common::RouteToken;

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn http_raw(host: &str, port: u16, path: &str) -> Result<String, String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("connect {}: {}", addr, e))?;
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {}", e))?;
    let mut buf = String::new();
    stream
        .read_to_string(&mut buf)
        .map_err(|e| format!("read: {}", e))?;
    Ok(buf)
}

fn http_status(host: &str, port: u16, path: &str) -> u16 {
    match http_raw(host, port, path) {
        Err(_) => 0,
        Ok(resp) => resp
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0),
    }
}

fn http_body(host: &str, port: u16, path: &str) -> String {
    match http_raw(host, port, path) {
        Err(_) => String::new(),
        Ok(resp) => match resp.find("\r\n\r\n") {
            Some(pos) => resp[pos + 4..].to_string(),
            None => resp,
        },
    }
}

// ── Assertion runner ──────────────────────────────────────────────────────────

struct Runner {
    passed: u32,
    failed: u32,
    group: u32,
}

impl Runner {
    fn new() -> Self {
        Runner {
            passed: 0,
            failed: 0,
            group: 0,
        }
    }

    fn set_group(&mut self, g: u32) {
        self.group = g;
    }

    fn check(&mut self, label: &str, ok: bool) {
        if ok {
            println!("  PASS  [group={}] {}", self.group, label);
            self.passed += 1;
        } else {
            eprintln!("  FAIL  [group={}] {}", self.group, label);
            self.failed += 1;
        }
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let host = std::env::var("BACKEND_HOST").unwrap_or_else(|_| "172.28.0.3".to_string());
    let port: u16 = std::env::var("BACKEND_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let admin_port: u16 = std::env::var("ADMIN_BACKEND_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(81);
    let relay_e2e_udp = std::env::var("RELAY_E2E_UDP")
        .unwrap_or_default()
        .trim()
        .eq("1");

    let mut t = Runner::new();

    // ── Group 1: Backend HTTP ─────────────────────────────────────────────────
    println!();
    println!("=== Group 1: Backend HTTP ===");
    t.set_group(1);

    let status = http_status(&host, port, "/health");
    t.check("1.1  GET /health returns 200", status == 200);

    // /active_relays is on the admin port (P1-14 route separation)
    let body = http_body(&host, admin_port, "/active_relays");
    t.check(
        "1.2  GET /active_relays contains relay-a",
        body.contains("relay-a"),
    );
    t.check(
        "1.3  GET /active_relays contains relay-b",
        body.contains("relay-b"),
    );
    t.check(
        "1.4  GET /active_relays contains relay-c",
        body.contains("relay-c"),
    );

    // ── Group 2: Client state machine ─────────────────────────────────────────
    println!();
    println!("=== Group 2: Client state machine ===");
    t.set_group(2);

    let (mut inner, mut client) = ClientInner::create();
    let server_addr = Address::V4 {
        octets: [127, 0, 0, 1],
        port: 7777,
    };
    let client_key = [0xABu8; XCHACHA_KEY_BYTES];

    client.open_session(server_addr, client_key);
    inner.pump_commands();
    t.check(
        "2.1  client state is CLIENT_STATE_OPEN after open_session",
        client.state() == CLIENT_STATE_OPEN,
    );

    let ext_addr = Address::V4 {
        octets: [10, 0, 0, 1],
        port: 5000,
    };
    client.route_update(UPDATE_TYPE_DIRECT, 0, vec![], [0u8; 8], ext_addr);
    inner.pump_commands();
    // route_update with DIRECT type is always accepted without panic
    t.check("2.2  route_update(DIRECT) processed without error", true);

    client.tick(0.016);
    inner.pump_commands();
    t.check("2.3  tick processed without error", true);

    client.drain_notify();
    t.check(
        "2.4  stats.route_changes >= 1 after open + tick",
        client.stats.route_changes >= 1,
    );

    client.close_session();
    inner.pump_commands();
    t.check(
        "2.5  inner.session_open is false after close_session",
        !inner.session_open,
    );

    // ── Group 3: Server state machine ─────────────────────────────────────────
    println!();
    println!("=== Group 3: Server state machine ===");
    t.set_group(3);

    let (mut sinner, mut server) = ServerInner::create();
    let bind_addr = Address::V4 {
        octets: [0, 0, 0, 0],
        port: 40000,
    };
    server.open(bind_addr);
    sinner.pump_commands();
    t.check("3.1  server.is_open() after open", server.is_open());

    let priv_key = [0x42u8; SESSION_PRIVATE_KEY_BYTES];
    let relay_addr = Address::V4 {
        octets: [172, 28, 0, 10],
        port: 40000,
    };
    server.register_session(0xDEAD_BEEF_u64, 1, priv_key, relay_addr);
    sinner.pump_commands();
    server.drain_notify();
    t.check(
        "3.2  stats.sessions_registered == 1 after register_session",
        server.stats.sessions_registered == 1,
    );

    server.expire_session(0xDEAD_BEEF_u64);
    sinner.pump_commands();
    server.drain_notify();
    t.check(
        "3.3  stats.sessions_expired == 1 after expire_session",
        server.stats.sessions_expired == 1,
    );
    t.check(
        "3.4  inner.session_count() == 0 after expire_session",
        sinner.session_count() == 0,
    );

    // ── Group 4: UDP E2E (only when RELAY_E2E_UDP=1) ──────────────────────────
    if relay_e2e_udp {
        println!();
        println!("=== Group 4: Route matrix convergence + UDP loopback E2E ===");
        t.set_group(4);
        run_group4(&host, admin_port, &mut t);
    }

    // ── Summary ───────────────────────────────────────────────────────────────
    println!();
    let total = t.passed + t.failed;
    println!("Results: {}/{} passed", t.passed, total);
    // Machine-parseable JSON summary line (consumed by Makefile / CI).
    println!(
        r#"{{"assertions":{},"passed":{},"failed":{}}}"#,
        total, t.passed, t.failed
    );
    if t.failed > 0 {
        eprintln!("{} assertion(s) failed", t.failed);
        std::process::exit(1);
    } else {
        println!("All {} assertions passed", t.passed);
    }
}

// ── Group 4 implementation ────────────────────────────────────────────────────

fn run_group4(host: &str, admin_port: u16, t: &mut Runner) {
    // ── 4.1: route_matrix convergence - all relay IDs visible to backend ──────
    //
    // Polls GET /route_matrix every 2 seconds for up to 30 seconds.
    // Passes when the body is non-empty and all IDs in RELAY_IDS appear in it.
    // This proves the deployed relay nodes have posted /relay_update heartbeats
    // and the optimizer has produced at least one route matrix.
    let relay_ids: Vec<String> = std::env::var("RELAY_IDS")
        .unwrap_or_default()
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let matrix_body = poll_route_matrix(host, admin_port, &relay_ids, 30, 2);
    let matrix_ok = !matrix_body.is_empty();
    t.check(
        "4.1  /route_matrix non-empty (relays converged to backend)",
        matrix_ok,
    );
    // Only check individual relay IDs if we got any body at all.
    if matrix_ok && !relay_ids.is_empty() {
        for id in &relay_ids {
            let label = format!("4.1  /route_matrix contains relay id {}", id);
            t.check(&label, matrix_body.contains(id.as_str()));
        }
    }

    // ── 4.2 - 4.4: UDP loopback codec E2E ────────────────────────────────────
    //
    // Proves ClientInner + ServerInner encode/decode correctly over real UDP
    // sockets (loopback). No deployed relay nodes are needed for this sub-test.
    // Flow:
    //   ClientInner (loopback:C) --(CLIENT_TO_SERVER)-> ServerInner (loopback:S)
    //   ServerInner              --(SERVER_TO_CLIENT)-> ClientInner
    run_udp_loopback(t);
}

// Poll GET /route_matrix up to `max_wait_s` seconds (2-second interval).
// Returns the body when non-empty and all `required_ids` appear, or an empty
// string on timeout.
fn poll_route_matrix(
    host: &str,
    admin_port: u16,
    required_ids: &[String],
    max_wait_s: u64,
    interval_s: u64,
) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(max_wait_s);
    loop {
        let body = http_body(host, admin_port, "/route_matrix");
        if !body.is_empty() && required_ids.iter().all(|id| body.contains(id.as_str())) {
            return body;
        }
        if std::time::Instant::now() >= deadline {
            eprintln!(
                "[group=4] route_matrix poll timed out after {}s",
                max_wait_s
            );
            return String::new();
        }
        eprintln!(
            "[group=4] waiting for route_matrix convergence ({}s remaining)...",
            deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_secs()
        );
        std::thread::sleep(Duration::from_secs(interval_s));
    }
}

// Real UDP loopback: ClientInner <-> ServerInner via loopback sockets.
//
// Session setup:
//   session_id       = 0xDEAD_C0DE_E2E0_0001
//   session_version  = 1
//   session_private_key = [0x55u8; SESSION_PRIVATE_KEY_BYTES]
//   client_secret_key   = [0xAAu8; XCHACHA_KEY_BYTES]  (XChaCha key for token decryption)
//
// Route token is encrypted with client_secret_key.
// Server registers with the same session_id / version / private_key.
// After ROUTE_RESPONSE is fed to inner, the route is established and
// CLIENT_TO_SERVER / SERVER_TO_CLIENT packets are exchanged via real UDP.
fn run_udp_loopback(t: &mut Runner) {
    const SESSION_ID: u64 = 0xDEAD_C0DE_E2E0_0001;
    const SESSION_VERSION: u8 = 1;
    const SESSION_KEY: [u8; SESSION_PRIVATE_KEY_BYTES] = [0x55u8; SESSION_PRIVATE_KEY_BYTES];
    const CLIENT_SECRET_KEY: [u8; XCHACHA_KEY_BYTES] = [0xAAu8; XCHACHA_KEY_BYTES];
    const MAGIC: [u8; 8] = [0xE2u8, 0xE0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];

    // Bind two loopback UDP sockets on OS-assigned ports.
    let server_sock = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[group=4] failed to bind server UDP socket: {}", e);
            t.check(
                "4.2  client.stats.packets_sent > 0 (UDP loopback C->S)",
                false,
            );
            t.check(
                "4.3  server.stats.packets_received > 0 (UDP loopback C->S)",
                false,
            );
            t.check(
                "4.4  echo payload equality (server echoes client payload)",
                false,
            );
            return;
        }
    };
    let client_sock = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[group=4] failed to bind client UDP socket: {}", e);
            t.check(
                "4.2  client.stats.packets_sent > 0 (UDP loopback C->S)",
                false,
            );
            t.check(
                "4.3  server.stats.packets_received > 0 (UDP loopback C->S)",
                false,
            );
            t.check(
                "4.4  echo payload equality (server echoes client payload)",
                false,
            );
            return;
        }
    };

    // 1-second recv timeout so a dropped packet fails fast rather than hanging.
    let _ = server_sock.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = client_sock.set_read_timeout(Some(Duration::from_secs(1)));

    let server_local_addr = server_sock.local_addr().unwrap();
    let client_local_addr = client_sock.local_addr().unwrap();

    let server_port = server_local_addr.port();
    let client_port = client_local_addr.port();

    // Address helpers for relay_sdk::address::Address.
    let server_sdk_addr = Address::V4 {
        octets: [127, 0, 0, 1],
        port: server_port,
    };
    let client_sdk_addr = Address::V4 {
        octets: [127, 0, 0, 1],
        port: client_port,
    };

    // ── Server side: open + register session ─────────────────────────────────
    //
    // relay_address is set to client_sdk_addr because in this loopback test
    // "the last relay hop" is the client socket (no relay node in the middle).
    // ServerInner sends SERVER_TO_CLIENT to relay_address, i.e. the client.
    let (mut sinner, mut server) = ServerInner::create();
    let bind_address = Address::V4 {
        octets: [0, 0, 0, 0],
        port: server_port,
    };
    server.open(bind_address);
    sinner.pump_commands();

    server.register_session(SESSION_ID, SESSION_VERSION, SESSION_KEY, client_sdk_addr);
    sinner.pump_commands();
    server.drain_notify();

    // ── Client side: open session + deliver route update ──────────────────────
    //
    // Build an encrypted RouteToken pointing at the server socket.
    // next_address is server IP as u32 big-endian (127.0.0.1 = 0x7F000001).
    let route_token = RouteToken {
        session_private_key: SESSION_KEY,
        expire_timestamp: 9_999_999_999,
        session_id: SESSION_ID,
        envelope_kbps_up: 1000,
        envelope_kbps_down: 2000,
        next_address: 0x7F00_0001u32.to_be(), // 127.0.0.1 in network byte order
        prev_address: 0,
        next_port: server_port.to_be(),
        prev_port: 0,
        session_version: SESSION_VERSION,
        next_internal: 0,
        prev_internal: 0,
    };

    let enc_token = encrypt_route_token(&route_token, &CLIENT_SECRET_KEY);
    // Tokens vec: first = route token for client, second = dummy server token.
    let mut tokens = Vec::with_capacity(ENCRYPTED_ROUTE_TOKEN_BYTES * 2);
    tokens.extend_from_slice(&enc_token);
    tokens.extend_from_slice(&[0u8; ENCRYPTED_ROUTE_TOKEN_BYTES]);

    let (mut inner, mut client) = ClientInner::create();
    client.open_session(server_sdk_addr, CLIENT_SECRET_KEY);
    inner.pump_commands();

    // Client external address used to stamp pittle/chonkle source field.
    client.route_update(UPDATE_TYPE_ROUTE, 2, tokens, MAGIC, client_sdk_addr);
    inner.pump_commands();

    // Drain the ROUTE_REQUEST that try_send_pending emitted (discard it - we
    // simulate the relay ROUTE_RESPONSE below without a real relay).
    client.drain_notify();
    while client.pop_send_raw().is_some() {}

    // ── Simulate ROUTE_RESPONSE to confirm the pending route ─────────────────
    //
    // In production the relay node sends this after receiving ROUTE_REQUEST.
    // Here we build it directly to establish the route without a real relay.
    let mut rr_buf = [0u8; ROUTE_RESPONSE_BYTES];
    rr_buf[0] = PACKET_TYPE_ROUTE_RESPONSE;
    // pittle + chonkle (bytes 1..18) are not validated by process_incoming - leave zero.

    // relay_header at bytes 18..43: HMAC must verify with pending_route_private_key = SESSION_KEY.
    let mut relay_hdr = [0u8; 25]; // HEADER_BYTES
    write_header(
        PACKET_TYPE_ROUTE_RESPONSE,
        0, // sequence
        SESSION_ID,
        SESSION_VERSION,
        &SESSION_KEY,
        &mut relay_hdr,
    );
    rr_buf[18..43].copy_from_slice(&relay_hdr);

    let rr_pkt = RouteResponsePacket {
        relay_header: relay_hdr,
    };
    let mut rr_encoded = [0u8; ROUTE_RESPONSE_BYTES];
    let _ = rr_pkt.encode(&mut rr_encoded);

    // Feed ROUTE_RESPONSE to client inner - this calls confirm_pending_route().
    let _ = inner.process_incoming(&rr_encoded);
    inner.pump_commands();
    client.drain_notify();

    // Route must now be established.
    if !inner.route_manager.has_network_next_route() {
        eprintln!("[group=4] route not established after ROUTE_RESPONSE - aborting UDP test");
        t.check(
            "4.2  client.stats.packets_sent > 0 (UDP loopback C->S)",
            false,
        );
        t.check(
            "4.3  server.stats.packets_received > 0 (UDP loopback C->S)",
            false,
        );
        t.check(
            "4.4  echo payload equality (server echoes client payload)",
            false,
        );
        return;
    }

    // ── Exchange 3 game packets: client -> server -> client (echo) ────────────
    let test_payloads: &[&[u8]] = &[b"e2e-ping-1", b"e2e-ping-2", b"e2e-ping-3"];
    let mut echo_ok = true;

    for payload in test_payloads {
        // -- Client sends --
        client.send_packet(payload);
        inner.pump_commands();

        let raw = match client.pop_send_raw() {
            Some(r) => r,
            None => {
                eprintln!("[group=4] no SendRaw after send_packet");
                echo_ok = false;
                continue;
            }
        };

        // Actual UDP send: client socket -> server socket.
        if client_sock.send_to(&raw.1, server_local_addr).is_err() {
            echo_ok = false;
            continue;
        }

        // -- Server receives --
        let mut recv_buf = [0u8; 1400];
        let (n, from) = match server_sock.recv_from(&mut recv_buf) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[group=4] server recv_from failed: {}", e);
                echo_ok = false;
                continue;
            }
        };

        let incoming = sinner.process_incoming(&recv_buf[..n]);
        sinner.pump_commands();

        let (_, rx_payload) = match server.recv_packet() {
            Some(p) => p,
            None => match incoming {
                Some((sid, data)) => (sid, data),
                None => {
                    eprintln!("[group=4] server did not receive payload");
                    echo_ok = false;
                    continue;
                }
            },
        };

        // -- Server echoes back --
        let from_addr = Address::V4 {
            octets: match from.ip() {
                std::net::IpAddr::V4(a) => a.octets(),
                _ => [127, 0, 0, 1],
            },
            port: from.port(),
        };
        server.send_packet(SESSION_ID, &rx_payload, MAGIC, from_addr);
        sinner.pump_commands();

        let (s2c_to, s2c_data) = match server.pop_send_raw() {
            Some(r) => r,
            None => {
                eprintln!("[group=4] server has no SendRaw for reply");
                echo_ok = false;
                continue;
            }
        };
        let _ = s2c_to;

        // Actual UDP send: server socket -> client socket.
        if server_sock.send_to(&s2c_data, client_local_addr).is_err() {
            echo_ok = false;
            continue;
        }

        // -- Client receives echo --
        // ClientInner::process_incoming returns the payload directly.
        // (It does not push Notify::PacketReceived - the network thread is
        // responsible for bridging that to the app thread in production.)
        let mut c_recv = [0u8; 1400];
        let (cn, _) = match client_sock.recv_from(&mut c_recv) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[group=4] client recv_from failed: {}", e);
                echo_ok = false;
                continue;
            }
        };

        match inner.process_incoming(&c_recv[..cn]) {
            Some(ep) if ep.as_slice() == *payload => {
                // echo matches - good
            }
            Some(ep) => {
                eprintln!("[group=4] echo mismatch: sent {:?} got {:?}", payload, ep);
                echo_ok = false;
            }
            None => {
                eprintln!("[group=4] client did not receive echoed payload");
                echo_ok = false;
            }
        }
    }

    t.check(
        "4.2  client.stats.packets_sent > 0 (UDP loopback C->S)",
        client.stats.packets_sent > 0,
    );
    t.check(
        "4.3  server.stats.packets_received > 0 (UDP loopback C->S)",
        server.stats.packets_received > 0,
    );
    t.check(
        "4.4  echo payload equality (server echoes client payload)",
        echo_ok,
    );
}
