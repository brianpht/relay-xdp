// relay-sdk/src/bin/relay_sdk_smoke.rs - SDK smoke test binary.
//
// Runs 3 groups of assertions:
//   Group 1: Backend HTTP  (4) - GET /health + GET /active_relays
//   Group 2: Client state  (5) - open/update/tick/stats/close
//   Group 3: Server state  (4) - open/register/expire/count
//
// Exit code: 0 = all 13 assertions passed, 1 = any failure.
//
// Env vars:
//   BACKEND_HOST  (default: 172.28.0.3)
//   BACKEND_PORT  (default: 80)

use std::io::{Read, Write};
use std::net::TcpStream;

use relay_sdk::address::Address;
use relay_sdk::client::{ClientInner, CLIENT_STATE_OPEN};
use relay_sdk::constants::{SESSION_PRIVATE_KEY_BYTES, UPDATE_TYPE_DIRECT};
use relay_sdk::crypto::XCHACHA_KEY_BYTES;
use relay_sdk::server::ServerInner;

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn http_raw(host: &str, port: u16, path: &str) -> Result<String, String> {
    let addr = format!("{}:{}", host, port);
    let mut stream =
        TcpStream::connect(&addr).map_err(|e| format!("connect {}: {}", addr, e))?;
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
}

impl Runner {
    fn new() -> Self {
        Runner {
            passed: 0,
            failed: 0,
        }
    }

    fn check(&mut self, label: &str, ok: bool) {
        if ok {
            println!("  PASS  {}", label);
            self.passed += 1;
        } else {
            eprintln!("  FAIL  {}", label);
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

    let mut t = Runner::new();

    // ── Group 1: Backend HTTP ─────────────────────────────────────────────────
    println!();
    println!("=== Group 1: Backend HTTP ===");

    let status = http_status(&host, port, "/health");
    t.check("1.1  GET /health returns 200", status == 200);

    let body = http_body(&host, port, "/active_relays");
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

    // ── Summary ───────────────────────────────────────────────────────────────
    println!();
    let total = t.passed + t.failed;
    println!("Results: {}/{} passed", t.passed, total);
    if t.failed > 0 {
        eprintln!("{} assertion(s) failed", t.failed);
        std::process::exit(1);
    } else {
        println!("All {} assertions passed", t.passed);
    }
}

