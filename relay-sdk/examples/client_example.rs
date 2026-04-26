// client_example.rs - relay-sdk game client integration walkthrough.
//
// Demonstrates the two-half pattern with an in-memory simulation:
//   Client     - main-thread handle (command queue, notify poll)
//   ClientInner - network-thread side (RouteManager, packet codec)
//
// In production the two halves run on different threads sharing
// Arc<Mutex<VecDeque<_>>> queues. This example keeps everything on one thread
// to make the data flow visible without OS thread overhead.
//
// Production socket integration notes:
//   - Bind a std::net::UdpSocket on the game client port.
//   - Call platform::set_socket_send_buffer_size / set_socket_recv_buffer_size
//     after bind to expand OS buffers for burst traffic.
//   - Network loop: pump_commands -> recv_from -> process_incoming -> pop_send_raw -> send_to.
//   - Main loop  : tick(delta) -> send_packet(payload) -> recv_packet().

use relay_sdk::address::Address;
use relay_sdk::client::{ClientInner, CLIENT_STATE_CLOSED, CLIENT_STATE_OPEN};
use relay_sdk::constants::{UPDATE_TYPE_DIRECT, UPDATE_TYPE_ROUTE};
use relay_sdk::crypto::XCHACHA_KEY_BYTES;
use relay_sdk::platform;

// Number of game-loop iterations to simulate.
const ITERATIONS: usize = 5;

fn main() {
    // ── 1. Show connection type and OS socket buffer sizes ────────────────────
    //
    // In production, call these after UdpSocket::bind().
    let conn_type = platform::connection_type();
    println!("[platform] connection type: {conn_type:?}");

    // Example with a real loopback socket to show the buffer API:
    {
        use std::net::UdpSocket;
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind loopback socket");

        // Request 2 MiB send/recv buffers for burst traffic headroom.
        let sndbuf_ok = platform::set_socket_send_buffer_size(&sock, 2 * 1024 * 1024);
        let rcvbuf_ok = platform::set_socket_recv_buffer_size(&sock, 2 * 1024 * 1024);
        let actual_snd = platform::get_socket_send_buffer_size(&sock);
        let actual_rcv = platform::get_socket_recv_buffer_size(&sock);
        println!(
            "[platform] SO_SNDBUF set={sndbuf_ok}, actual={actual_snd} bytes; \
             SO_RCVBUF set={rcvbuf_ok}, actual={actual_rcv} bytes"
        );
    }

    // ── 2. Create the (ClientInner, Client) pair ──────────────────────────────
    //
    // In production ClientInner lives on the network thread; Client lives on
    // the main / game thread. They share queues through Arc<Mutex<VecDeque>>.
    let (mut inner, mut client) = ClientInner::create();

    // ── 3. Open a session ─────────────────────────────────────────────────────
    //
    // server_address  : UDP address of the game server.
    // client_secret_key: 32-byte key received from the relay-backend HTTP push.
    let server_address = Address::V4 {
        octets: [203, 0, 113, 10], // example server address
        port: 7777,
    };
    let client_secret_key = [0x42u8; XCHACHA_KEY_BYTES];

    client.open_session(server_address, client_secret_key);
    inner.pump_commands(); // network thread drains the command queue

    assert_eq!(client.state, CLIENT_STATE_OPEN);
    println!("[client] session opened -> state={}", client.state);

    // ── 4. Deliver a route update (direct, no relay hop) ──────────────────────
    //
    // In production the relay-backend sends route updates via HTTP POST once
    // per second. UPDATE_TYPE_DIRECT means the client talks straight to the
    // game server without relay indirection.
    let client_ext = Address::V4 {
        octets: [198, 51, 100, 5], // example client external address
        port: 50000,
    };
    client.route_update(
        UPDATE_TYPE_DIRECT,
        0,       // num_tokens (0 for direct)
        vec![],  // token bytes
        [0u8; 8], // magic (relay node identifier)
        client_ext,
    );
    inner.pump_commands();
    client.drain_notify();
    println!(
        "[client] route update (direct): has_relay_route={}, fallback={}",
        client.has_relay_route, client.fallback_to_direct
    );

    // ── 5. Game loop - tick, send, and receive ────────────────────────────────
    for i in 0..ITERATIONS {
        let delta_time = 0.016; // 60 Hz game loop -> ~16 ms per frame

        // Main thread: tick advances RouteManager timers.
        client.tick(delta_time);
        inner.pump_commands();

        // Main thread: queue a game payload.
        let payload = format!("frame {i}: player pos = (100, 200, 300)");
        client.send_packet(payload.as_bytes());
        inner.pump_commands();

        // Network thread: flush any outbound packets queued by ClientInner.
        // In production these go to UdpSocket::send_to(data, to).
        while let Some((to, data)) = client.pop_send_raw() {
            println!(
                "[client->net] SendRaw: {} bytes -> {to}",
                data.len()
            );
        }

        // Network thread: deliver a simulated incoming SERVER_TO_CLIENT packet.
        // (In production this comes from UdpSocket::recv_from.)
        // We skip injecting real packets here - just show the API call shape:
        let _ = inner.process_incoming(&[]); // empty -> returns None, no-op

        // Main thread: poll received game payloads.
        while let Some(received) = client.recv_packet() {
            let text = String::from_utf8_lossy(&received);
            println!("[client] recv_packet: {text}");
        }
    }

    // ── 6. Route update with relay hop (UPDATE_TYPE_ROUTE) ───────────────────
    //
    // This is what the relay-backend pushes when a relay path is available.
    // token bytes would contain encrypted RouteTokens from the backend.
    // Here we send an empty token list just to show the API shape.
    client.route_update(
        UPDATE_TYPE_ROUTE,
        0,        // num_tokens = 0 -> RouteManager will reject gracefully
        vec![],
        [1, 2, 3, 4, 5, 6, 7, 8],
        client_ext,
    );
    inner.pump_commands();
    client.drain_notify();
    println!(
        "[client] route update (route): has_relay_route={}, flags=0x{:08X}",
        client.has_relay_route, client.flags
    );

    // ── 7. Simulate receiving a valid ROUTE_RESPONSE to confirm the route ─────
    //
    // In production the relay node sends this back in response to ROUTE_REQUEST.
    // The client verifies the SHA-256 HMAC inside process_incoming before
    // calling confirm_pending_route().  Here we demonstrate the verification
    // path by building a packet with a deliberately wrong (zero) HMAC - the
    // route must NOT be confirmed.
    {
        use relay_sdk::packets::{RouteResponsePacket, ROUTE_RESPONSE_BYTES};
        let bad_hdr = [0u8; relay_sdk::route::HEADER_BYTES];
        let pkt = RouteResponsePacket {
            relay_header: bad_hdr,
        };
        let mut buf = [0u8; ROUTE_RESPONSE_BYTES];
        pkt.encode(&mut buf).unwrap();
        inner.process_incoming(&buf);
        println!(
            "[client] spoofed ROUTE_RESPONSE -> has_relay_route={} (must be false)",
            inner.route_manager.has_network_next_route()
        );
        assert!(
            !inner.route_manager.has_network_next_route(),
            "security: spoofed ROUTE_RESPONSE must not confirm route"
        );
    }

    // ── 8. Close the session ──────────────────────────────────────────────────
    client.close_session();
    inner.pump_commands();

    assert_eq!(client.state, CLIENT_STATE_CLOSED);
    assert!(!inner.session_open);
    println!("[client] session closed -> state={}", client.state);

    // ── 9. Destroy (pump returns false after Destroy command) ─────────────────
    // Dropping `client` sends Command::Destroy via Drop impl.
    drop(client);
    let alive = inner.pump_commands();
    assert!(!alive);
    println!("[client] inner.pump_commands after destroy -> alive={alive}");
}

