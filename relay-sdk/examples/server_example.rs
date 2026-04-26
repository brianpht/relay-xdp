// server_example.rs - relay-sdk game server integration walkthrough.
//
// Demonstrates the two-half pattern for the game server (final relay destination):
//   Server      - main-thread handle (command queue, notify poll)
//   ServerInner - network-thread side (session map, packet codec)
//
// Production socket integration notes:
//   - Bind a std::net::UdpSocket on the game server port.
//   - Call platform::set_socket_send_buffer_size / set_socket_recv_buffer_size
//     after bind.
//   - Network loop: pump_commands -> recv_from -> process_incoming
//                   -> push game packets -> pop_send_raw -> send_to (to relay hop).
//   - Session keys arrive from relay-backend via HTTP POST (once per player join).
//   - Each send reply routes to relay_address (last relay hop), NOT to client directly.

use relay_sdk::address::Address;
use relay_sdk::constants::SESSION_PRIVATE_KEY_BYTES;
use relay_sdk::platform;
use relay_sdk::route::{address_ipv4_bytes, stamp_packet, write_header, HEADER_BYTES};
use relay_sdk::server::{ServerInner, SERVER_STATE_CLOSED, SERVER_STATE_OPEN};
use relay_sdk::constants::{
    MAX_PACKET_BYTES, PACKET_BODY_OFFSET, PACKET_TYPE_CLIENT_TO_SERVER,
};

fn main() {
    // ── 1. Platform: check connection type and set socket buffers ─────────────
    let conn_type = platform::connection_type();
    println!("[platform] connection type: {conn_type:?}");

    {
        use std::net::UdpSocket;
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
        platform::set_socket_send_buffer_size(&sock, 4 * 1024 * 1024); // 4 MiB
        platform::set_socket_recv_buffer_size(&sock, 4 * 1024 * 1024);
        println!(
            "[platform] SO_SNDBUF={}, SO_RCVBUF={}",
            platform::get_socket_send_buffer_size(&sock),
            platform::get_socket_recv_buffer_size(&sock),
        );
    }

    // ── 2. Create the (ServerInner, Server) pair ──────────────────────────────
    let (mut inner, mut server) = ServerInner::create();
    assert_eq!(server.state(), SERVER_STATE_CLOSED);

    // ── 3. Open the server ────────────────────────────────────────────────────
    let bind_address = Address::V4 {
        octets: [0, 0, 0, 0], // 0.0.0.0 = all interfaces
        port: 7777,
    };
    server.open(bind_address);
    inner.pump_commands();
    assert_eq!(server.state(), SERVER_STATE_OPEN);
    println!("[server] opened on port 7777");

    // ── 4. Register a session ─────────────────────────────────────────────────
    //
    // In production the relay-backend calls your HTTP endpoint with:
    //   session_id         - unique 64-bit session identifier
    //   session_version    - increments on reconnect to invalidate old keys
    //   session_private_key - 32-byte XChaCha20-Poly1305 key from RouteToken
    //   relay_address      - last relay hop (SERVER_TO_CLIENT packets go here)
    let session_id: u64 = 0xDEAD_CAFE_1234_5678;
    let session_version: u8 = 1;
    let session_private_key = [0x55u8; SESSION_PRIVATE_KEY_BYTES];
    let relay_address = Address::V4 {
        octets: [10, 0, 0, 1], // last relay hop
        port: 4000,
    };

    server.register_session(
        session_id,
        session_version,
        session_private_key,
        relay_address,
    );
    inner.pump_commands();
    server.drain_notify(); // applies SessionRegistered -> increments num_sessions
    assert_eq!(server.num_sessions, 1);
    println!("[server] session registered: id=0x{session_id:016X}, count={}", server.num_sessions);

    // ── 5. Receive a CLIENT_TO_SERVER packet ──────────────────────────────────
    //
    // Build a well-formed CLIENT_TO_SERVER packet and feed it to process_incoming.
    // In production this comes from UdpSocket::recv_from.
    let game_payload = b"player moved to (42, 100, 7)";
    let seq: u64 = 1;
    let from_addr = Address::V4 {
        octets: [198, 51, 100, 5],
        port: 50001,
    };

    let buf = build_client_to_server(
        game_payload,
        seq,
        session_id,
        session_version,
        &session_private_key,
        &from_addr,
        &relay_address,
    );

    let result = inner.process_incoming(&buf);
    assert!(result.is_some(), "valid CLIENT_TO_SERVER must be extracted");
    let (sid, payload) = result.unwrap();
    assert_eq!(sid, session_id);
    assert_eq!(payload.as_slice(), game_payload.as_slice());
    println!(
        "[server] process_incoming OK: session_id=0x{sid:016X}, payload=\"{}\"",
        String::from_utf8_lossy(&payload)
    );

    // The same packet is also pushed to the notify queue.
    // The game application drains it via server.recv_packet():
    if let Some((sid2, payload2)) = server.recv_packet() {
        println!(
            "[server] recv_packet: id=0x{sid2:016X}, payload=\"{}\"",
            String::from_utf8_lossy(&payload2)
        );
    }

    // ── 6. Replay protection: duplicate packet must be rejected ───────────────
    let replay_result = inner.process_incoming(&buf);
    assert!(
        replay_result.is_none(),
        "replay protection: duplicate sequence must be rejected"
    );
    println!("[server] replay protection OK: duplicate sequence rejected");

    // ── 7. Send a SERVER_TO_CLIENT reply ──────────────────────────────────────
    //
    // server.send_packet enqueues a Command::SendPacket.
    // ServerInner.send_packet_inner builds the SERVER_TO_CLIENT packet,
    // stamps pittle/chonkle, and pushes Notify::SendRaw.
    let reply = b"server ack: position accepted";
    let magic = [1u8, 2, 3, 4, 5, 6, 7, 8];
    server.send_packet(session_id, reply, magic, from_addr);
    inner.pump_commands();

    // Pop the outbound packet (in production: UdpSocket::send_to(data, to)).
    if let Some((to, data)) = server.pop_send_raw() {
        println!(
            "[server] pop_send_raw: {} bytes -> {to} (relay hop)",
            data.len()
        );
        // Verify the packet type byte is SERVER_TO_CLIENT (0x04).
        assert_eq!(data[0], relay_sdk::constants::PACKET_TYPE_SERVER_TO_CLIENT);
    } else {
        println!("[server] no outbound packet (send may have been queued without a registered session send path)");
    }

    // ── 8. Check for send errors ──────────────────────────────────────────────
    //
    // Oversized payloads push Notify::SendError instead of Notify::SendRaw.
    let huge_payload = vec![0u8; MAX_PACKET_BYTES + 1];
    server.send_packet(session_id, &huge_payload, magic, from_addr);
    inner.pump_commands();
    server.drain_notify(); // applies SendError -> sets last_send_error
    if let Some((err_sid, reason)) = server.last_send_error {
        println!("[server] send error for session 0x{err_sid:016X}: {reason}");
    }
    server.clear_last_send_error();
    assert!(server.last_send_error.is_none());

    // ── 9. Expire the session ─────────────────────────────────────────────────
    server.expire_session(session_id);
    inner.pump_commands();
    server.drain_notify(); // applies SessionExpired -> decrements num_sessions
    assert_eq!(server.num_sessions, 0);
    assert!(inner.session(session_id).is_none());
    println!("[server] session expired: count={}", server.num_sessions);

    // ── 10. Close and destroy ─────────────────────────────────────────────────
    server.close();
    inner.pump_commands();
    assert_eq!(server.state(), SERVER_STATE_CLOSED);
    println!("[server] closed -> state={}", server.state());

    drop(server); // sends Command::Destroy
    let alive = inner.pump_commands();
    assert!(!alive);
    println!("[server] inner.pump_commands after destroy -> alive={alive}");
}

// ── Helper: build a well-formed CLIENT_TO_SERVER packet ──────────────────────

fn build_client_to_server(
    payload: &[u8],
    seq: u64,
    session_id: u64,
    session_version: u8,
    key: &[u8; SESSION_PRIVATE_KEY_BYTES],
    from: &Address,
    to: &Address,
) -> Vec<u8> {
    let total = PACKET_BODY_OFFSET + HEADER_BYTES + payload.len();
    let mut buf = vec![0u8; total];
    buf[0] = PACKET_TYPE_CLIENT_TO_SERVER;

    let header_slice: &mut [u8; HEADER_BYTES] =
        (&mut buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES])
            .try_into()
            .expect("infallible");
    write_header(
        PACKET_TYPE_CLIENT_TO_SERVER,
        seq,
        session_id,
        session_version,
        key,
        header_slice,
    );
    buf[PACKET_BODY_OFFSET + HEADER_BYTES..].copy_from_slice(payload);

    let from_bytes = address_ipv4_bytes(from);
    let to_bytes = match to {
        Address::V4 { octets, .. } => *octets,
        _ => [0u8; 4],
    };
    stamp_packet(&mut buf, &[0u8; 8], &from_bytes, &to_bytes);
    buf
}

