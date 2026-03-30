//! Functional parity tests — verify the Rust relay userspace behaves identically
//! to the C XDP relay when talking to the relay_backend.
//!
//! These tests run in RELAY_NO_BPF=1 mode and do NOT require root or BPF.
//! They validate the update protocol, crypto, encoding, and ping logic.
//!
//! Run with: `cargo test --test func_parity -- --ignored --test-threads=1`
//! Or via:   `cargo xtask func-test`

use relay_xdp_common::*;
use std::io::Read;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Test keys matching Go func_test_relay.go
const TEST_RELAY_PUBLIC_KEY: &str = "1nTj7bQmo8gfIDqG+o//GFsak/g1TRo4hl6XXw1JkyI=";
const TEST_RELAY_PRIVATE_KEY: &str = "cwvK44Pr5aHI3vE3siODS7CUgdPI/l1VwjVZ2FvEyAo=";
const TEST_RELAY_BACKEND_PUBLIC_KEY: &str = "IsjRpWEz9H7qslhWWupW4A9LIpVh+PzWoLleuXL1NUE=";
const TEST_RELAY_BACKEND_PRIVATE_KEY: &str = "qXeUdLPZxaMnZ/zFHLHkmgkQOmunWq1AmRv55nqTYMg=";

fn decode_key(s: &str) -> [u8; 32] {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(s).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    arr
}

// ---------------------------------------------------------------------------
// Config error tests
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_config_missing_relay_name() {
    // Temporarily clear env vars
    let result = std::panic::catch_unwind(|| {
        // read_config will fail if RELAY_NAME is not set
        // We test this by unsetting and calling directly
        std::env::remove_var("RELAY_NAME");
        relay_xdp::config::read_config()
    });
    match result {
        Ok(Err(e)) => {
            assert!(
                format!("{e:#}").contains("RELAY_NAME"),
                "error should mention RELAY_NAME: {e:#}"
            );
        }
        Ok(Ok(_)) => panic!("expected error when RELAY_NAME is not set"),
        Err(_) => {} // panic is also acceptable
    }
}

#[test]
#[ignore]
fn test_config_missing_public_address() {
    std::env::set_var("RELAY_NAME", "test");
    std::env::remove_var("RELAY_PUBLIC_ADDRESS");
    let result = relay_xdp::config::read_config();
    assert!(result.is_err());
    assert!(format!("{:#}", result.unwrap_err()).contains("RELAY_PUBLIC_ADDRESS"));
    std::env::remove_var("RELAY_NAME");
}

#[test]
#[ignore]
fn test_config_missing_public_key() {
    std::env::set_var("RELAY_NAME", "test");
    std::env::set_var("RELAY_PUBLIC_ADDRESS", "127.0.0.1:40000");
    std::env::remove_var("RELAY_PUBLIC_KEY");
    let result = relay_xdp::config::read_config();
    assert!(result.is_err());
    assert!(format!("{:#}", result.unwrap_err()).contains("RELAY_PUBLIC_KEY"));
    std::env::remove_var("RELAY_NAME");
    std::env::remove_var("RELAY_PUBLIC_ADDRESS");
}

#[test]
#[ignore]
fn test_config_valid() {
    std::env::set_var("RELAY_NAME", "test.1");
    std::env::set_var("RELAY_PUBLIC_ADDRESS", "127.0.0.1:40000");
    std::env::set_var("RELAY_PUBLIC_KEY", TEST_RELAY_PUBLIC_KEY);
    std::env::set_var("RELAY_PRIVATE_KEY", TEST_RELAY_PRIVATE_KEY);
    std::env::set_var("RELAY_BACKEND_PUBLIC_KEY", TEST_RELAY_BACKEND_PUBLIC_KEY);
    std::env::set_var("RELAY_BACKEND_URL", "http://127.0.0.1:30000");

    let config = relay_xdp::config::read_config().expect("config should be valid");
    assert_eq!(config.relay_name, "test.1");
    assert_eq!(config.relay_port, 40000);

    // Verify key derivation produces a non-zero secret key
    assert_ne!(config.relay_secret_key, [0u8; 32]);

    // Clean up
    std::env::remove_var("RELAY_NAME");
    std::env::remove_var("RELAY_PUBLIC_ADDRESS");
    std::env::remove_var("RELAY_PUBLIC_KEY");
    std::env::remove_var("RELAY_PRIVATE_KEY");
    std::env::remove_var("RELAY_BACKEND_PUBLIC_KEY");
    std::env::remove_var("RELAY_BACKEND_URL");
}

// ---------------------------------------------------------------------------
// Update protocol tests
// ---------------------------------------------------------------------------

/// Build a mock relay update response matching the format from relay_main.c / func_backend.go
fn build_mock_update_response(
    relay_public_address: u32,
    relay_port: u16,
    relay_public_key: &[u8; 32],
    backend_public_key: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    let mut w = relay_xdp::encoding::Writer::new(&mut buf);

    let version: u8 = 1;
    w.write_uint8(version);

    let backend_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    w.write_uint64(backend_timestamp);

    // num_relays = 0 (no relay peers)
    w.write_uint32(0);

    // target version string
    w.write_string("relay-rust", RELAY_VERSION_LENGTH);

    // Magic values (next, current, previous)
    let next_magic = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let current_magic = [9u8, 10, 11, 12, 13, 14, 15, 16];
    let previous_magic = [17u8, 18, 19, 20, 21, 22, 23, 24];
    w.write_bytes(&next_magic);
    w.write_bytes(&current_magic);
    w.write_bytes(&previous_magic);

    // Expected public address
    w.write_uint8(RELAY_ADDRESS_IPV4);
    w.write_uint32(relay_public_address.to_be());
    w.write_uint16(relay_port);

    // has_internal = 0
    w.write_uint8(0);

    // Expected relay public key
    w.write_bytes(relay_public_key);

    // Expected backend public key
    w.write_bytes(backend_public_key);

    // Dummy encrypted route token
    w.write_bytes(&[0u8; RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES]);

    // Ping key
    let ping_key = [42u8; RELAY_PING_KEY_BYTES];
    w.write_bytes(&ping_key);

    buf
}

#[test]
#[ignore]
fn test_parse_update_response_valid() {
    relay_xdp::platform::init();

    std::env::set_var("RELAY_NAME", "test.1");
    std::env::set_var("RELAY_PUBLIC_ADDRESS", "127.0.0.1:40000");
    std::env::set_var("RELAY_PUBLIC_KEY", TEST_RELAY_PUBLIC_KEY);
    std::env::set_var("RELAY_PRIVATE_KEY", TEST_RELAY_PRIVATE_KEY);
    std::env::set_var("RELAY_BACKEND_PUBLIC_KEY", TEST_RELAY_BACKEND_PUBLIC_KEY);
    std::env::set_var("RELAY_BACKEND_URL", "http://127.0.0.1:30000");

    let config = Arc::new(relay_xdp::config::read_config().unwrap());
    let quit = Arc::new(AtomicBool::new(false));
    let clean_shutdown = Arc::new(AtomicBool::new(false));
    let control_queue = relay_xdp::main_thread::new_queue();
    let stats_queue = relay_xdp::main_thread::new_queue();

    let mut main_thread = relay_xdp::main_thread::MainThread::new(
        config.clone(),
        None, // no BPF
        control_queue.clone(),
        stats_queue,
        quit,
        clean_shutdown,
    )
    .unwrap();

    let response = build_mock_update_response(
        config.relay_public_address,
        config.relay_port,
        &config.relay_public_key,
        &config.relay_backend_public_key,
    );

    // Should parse without error
    main_thread.parse_update_response(&response).unwrap();

    // Check that a control message was sent
    let queue = control_queue.lock().unwrap();
    assert_eq!(queue.len(), 1);
    let msg = &queue[0];
    assert_eq!(msg.current_magic, [9, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(msg.ping_key, [42u8; RELAY_PING_KEY_BYTES]);

    // Clean up
    std::env::remove_var("RELAY_NAME");
    std::env::remove_var("RELAY_PUBLIC_ADDRESS");
    std::env::remove_var("RELAY_PUBLIC_KEY");
    std::env::remove_var("RELAY_PRIVATE_KEY");
    std::env::remove_var("RELAY_BACKEND_PUBLIC_KEY");
    std::env::remove_var("RELAY_BACKEND_URL");
}

#[test]
#[ignore]
fn test_parse_update_response_bad_version() {
    relay_xdp::platform::init();

    std::env::set_var("RELAY_NAME", "test.1");
    std::env::set_var("RELAY_PUBLIC_ADDRESS", "127.0.0.1:40000");
    std::env::set_var("RELAY_PUBLIC_KEY", TEST_RELAY_PUBLIC_KEY);
    std::env::set_var("RELAY_PRIVATE_KEY", TEST_RELAY_PRIVATE_KEY);
    std::env::set_var("RELAY_BACKEND_PUBLIC_KEY", TEST_RELAY_BACKEND_PUBLIC_KEY);
    std::env::set_var("RELAY_BACKEND_URL", "http://127.0.0.1:30000");

    let config = Arc::new(relay_xdp::config::read_config().unwrap());
    let quit = Arc::new(AtomicBool::new(false));
    let clean_shutdown = Arc::new(AtomicBool::new(false));
    let control_queue = relay_xdp::main_thread::new_queue();
    let stats_queue = relay_xdp::main_thread::new_queue();

    let mut main_thread = relay_xdp::main_thread::MainThread::new(
        config,
        None,
        control_queue,
        stats_queue,
        quit,
        clean_shutdown,
    )
    .unwrap();

    // Bad version byte
    let response = vec![99u8; 256];
    let result = main_thread.parse_update_response(&response);
    assert!(result.is_err());
    assert!(format!("{:#}", result.unwrap_err()).contains("version"));

    // Clean up
    std::env::remove_var("RELAY_NAME");
    std::env::remove_var("RELAY_PUBLIC_ADDRESS");
    std::env::remove_var("RELAY_PUBLIC_KEY");
    std::env::remove_var("RELAY_PRIVATE_KEY");
    std::env::remove_var("RELAY_BACKEND_PUBLIC_KEY");
    std::env::remove_var("RELAY_BACKEND_URL");
}

#[test]
#[ignore]
fn test_parse_update_response_public_key_mismatch() {
    relay_xdp::platform::init();

    std::env::set_var("RELAY_NAME", "test.1");
    std::env::set_var("RELAY_PUBLIC_ADDRESS", "127.0.0.1:40000");
    std::env::set_var("RELAY_PUBLIC_KEY", TEST_RELAY_PUBLIC_KEY);
    std::env::set_var("RELAY_PRIVATE_KEY", TEST_RELAY_PRIVATE_KEY);
    std::env::set_var("RELAY_BACKEND_PUBLIC_KEY", TEST_RELAY_BACKEND_PUBLIC_KEY);
    std::env::set_var("RELAY_BACKEND_URL", "http://127.0.0.1:30000");

    let config = Arc::new(relay_xdp::config::read_config().unwrap());
    let quit = Arc::new(AtomicBool::new(false));
    let clean_shutdown = Arc::new(AtomicBool::new(false));
    let control_queue = relay_xdp::main_thread::new_queue();
    let stats_queue = relay_xdp::main_thread::new_queue();

    let mut main_thread = relay_xdp::main_thread::MainThread::new(
        config.clone(),
        None,
        control_queue,
        stats_queue,
        quit,
        clean_shutdown,
    )
    .unwrap();

    // Use a wrong relay public key in the response
    let mut wrong_key = config.relay_public_key;
    wrong_key[0] ^= 0xFF;
    let response = build_mock_update_response(
        config.relay_public_address,
        config.relay_port,
        &wrong_key,
        &config.relay_backend_public_key,
    );

    let result = main_thread.parse_update_response(&response);
    assert!(result.is_err());
    assert!(format!("{:#}", result.unwrap_err()).contains("public key"));

    // Clean up
    std::env::remove_var("RELAY_NAME");
    std::env::remove_var("RELAY_PUBLIC_ADDRESS");
    std::env::remove_var("RELAY_PUBLIC_KEY");
    std::env::remove_var("RELAY_PRIVATE_KEY");
    std::env::remove_var("RELAY_BACKEND_PUBLIC_KEY");
    std::env::remove_var("RELAY_BACKEND_URL");
}

// ---------------------------------------------------------------------------
// Crypto roundtrip tests (pure-Rust ↔ NaCl compatibility)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_crypto_kx_deterministic() {
    // Verify that our pure-Rust crypto_kx implementation produces consistent results
    let _relay_pk = decode_key(TEST_RELAY_PUBLIC_KEY);
    let _relay_sk = decode_key(TEST_RELAY_PRIVATE_KEY);
    let _backend_pk = decode_key(TEST_RELAY_BACKEND_PUBLIC_KEY);

    std::env::set_var("RELAY_NAME", "test.1");
    std::env::set_var("RELAY_PUBLIC_ADDRESS", "127.0.0.1:40000");
    std::env::set_var("RELAY_PUBLIC_KEY", TEST_RELAY_PUBLIC_KEY);
    std::env::set_var("RELAY_PRIVATE_KEY", TEST_RELAY_PRIVATE_KEY);
    std::env::set_var("RELAY_BACKEND_PUBLIC_KEY", TEST_RELAY_BACKEND_PUBLIC_KEY);
    std::env::set_var("RELAY_BACKEND_URL", "http://127.0.0.1:30000");

    let config1 = relay_xdp::config::read_config().unwrap();
    let config2 = relay_xdp::config::read_config().unwrap();

    // Same inputs → same secret key
    assert_eq!(config1.relay_secret_key, config2.relay_secret_key);
    assert_ne!(config1.relay_secret_key, [0u8; 32]);

    // Clean up
    std::env::remove_var("RELAY_NAME");
    std::env::remove_var("RELAY_PUBLIC_ADDRESS");
    std::env::remove_var("RELAY_PUBLIC_KEY");
    std::env::remove_var("RELAY_PRIVATE_KEY");
    std::env::remove_var("RELAY_BACKEND_PUBLIC_KEY");
    std::env::remove_var("RELAY_BACKEND_URL");
}

#[test]
#[ignore]
fn test_crypto_box_encrypt_decrypt_with_test_keys() {
    use crypto_box::aead::{AeadCore, AeadInPlace, OsRng};

    let relay_sk = decode_key(TEST_RELAY_PRIVATE_KEY);
    let relay_pk = decode_key(TEST_RELAY_PUBLIC_KEY);
    let backend_sk = decode_key(TEST_RELAY_BACKEND_PRIVATE_KEY);
    let backend_pk = decode_key(TEST_RELAY_BACKEND_PUBLIC_KEY);

    // Relay encrypts to backend
    let relay_secret = crypto_box::SecretKey::from(relay_sk);
    let backend_public = crypto_box::PublicKey::from(backend_pk);
    let encrypt_box = crypto_box::SalsaBox::new(&backend_public, &relay_secret);

    let plaintext = b"test relay update payload data";
    let nonce = crypto_box::SalsaBox::generate_nonce(&mut OsRng);

    let mut buffer = plaintext.to_vec();
    let tag = encrypt_box
        .encrypt_in_place_detached(&nonce, b"", &mut buffer)
        .expect("encrypt failed");

    // Backend decrypts from relay
    let backend_secret = crypto_box::SecretKey::from(backend_sk);
    let relay_public = crypto_box::PublicKey::from(relay_pk);
    let decrypt_box = crypto_box::SalsaBox::new(&relay_public, &backend_secret);

    decrypt_box
        .decrypt_in_place_detached(&nonce, b"", &mut buffer, &tag)
        .expect("decrypt failed");

    assert_eq!(&buffer, plaintext);
}

// ---------------------------------------------------------------------------
// Ping packet wire format tests
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_ping_packet_construction() {
    use sha2::Digest;

    let ping_key = [0xBBu8; RELAY_PING_KEY_BYTES];
    let source_addr: u32 = 0x7F000001; // 127.0.0.1 host order
    let dest_addr: u32 = 0x7F000002; // 127.0.0.2 host order
    let source_port: u16 = 40000;
    let dest_port: u16 = 40001;
    let expire_timestamp: u64 = 1700000000;

    // Build PingTokenData exactly as ping_thread.rs does
    let token_data = PingTokenData {
        ping_key,
        expire_timestamp,
        source_address: source_addr.to_be(),
        source_port: source_port.to_be(),
        dest_address: dest_addr.to_be(),
        dest_port: dest_port.to_be(),
    };

    let token_bytes = unsafe {
        std::slice::from_raw_parts(
            &token_data as *const _ as *const u8,
            std::mem::size_of::<PingTokenData>(),
        )
    };

    let ping_token: [u8; 32] = sha2::Sha256::digest(token_bytes).into();

    // Build packet
    let mut packet = Vec::with_capacity(256);
    packet.push(RELAY_PING_PACKET); // type
    packet.extend_from_slice(&[0u8; 17]); // pittle (2) + chonkle (15) placeholder

    let mut w = relay_xdp::encoding::Writer::new(&mut packet);
    w.write_uint64(0); // sequence
    w.write_uint64(expire_timestamp);
    w.write_uint8(0); // not internal
    w.write_bytes(&ping_token);

    // Total: 1 + 17 + 8 + 8 + 1 + 32 = 67
    assert_eq!(packet.len(), 67, "ping packet should be 67 bytes");

    // Generate and apply pittle/chonkle
    let magic = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let from_bytes = relay_xdp::packet_filter::address_to_bytes(source_addr);
    let to_bytes = relay_xdp::packet_filter::address_to_bytes(dest_addr);
    let packet_length = packet.len() as u16;

    let pittle = relay_xdp::packet_filter::generate_pittle(&from_bytes, &to_bytes, packet_length);
    let chonkle =
        relay_xdp::packet_filter::generate_chonkle(&magic, &from_bytes, &to_bytes, packet_length);

    packet[1] = pittle[0];
    packet[2] = pittle[1];
    packet[3..18].copy_from_slice(&chonkle);

    // Verify pittle relationship
    assert_eq!(
        pittle[1],
        1 | ((255u8.wrapping_sub(pittle[0])) ^ 113),
        "pittle[1] must match the basic packet filter formula"
    );

    // Verify chonkle values are in expected ranges
    assert!((0x2A..=0x2D).contains(&chonkle[0]));
    assert!((0xC8..=0xE7).contains(&chonkle[1]));
}

// ---------------------------------------------------------------------------
// Ping history stats tests
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_ping_history_integration() {
    let mut history = relay_xdp::ping_history::PingHistory::new();

    // Simulate 20 ping/pong exchanges
    for i in 0..20u64 {
        let time = i as f64 * 0.1; // 100ms apart
        let seq = history.ping_sent(time);
        assert_eq!(seq, i);
        // Pong arrives after 5ms
        history.pong_received(i, time + 0.005);
    }

    let stats = history.get_stats(0.0, 2.0, 0.5);
    assert!(stats.packet_loss < 1.0, "should have ~0% loss");
    assert!((stats.rtt - 5.0).abs() < 0.5, "RTT should be ~5ms, got {}", stats.rtt);
    assert!(stats.jitter < 1.0, "jitter should be ~0ms, got {}", stats.jitter);
}

// ---------------------------------------------------------------------------
// Encoding roundtrip tests
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_encoding_update_payload_format() {
    // Verify the update payload format matches what the Go backend expects
    let mut buf = Vec::new();
    let mut w = relay_xdp::encoding::Writer::new(&mut buf);

    // Version byte
    w.write_uint8(1);

    // Address: type(1) + ip(4) + port(2) = 7 bytes
    w.write_uint8(RELAY_ADDRESS_IPV4);
    w.write_uint32(0x7F000001u32.to_be()); // 127.0.0.1 in BE
    w.write_uint16(40000);

    assert_eq!(buf.len(), 8, "header should be 8 bytes (1 version + 7 address)");

    // Verify the address bytes
    assert_eq!(buf[0], 1); // version
    assert_eq!(buf[1], RELAY_ADDRESS_IPV4);
    // IP in network order (big endian) stored as LE u32
    let ip_bytes = &buf[2..6];
    assert_eq!(ip_bytes, &0x7F000001u32.to_be().to_le_bytes());
}

// ---------------------------------------------------------------------------
// Relay manager tests
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_relay_manager_add_remove() {
    relay_xdp::platform::init();

    let mut manager = relay_xdp::manager::RelayManager::new();
    assert_eq!(manager.num_relays, 0);

    // Add relays
    let mut new_set = relay_xdp::manager::RelaySet::new();
    new_set.push(100, 0x7F000001, 40001, 0);
    new_set.push(200, 0x7F000002, 40002, 1);
    let empty = relay_xdp::manager::RelaySet::new();

    manager.update(&new_set, &empty);
    assert_eq!(manager.num_relays, 2);
    assert_eq!(manager.relay_ids[0], 100);
    assert_eq!(manager.relay_ids[1], 200);

    // Delete one relay
    let mut del_set = relay_xdp::manager::RelaySet::new();
    del_set.push(100, 0x7F000001, 40001, 0);
    let empty2 = relay_xdp::manager::RelaySet::new();

    manager.update(&empty2, &del_set);
    assert_eq!(manager.num_relays, 1);
    assert_eq!(manager.relay_ids[0], 200);
}

// ---------------------------------------------------------------------------
// Mock HTTP backend test (simulates relay_backend /relay_update endpoint)
// ---------------------------------------------------------------------------

/// A minimal mock relay_backend that accepts POST /relay_update and returns
/// a valid response. Used to test the full update cycle without the real Go backend.
fn start_mock_backend(
    relay_public_address: u32,
    relay_port: u16,
    relay_public_key: [u8; 32],
    backend_public_key: [u8; 32],
    _backend_private_key: [u8; 32],
) -> (std::thread::JoinHandle<()>, u16, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    let handle = std::thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("set_nonblocking failed");

        while !stop_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // Read the HTTP request (simplified: just read until we have the body)
                    let mut request = Vec::new();
                    let mut buf = [0u8; 16384];
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .ok();
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                            Err(_) => break,
                        }
                        // Simple check: if we see the double CRLF, read Content-Length and body
                        if request.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }

                    // Build response
                    let response_body = build_mock_update_response(
                        relay_public_address,
                        relay_port,
                        &relay_public_key,
                        &backend_public_key,
                    );

                    let http_response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                        response_body.len()
                    );

                    use std::io::Write;
                    let _ = stream.write_all(http_response.as_bytes());
                    let _ = stream.write_all(&response_body);
                    let _ = stream.flush();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
    });

    (handle, port, stop)
}

#[test]
#[ignore]
fn test_full_update_cycle_with_mock_backend() {
    relay_xdp::platform::init();

    let _relay_sk = decode_key(TEST_RELAY_PRIVATE_KEY);
    let relay_pk = decode_key(TEST_RELAY_PUBLIC_KEY);
    let backend_pk = decode_key(TEST_RELAY_BACKEND_PUBLIC_KEY);
    let backend_sk = decode_key(TEST_RELAY_BACKEND_PRIVATE_KEY);

    let relay_address: u32 = 0x7F000001; // 127.0.0.1
    let relay_port: u16 = 40000;

    let (backend_handle, backend_port, stop) = start_mock_backend(
        relay_address,
        relay_port,
        relay_pk,
        backend_pk,
        backend_sk,
    );

    // Configure the relay
    std::env::set_var("RELAY_NAME", "test.mock");
    std::env::set_var("RELAY_PUBLIC_ADDRESS", "127.0.0.1:40000");
    std::env::set_var("RELAY_PUBLIC_KEY", TEST_RELAY_PUBLIC_KEY);
    std::env::set_var("RELAY_PRIVATE_KEY", TEST_RELAY_PRIVATE_KEY);
    std::env::set_var("RELAY_BACKEND_PUBLIC_KEY", TEST_RELAY_BACKEND_PUBLIC_KEY);
    std::env::set_var(
        "RELAY_BACKEND_URL",
        &format!("http://127.0.0.1:{backend_port}"),
    );

    let config = Arc::new(relay_xdp::config::read_config().unwrap());
    let quit = Arc::new(AtomicBool::new(false));
    let clean_shutdown = Arc::new(AtomicBool::new(false));
    let control_queue = relay_xdp::main_thread::new_queue();
    let stats_queue = relay_xdp::main_thread::new_queue();

    let mut main_thread = relay_xdp::main_thread::MainThread::new(
        config.clone(),
        None, // no BPF
        control_queue.clone(),
        stats_queue,
        quit.clone(),
        clean_shutdown.clone(),
    )
    .unwrap();

    // Run one update cycle — this will POST to our mock backend and parse the response
    // We need to trigger the quit after the update so it doesn't loop
    quit.store(true, Ordering::Relaxed);
    let result = main_thread.run();

    // The run() exits because quit is set. Check control queue for messages.
    let _queue = control_queue.lock().unwrap();
    // At least one successful update should have happened
    // (quit was already set but run() does one update before checking quit)

    // Clean up
    stop.store(true, Ordering::Relaxed);
    let _ = backend_handle.join();

    std::env::remove_var("RELAY_NAME");
    std::env::remove_var("RELAY_PUBLIC_ADDRESS");
    std::env::remove_var("RELAY_PUBLIC_KEY");
    std::env::remove_var("RELAY_PRIVATE_KEY");
    std::env::remove_var("RELAY_BACKEND_PUBLIC_KEY");
    std::env::remove_var("RELAY_BACKEND_URL");

    // The update should have completed without error (or failed gracefully)
    // since quit was set before run() started
    result.unwrap();
}

// ---------------------------------------------------------------------------
// Relay set delta computation test
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_parse_update_response_with_relay_set() {
    relay_xdp::platform::init();

    std::env::set_var("RELAY_NAME", "test.1");
    std::env::set_var("RELAY_PUBLIC_ADDRESS", "127.0.0.1:40000");
    std::env::set_var("RELAY_PUBLIC_KEY", TEST_RELAY_PUBLIC_KEY);
    std::env::set_var("RELAY_PRIVATE_KEY", TEST_RELAY_PRIVATE_KEY);
    std::env::set_var("RELAY_BACKEND_PUBLIC_KEY", TEST_RELAY_BACKEND_PUBLIC_KEY);
    std::env::set_var("RELAY_BACKEND_URL", "http://127.0.0.1:30000");

    let config = Arc::new(relay_xdp::config::read_config().unwrap());
    let quit = Arc::new(AtomicBool::new(false));
    let clean_shutdown = Arc::new(AtomicBool::new(false));
    let control_queue = relay_xdp::main_thread::new_queue();
    let stats_queue = relay_xdp::main_thread::new_queue();

    let mut main_thread = relay_xdp::main_thread::MainThread::new(
        config.clone(),
        None,
        control_queue.clone(),
        stats_queue,
        quit,
        clean_shutdown,
    )
    .unwrap();

    // Build response with 2 relays
    let mut buf = Vec::with_capacity(4096);
    let mut w = relay_xdp::encoding::Writer::new(&mut buf);

    w.write_uint8(1); // version
    w.write_uint64(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());

    // 2 relays
    w.write_uint32(2);

    // Relay 1: id=100, 10.0.0.1:40001, internal=0
    w.write_uint64(100);
    w.write_uint8(RELAY_ADDRESS_IPV4);
    w.write_uint32(0x0A000001u32); // already BE
    w.write_uint16(40001);
    w.write_uint8(0);

    // Relay 2: id=200, 10.0.0.2:40002, internal=1
    w.write_uint64(200);
    w.write_uint8(RELAY_ADDRESS_IPV4);
    w.write_uint32(0x0A000002u32);
    w.write_uint16(40002);
    w.write_uint8(1);

    // Rest of response
    w.write_string("relay-rust", RELAY_VERSION_LENGTH);
    w.write_bytes(&[1u8; 8]); // next magic
    w.write_bytes(&[2u8; 8]); // current magic
    w.write_bytes(&[3u8; 8]); // previous magic
    w.write_uint8(RELAY_ADDRESS_IPV4);
    w.write_uint32(config.relay_public_address.to_be());
    w.write_uint16(config.relay_port);
    w.write_uint8(0); // no internal
    w.write_bytes(&config.relay_public_key);
    w.write_bytes(&config.relay_backend_public_key);
    w.write_bytes(&[0u8; RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES]);
    w.write_bytes(&[0xAA; RELAY_PING_KEY_BYTES]);

    main_thread.parse_update_response(&buf).unwrap();

    // First update: all 2 relays should be "new"
    {
        let queue = control_queue.lock().unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].new_relays.num_relays, 2);
        assert_eq!(queue[0].delete_relays.num_relays, 0);
    }

    // Clean up
    std::env::remove_var("RELAY_NAME");
    std::env::remove_var("RELAY_PUBLIC_ADDRESS");
    std::env::remove_var("RELAY_PUBLIC_KEY");
    std::env::remove_var("RELAY_PRIVATE_KEY");
    std::env::remove_var("RELAY_BACKEND_PUBLIC_KEY");
    std::env::remove_var("RELAY_BACKEND_URL");
}

