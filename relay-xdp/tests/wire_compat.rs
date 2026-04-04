//! Wire-compatibility tests: verify struct layouts, sizes, and field offsets
//! match the C implementation in `relay_shared.h`.

use relay_xdp_common::*;
use std::mem::{offset_of, size_of};

// -------------------------------------------------------
// Struct size assertions (must match C struct sizes on x86_64 Linux)
// -------------------------------------------------------

#[test]
fn test_relay_config_size() {
    // C: relay_config (no packing)
    // u32 dedicated(4) + u32 relay_public_address(4) + u32 relay_internal_address(4)
    // + u16 relay_port(2) + u8[32] + u8[32] + u8[6] + u8(1) + 1 padding = 88
    assert_eq!(size_of::<RelayConfig>(), 88);
}

#[test]
fn test_relay_state_size() {
    // C: relay_state
    // u64(8) + u8[8] + u8[8] + u8[8] + u8[32] = 64
    assert_eq!(size_of::<RelayState>(), 64);
}

#[test]
fn test_relay_stats_size() {
    // C: relay_stats
    // u64[150] = 1200
    assert_eq!(size_of::<RelayStats>(), 1200);
}

#[test]
fn test_session_data_size() {
    // C: session_data (no packing)
    // u8[32] + u64(8) + u64(8) + u64(8) + u64(8) + u64(8) + u64(8)
    // + u32(4) + u32(4) + u32(4) + u32(4) + u16(2) + u16(2) + u8(1) + u8(1) + u8(1) + u8(1) = 104
    assert_eq!(size_of::<SessionData>(), 104);
}

#[test]
fn test_session_key_size() {
    // C: session_key
    // u64(8) + u64(8) = 16
    assert_eq!(size_of::<SessionKey>(), 16);
}

#[test]
fn test_whitelist_key_size() {
    // C: whitelist_key
    // u32(4) + u32(4) = 8
    assert_eq!(size_of::<WhitelistKey>(), 8);
}

#[test]
fn test_whitelist_value_size() {
    // C: whitelist_value
    // u64(8) + u8[6] + u8[6] = 20, padded to 24 (align 8)
    assert_eq!(size_of::<WhitelistValue>(), 24);
}

#[test]
fn test_ping_token_data_size() {
    // C: ping_token_data (#pragma pack(push, 1))
    // u8[32] + u64(8) + u32(4) + u32(4) + u16(2) + u16(2) = 52
    assert_eq!(size_of::<PingTokenData>(), 52);
}

#[test]
fn test_header_data_size() {
    // C: header_data (#pragma pack(push, 1))
    // u8[32] + u8(1) + u64(8) + u64(8) + u8(1) = 50
    assert_eq!(size_of::<HeaderData>(), 50);
}

#[test]
fn test_route_token_size() {
    // C: route_token (#pragma pack(push, 1))
    // u8[32] + u64(8) + u64(8) + u32(4) + u32(4) + u32(4) + u32(4) + u16(2) + u16(2) + u8(1) + u8(1) + u8(1) = 71
    assert_eq!(size_of::<RouteToken>(), RELAY_ROUTE_TOKEN_BYTES);
    assert_eq!(size_of::<RouteToken>(), 71);
}

#[test]
fn test_continue_token_size() {
    // C: continue_token (#pragma pack(push, 1))
    // u64(8) + u64(8) + u8(1) = 17
    assert_eq!(size_of::<ContinueToken>(), RELAY_CONTINUE_TOKEN_BYTES);
    assert_eq!(size_of::<ContinueToken>(), 17);
}

// -------------------------------------------------------
// Field offset assertions (critical for BPF map compatibility)
// -------------------------------------------------------

#[test]
fn test_relay_config_field_offsets() {
    assert_eq!(offset_of!(RelayConfig, dedicated), 0);
    assert_eq!(offset_of!(RelayConfig, relay_public_address), 4);
    assert_eq!(offset_of!(RelayConfig, relay_internal_address), 8);
    assert_eq!(offset_of!(RelayConfig, relay_port), 12);
    assert_eq!(offset_of!(RelayConfig, relay_secret_key), 14);
    assert_eq!(offset_of!(RelayConfig, relay_backend_public_key), 46);
    assert_eq!(offset_of!(RelayConfig, gateway_ethernet_address), 78);
    assert_eq!(offset_of!(RelayConfig, use_gateway_ethernet_address), 84);
}

#[test]
fn test_session_data_field_offsets() {
    assert_eq!(offset_of!(SessionData, session_private_key), 0);
    assert_eq!(offset_of!(SessionData, expire_timestamp), 32);
    assert_eq!(offset_of!(SessionData, session_id), 40);
    assert_eq!(offset_of!(SessionData, envelope_kbps_up), 80);
    assert_eq!(offset_of!(SessionData, envelope_kbps_down), 84);
    assert_eq!(offset_of!(SessionData, next_address), 88);
    assert_eq!(offset_of!(SessionData, prev_address), 92);
    assert_eq!(offset_of!(SessionData, next_port), 96);
    assert_eq!(offset_of!(SessionData, prev_port), 98);
    assert_eq!(offset_of!(SessionData, session_version), 100);
    assert_eq!(offset_of!(SessionData, first_hop), 103);
}

#[test]
fn test_ping_token_data_field_offsets() {
    // Packed struct - fields are contiguous with no padding
    assert_eq!(offset_of!(PingTokenData, ping_key), 0);
    assert_eq!(offset_of!(PingTokenData, expire_timestamp), 32);
    assert_eq!(offset_of!(PingTokenData, source_address), 40);
    assert_eq!(offset_of!(PingTokenData, dest_address), 44);
    assert_eq!(offset_of!(PingTokenData, source_port), 48);
    assert_eq!(offset_of!(PingTokenData, dest_port), 50);
}

#[test]
fn test_header_data_field_offsets() {
    assert_eq!(offset_of!(HeaderData, session_private_key), 0);
    assert_eq!(offset_of!(HeaderData, packet_type), 32);
    assert_eq!(offset_of!(HeaderData, packet_sequence), 33);
    assert_eq!(offset_of!(HeaderData, session_id), 41);
    assert_eq!(offset_of!(HeaderData, session_version), 49);
}

// -------------------------------------------------------
// Constant assertions (match relay_constants.h)
// -------------------------------------------------------

#[test]
fn test_constants_match_c() {
    assert_eq!(MAX_RELAYS, 1024);
    assert_eq!(MAX_SESSIONS, 100_000);
    assert_eq!(RELAY_HEADER_BYTES, 25);
    assert_eq!(RELAY_MTU, 1200);
    assert_eq!(RELAY_MAX_PACKET_BYTES, 1384);
    assert_eq!(RELAY_PING_HISTORY_SIZE, 64);
    assert_eq!(RELAY_PING_TOKEN_BYTES, 32);
    assert_eq!(RELAY_PING_KEY_BYTES, 32);
    assert_eq!(RELAY_SESSION_PRIVATE_KEY_BYTES, 32);
    assert_eq!(RELAY_ROUTE_TOKEN_BYTES, 71);
    assert_eq!(RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES, 111);
    assert_eq!(RELAY_CONTINUE_TOKEN_BYTES, 17);
    assert_eq!(RELAY_ENCRYPTED_CONTINUE_TOKEN_BYTES, 57);
    assert_eq!(RELAY_NUM_COUNTERS, 150);
    assert_eq!(RELAY_VERSION_LENGTH, 32);
    assert_eq!(WHITELIST_TIMEOUT, 1000);
    assert_eq!(RELAY_ETHERNET_ADDRESS_BYTES, 6);

    // Packet types
    assert_eq!(RELAY_PING_PACKET, 11);
    assert_eq!(RELAY_PONG_PACKET, 12);
    assert_eq!(RELAY_ROUTE_REQUEST_PACKET, 1);
    assert_eq!(RELAY_ROUTE_RESPONSE_PACKET, 2);
    assert_eq!(RELAY_CLIENT_TO_SERVER_PACKET, 3);
    assert_eq!(RELAY_SERVER_TO_CLIENT_PACKET, 4);
    assert_eq!(RELAY_SESSION_PING_PACKET, 5);
    assert_eq!(RELAY_SESSION_PONG_PACKET, 6);
    assert_eq!(RELAY_CONTINUE_REQUEST_PACKET, 7);
    assert_eq!(RELAY_CONTINUE_RESPONSE_PACKET, 8);
    assert_eq!(RELAY_CLIENT_PING_PACKET, 9);
    assert_eq!(RELAY_CLIENT_PONG_PACKET, 10);
    assert_eq!(RELAY_SERVER_PING_PACKET, 13);
    assert_eq!(RELAY_SERVER_PONG_PACKET, 14);
}

// -------------------------------------------------------
// SHA-256 ping token test
// -------------------------------------------------------

#[test]
fn test_ping_token_sha256_deterministic() {
    use sha2::Digest;

    // Populate PingTokenData with known values and verify SHA-256 produces
    // deterministic output (same as C's crypto_hash_sha256 over the same bytes)
    let token_data = PingTokenData {
        ping_key: [0xAA; 32],
        expire_timestamp: 1700000000u64, // native byte order
        source_address: 0x0A000001u32.to_be(), // 10.0.0.1 in BE
        dest_address: 0x0A000002u32.to_be(),   // 10.0.0.2 in BE
        source_port: 40000u16.to_be(),
        dest_port: 40001u16.to_be(),
    };

    let token_bytes = unsafe {
        std::slice::from_raw_parts(
            &token_data as *const _ as *const u8,
            std::mem::size_of::<PingTokenData>(),
        )
    };

    let hash: [u8; 32] = sha2::Sha256::digest(token_bytes).into();

    // Re-hash the same data - must be identical
    let hash2: [u8; 32] = sha2::Sha256::digest(token_bytes).into();

    assert_eq!(hash, hash2);
    // Hash must not be all zeros (placeholder would produce this)
    assert_ne!(hash, [0u8; 32]);
}

// -------------------------------------------------------
// crypto_box_easy / crypto_box_open_easy roundtrip
// -------------------------------------------------------

#[test]
fn test_crypto_box_roundtrip() {
    use crypto_box::aead::{AeadCore, AeadInPlace, OsRng};

    let client_sk = crypto_box::SecretKey::generate(&mut OsRng);
    let client_pk = client_sk.public_key();
    let server_sk = crypto_box::SecretKey::generate(&mut OsRng);
    let server_pk = server_sk.public_key();

    let plaintext = b"hello network next relay";
    let nonce = crypto_box::SalsaBox::generate_nonce(&mut OsRng);

    // Encrypt: client → server
    let encrypt_box = crypto_box::SalsaBox::new(&server_pk, &client_sk);
    let mut buffer = plaintext.to_vec();
    let tag = encrypt_box
        .encrypt_in_place_detached(&nonce, b"", &mut buffer)
        .expect("encrypt failed");

    // Decrypt: server opens
    let decrypt_box = crypto_box::SalsaBox::new(&client_pk, &server_sk);
    decrypt_box
        .decrypt_in_place_detached(&nonce, b"", &mut buffer, &tag)
        .expect("decrypt failed");

    assert_eq!(&buffer, plaintext);
}

// -------------------------------------------------------
// crypto_kx roundtrip
// -------------------------------------------------------

#[test]
fn test_crypto_kx_session_keys() {
    use blake2::digest::{Update, VariableOutput};
    use x25519_dalek::{PublicKey, StaticSecret};

    // Generate keypairs using x25519
    let mut client_sk_bytes = [0u8; 32];
    let mut server_sk_bytes = [0u8; 32];
    getrandom::fill(&mut client_sk_bytes).unwrap();
    getrandom::fill(&mut server_sk_bytes).unwrap();

    let client_sk = StaticSecret::from(client_sk_bytes);
    let client_pk = PublicKey::from(&client_sk);
    let server_sk = StaticSecret::from(server_sk_bytes);
    let server_pk = PublicKey::from(&server_sk);

    // Shared secret is same for both sides
    let client_shared = client_sk.diffie_hellman(&server_pk);
    let server_shared = server_sk.diffie_hellman(&client_pk);
    assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());

    // Both sides hash with the SAME input: q || client_pk || server_pk
    // (libsodium's crypto_kx uses this canonical order for both client and server)

    // Client-side: rx = first 32, tx = last 32
    let mut client_hasher = blake2::Blake2bVar::new(64).unwrap();
    client_hasher.update(client_shared.as_bytes());
    client_hasher.update(client_pk.as_bytes());
    client_hasher.update(server_pk.as_bytes());
    let mut client_output = [0u8; 64];
    client_hasher.finalize_variable(&mut client_output).unwrap();
    let client_rx = &client_output[..32];
    let client_tx = &client_output[32..];

    // Server-side: same hash input, but rx = last 32, tx = first 32 (SWAPPED)
    let mut server_hasher = blake2::Blake2bVar::new(64).unwrap();
    server_hasher.update(server_shared.as_bytes());
    server_hasher.update(client_pk.as_bytes());
    server_hasher.update(server_pk.as_bytes());
    let mut server_output = [0u8; 64];
    server_hasher.finalize_variable(&mut server_output).unwrap();
    let server_rx = &server_output[32..]; // swapped!
    let server_tx = &server_output[..32]; // swapped!

    // client_rx == server_tx, client_tx == server_rx
    assert_eq!(client_rx, server_tx);
    assert_eq!(client_tx, server_rx);
}

// -------------------------------------------------------
// Ping packet wire format
// -------------------------------------------------------

#[test]
fn test_ping_packet_wire_format_size() {
    // A relay ping packet should be:
    // 1 byte packet_type + 2 bytes pittle + 15 bytes chonkle = 18 bytes header
    // + 8 bytes sequence + 8 bytes expire_timestamp + 1 byte internal
    // + 32 bytes ping_token = 49 bytes payload
    // Total = 18 + 49 = 67 bytes
    let header = 18;
    let payload = 8 + 8 + 1 + RELAY_PING_TOKEN_BYTES;
    assert_eq!(header + payload, 67);
}

