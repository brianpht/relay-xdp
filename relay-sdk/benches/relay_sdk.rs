// benches/relay_sdk.rs - criterion benchmarks for relay-sdk hot paths.
//
// Groups:
//   packet_codec   - encode/decode for RouteResponse, SessionPing, RelayPing
//   header_hmac    - write_header / read_header (SHA-256 per forwarded packet)
//   filter         - generate_pittle / generate_chonkle (FNV-1a per packet)
//   token_crypto   - XChaCha20-Poly1305 RouteToken / ContinueToken AEAD
//   route_manager  - RouteManager::update (begin_next_route) and prepare_send_packet
//
// Run: cargo bench --bench relay_sdk

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use relay_sdk::{
    address::Address,
    constants::{
        ENCRYPTED_ROUTE_TOKEN_BYTES, MAX_PACKET_BYTES, PACKET_TYPE_CLIENT_TO_SERVER,
        RELAY_PING_TOKEN_BYTES, SESSION_PRIVATE_KEY_BYTES, UPDATE_TYPE_ROUTE,
    },
    packets::{
        RelayPingPacket, RouteResponsePacket, SessionPingPacket, RELAY_PING_BYTES,
        ROUTE_RESPONSE_BYTES, SESSION_PING_BYTES,
    },
    route::{
        generate_chonkle, generate_pittle, read_header, write_header, RouteManager, HEADER_BYTES,
    },
    tokens::{
        decrypt_continue_token, decrypt_route_token, encrypt_continue_token, encrypt_route_token,
    },
};
use relay_xdp_common::{ContinueToken, RouteToken};

// ── Fixture helpers ────────────────────────────────────────────────────────────

fn fixture_route_token() -> RouteToken {
    RouteToken {
        session_private_key: [0x55u8; SESSION_PRIVATE_KEY_BYTES],
        expire_timestamp: 9_999_999,
        session_id: 0xCAFE_BABE_DEAD_BEEF,
        envelope_kbps_up: 1000,
        envelope_kbps_down: 2000,
        // IPv4 10.0.0.1 in big-endian network order
        next_address: 0x0A00_0001u32.to_be(),
        prev_address: 0,
        next_port: 12345u16.to_be(),
        prev_port: 0,
        session_version: 3,
        next_internal: 0,
        prev_internal: 0,
    }
}

fn fixture_continue_token() -> ContinueToken {
    ContinueToken {
        expire_timestamp: 9_999_999,
        session_id: 0xCAFE_BABE_DEAD_BEEF,
        session_version: 3,
    }
}

// ── Group: packet_codec ────────────────────────────────────────────────────────
//
// Measures encode and decode cost for the three most frequently forwarded
// packet types: ROUTE_RESPONSE (every route setup), SESSION_PING (every relay
// hop keep-alive), and RELAY_PING (relay-to-relay RTT probing).

fn bench_packet_codec(c: &mut Criterion) {
    let mut g = c.benchmark_group("packet_codec");

    // __ RouteResponsePacket __
    let rr_pkt = RouteResponsePacket {
        relay_header: [0xABu8; HEADER_BYTES],
    };
    let mut rr_buf = [0u8; ROUTE_RESPONSE_BYTES];
    rr_pkt.encode(&mut rr_buf).unwrap();

    g.bench_function("route_response_encode", |b| {
        b.iter(|| {
            let mut buf = [0u8; ROUTE_RESPONSE_BYTES];
            let _ = black_box(&rr_pkt).encode(black_box(&mut buf));
        })
    });
    g.bench_function("route_response_decode", |b| {
        b.iter(|| {
            let _ = RouteResponsePacket::decode(black_box(&rr_buf));
        })
    });

    // __ SessionPingPacket __
    let sp_pkt = SessionPingPacket {
        relay_header: [0xCDu8; HEADER_BYTES],
        ping_sequence: 42,
    };
    let mut sp_buf = [0u8; SESSION_PING_BYTES];
    sp_pkt.encode(&mut sp_buf).unwrap();

    g.bench_function("session_ping_encode", |b| {
        b.iter(|| {
            let mut buf = [0u8; SESSION_PING_BYTES];
            let _ = black_box(&sp_pkt).encode(black_box(&mut buf));
        })
    });
    g.bench_function("session_ping_decode", |b| {
        b.iter(|| {
            let _ = SessionPingPacket::decode(black_box(&sp_buf));
        })
    });

    // __ RelayPingPacket __
    let rp_pkt = RelayPingPacket {
        sequence: 100,
        expire_timestamp: 9_999_999,
        is_internal: false,
        ping_token: [0xEFu8; RELAY_PING_TOKEN_BYTES],
    };
    let mut rp_buf = [0u8; RELAY_PING_BYTES];
    rp_pkt.encode(&mut rp_buf).unwrap();

    g.bench_function("relay_ping_encode", |b| {
        b.iter(|| {
            let mut buf = [0u8; RELAY_PING_BYTES];
            let _ = black_box(&rp_pkt).encode(black_box(&mut buf));
        })
    });
    g.bench_function("relay_ping_decode", |b| {
        b.iter(|| {
            let _ = RelayPingPacket::decode(black_box(&rp_buf));
        })
    });

    g.finish();
}

// ── Group: header_hmac ─────────────────────────────────────────────────────────
//
// Every relay-forwarded packet pays write_header (outbound) or read_header
// (inbound). Both compute SHA-256(HeaderData) internally - this is the dominant
// per-packet crypto cost.

fn bench_header_hmac(c: &mut Criterion) {
    let mut g = c.benchmark_group("header_hmac");

    let private_key = [0x55u8; SESSION_PRIVATE_KEY_BYTES];
    let mut header = [0u8; HEADER_BYTES];
    write_header(
        PACKET_TYPE_CLIENT_TO_SERVER,
        12345,
        0xDEAD_BEEF_0000_0001,
        7,
        &private_key,
        &mut header,
    );

    g.bench_function("write_header", |b| {
        b.iter(|| {
            let mut hdr = [0u8; HEADER_BYTES];
            write_header(
                black_box(PACKET_TYPE_CLIENT_TO_SERVER),
                black_box(12345u64),
                black_box(0xDEAD_BEEF_0000_0001u64),
                black_box(7u8),
                black_box(&private_key),
                black_box(&mut hdr),
            );
            black_box(hdr)
        })
    });

    g.bench_function("read_header_valid", |b| {
        b.iter(|| {
            let _ = read_header(
                black_box(PACKET_TYPE_CLIENT_TO_SERVER),
                black_box(&private_key),
                black_box(&header[..]),
            );
        })
    });

    let bad_key = [0x99u8; SESSION_PRIVATE_KEY_BYTES];
    g.bench_function("read_header_invalid_key", |b| {
        b.iter(|| {
            let _ = read_header(
                black_box(PACKET_TYPE_CLIENT_TO_SERVER),
                black_box(&bad_key),
                black_box(&header[..]),
            );
        })
    });

    g.finish();
}

// ── Group: filter ──────────────────────────────────────────────────────────────
//
// generate_pittle and generate_chonkle run on every packet (DDoS filter).
// Both are FNV-1a based - this establishes a per-packet baseline.

fn bench_filter(c: &mut Criterion) {
    let mut g = c.benchmark_group("filter");

    let from = [10u8, 0, 0, 1];
    let to = [10u8, 0, 0, 2];
    let len: u16 = 512;
    let magic = [1u8, 2, 3, 4, 5, 6, 7, 8];

    g.bench_function("generate_pittle", |b| {
        b.iter(|| {
            let mut out = [0u8; 2];
            generate_pittle(
                black_box(&mut out),
                black_box(&from),
                black_box(&to),
                black_box(len),
            );
            black_box(out)
        })
    });

    g.bench_function("generate_chonkle", |b| {
        b.iter(|| {
            let mut out = [0u8; 15];
            generate_chonkle(
                black_box(&mut out),
                black_box(&magic),
                black_box(&from),
                black_box(&to),
                black_box(len),
            );
            black_box(out)
        })
    });

    g.finish();
}

// ── Group: token_crypto ────────────────────────────────────────────────────────
//
// XChaCha20-Poly1305 AEAD called once per route/continue setup (not per packet).
// Encrypt uses random nonce each call (rand::thread_rng) - measures full cost.

fn bench_token_crypto(c: &mut Criterion) {
    let mut g = c.benchmark_group("token_crypto");

    let key = [0x42u8; 32]; // XCHACHA_KEY_BYTES
    let rt = fixture_route_token();
    let ct = fixture_continue_token();
    let enc_rt = encrypt_route_token(&rt, &key);
    let enc_ct = encrypt_continue_token(&ct, &key);

    g.bench_function("encrypt_route_token", |b| {
        b.iter(|| {
            let _ = encrypt_route_token(black_box(&rt), black_box(&key));
        })
    });
    g.bench_function("decrypt_route_token", |b| {
        b.iter(|| {
            let _ = decrypt_route_token(black_box(&enc_rt), black_box(&key));
        })
    });
    g.bench_function("encrypt_continue_token", |b| {
        b.iter(|| {
            let _ = encrypt_continue_token(black_box(&ct), black_box(&key));
        })
    });
    g.bench_function("decrypt_continue_token", |b| {
        b.iter(|| {
            let _ = decrypt_continue_token(black_box(&enc_ct), black_box(&key));
        })
    });

    g.finish();
}

// ── Group: route_manager ───────────────────────────────────────────────────────
//
// update_begin_next_route: full token decrypt + state transition on route update.
// prepare_send_packet: per-tick outbound packet encoding on an active route.
//
// RouteManager does not implement Clone so iter_batched is used to separate
// per-iteration setup from the measured path.

fn bench_route_manager(c: &mut Criterion) {
    let mut g = c.benchmark_group("route_manager");

    let client_key = [0x42u8; 32]; // XCHACHA_KEY_BYTES
    let magic = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let ext_addr = Address::V4 {
        octets: [1, 2, 3, 4],
        port: 5555,
    };

    // Two-entry token bundle: [enc_rt_0][enc_rt_1] (same token, valid fixture).
    let enc_rt = encrypt_route_token(&fixture_route_token(), &client_key);
    let mut token_bundle = vec![0u8; 2 * ENCRYPTED_ROUTE_TOKEN_BYTES];
    token_bundle[..ENCRYPTED_ROUTE_TOKEN_BYTES].copy_from_slice(&enc_rt);
    token_bundle[ENCRYPTED_ROUTE_TOKEN_BYTES..].copy_from_slice(&enc_rt);

    // Bench: full begin_next_route transition (token decrypt + state write).
    g.bench_function("update_begin_next_route", |b| {
        b.iter_batched(
            RouteManager::new,
            |mut rm| {
                rm.update(
                    black_box(UPDATE_TYPE_ROUTE),
                    black_box(2),
                    black_box(&token_bundle),
                    black_box(&client_key),
                    black_box(&magic),
                    black_box(&ext_addr),
                );
                black_box(rm.has_network_next_route())
            },
            BatchSize::SmallInput,
        )
    });

    // Bench: prepare_send_packet on an already-active route.
    // Setup activates the route (outside timing); only per-packet encoding is timed.
    let payload = vec![0xAAu8; 256];
    g.bench_function("prepare_send_packet_256b", |b| {
        b.iter_batched(
            || {
                let mut rm = RouteManager::new();
                rm.update(
                    UPDATE_TYPE_ROUTE,
                    2,
                    &token_bundle,
                    &client_key,
                    &magic,
                    &ext_addr,
                );
                rm.confirm_pending_route();
                rm
            },
            |mut rm| {
                let seq = rm.next_send_sequence();
                let mut pkt_buf = [0u8; MAX_PACKET_BYTES];
                let _ = rm.prepare_send_packet(
                    black_box(seq),
                    black_box(&payload),
                    black_box(&mut pkt_buf),
                    black_box(&magic),
                    black_box(&ext_addr),
                );
                black_box(pkt_buf)
            },
            BatchSize::SmallInput,
        )
    });

    g.finish();
}

// ── Criterion entry point ──────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_packet_codec,
    bench_header_hmac,
    bench_filter,
    bench_token_crypto,
    bench_route_manager,
);
criterion_main!(benches);
