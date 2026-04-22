# Session Summary: relay-sdk Planning

**Date:** 2026-04-22
**Duration:** ~1 session (~15 interactions)
**Focus Area:** relay-sdk - architecture analysis and implementation

## Objectives

- [x] Analyze rust-sdk crate (modules, wire format, crypto, threading)
- [x] Define scope of relay-sdk vs rust-sdk
- [x] Decide copy vs rewrite strategy for each module
- [x] Identify role of mod server (final destination, not relay node)
- [x] Confirm threading model (Arc<Mutex<VecDeque>>, 1 network thread)
- [x] Confirm HeaderData layout mapping before copying pittle/chonkle
- [x] Create relay-sdk/ crate - Cargo.toml, workspace registration, lib.rs skeleton
- [x] Copy 5 modules (bitpacker, stream, read_write, platform, route/trackers) - 27/27 tests pass
- [x] Rewrite mod address + mod crypto - 40/40 tests pass
- [x] mod tokens (RouteToken/ContinueToken encrypt/decrypt) + mod route (RouteManager, pittle/chonkle, write/read_header) - 59/59 tests pass
- [x] Rewrite mod packets (14 packet types, dispatch decode, wire constants) - 73/73 tests pass
- [x] Write new mod client + mod server (two-half, 1 network thread, VecDeque IPC) - 91/91 tests pass
- [ ] mod ffi stub + cbindgen generate relay_generated.h

## Work Completed

### Step 1: Create relay-sdk/ crate

- Create `relay-sdk/Cargo.toml`: crate-type cdylib/staticlib/rlib, dep relay-xdp-common, chacha20poly1305, sha2, rand, zeroize, thiserror, anyhow; build-dep cbindgen
- Create `relay-sdk/build.rs`: cbindgen -> `include/relay_generated.h`
- Create `relay-sdk/cbindgen.toml`: prefix relay_, include guard RELAY_GENERATED_H
- Create `relay-sdk/src/lib.rs`, `relay-sdk/src/constants.rs`
- Add `relay-sdk` to workspace `Cargo.toml`

### Step 2: Copy 5 modules from rust-sdk

- Copy unchanged: `bitpacker/`, `stream/`, `read_write.rs`, `platform/`, `route/trackers.rs`
- Create `src/route/mod.rs` stub so trackers.rs compiles
- Add required constants (`REPLAY_PROTECTION_BUFFER_SIZE`, `MAX_PACKET_BYTES`, `ADDRESS_*`, ...) to `constants.rs`
- Create stub `src/address/mod.rs` so `read_write.rs` compiles at this stage
- Result: **27/27 tests pass**

### Step 3: Rewrite mod address + mod crypto

- `src/address/mod.rs`: full rewrite - byte-level LE encoding matching relay-xdp wire format
  - `encode(&self, buf) -> Result<usize>`: type(u8) + ip(BE) + port(LE)
  - `decode(buf) -> Result<(Address, usize)>`
  - Add `encoded_len()`, `From<Address> for Option<SocketAddr>`
  - 7 tests: roundtrip IPv4/IPv6/None, parse, display, wire bytes, encoded_len
- `src/crypto/mod.rs`: written from scratch - SHA-256 + XChaCha20-Poly1305 only
  - `hash_sha256(data) -> [u8; 32]`
  - `xchacha_encrypt(plaintext, nonce, key, aad) -> Vec<u8>`
  - `xchacha_decrypt(ciphertext, nonce, key, aad) -> Result<Vec<u8>>`
  - 5 tests: known-vector SHA256, roundtrip, wrong key, AAD, short ciphertext
- Result: **40/40 tests pass**

### Step 4: Copy pittle/chonkle/fnv1a_64 + rewrite write_header/read_header + RouteManager

- Map `HeaderData` layout from `relay-xdp-common` (version, flags, sequence, session_id, token)
- Copy `pittle`, `chonkle`, `fnv1a_64` from `rust-sdk/src/route/mod.rs` (logic unchanged)
- Rewrite `write_header` / `read_header` to match relay-xdp wire format layout
- Write `RouteManager` state machine: direct/pending/active route, RTT tracking, fallback logic
- 19 tests: header roundtrip, wrong key, pittle/chonkle deterministic, route state transitions, send sequence, C2S packet, etc.
- Result: **59/59 tests pass**

### Step 5: Rewrite mod tokens + mod packets

- `src/tokens/mod.rs`: full rewrite
  - `RouteToken` (71B plain -> 111B encrypted), `ContinueToken` (17B plain -> 57B encrypted)
  - encrypt/decrypt using XChaCha20-Poly1305 + key from relay-xdp wire format
  - 6 tests: roundtrip, wrong key, encrypted size
- `src/packets/mod.rs`: full rewrite
  - 14 packet types (RELAY_PING=1 .. CLIENT_TO_SERVER_PACKET=14)
  - `dispatch_decode(buf) -> Result<Packet>` dispatcher
  - Size constants, per-type encode/decode, wire format little-endian
  - 14 tests: roundtrip per type, size constants, dispatch decode, error cases
- Result: **73/73 tests pass**

### Step 6: Write new mod client + mod server

- `src/client/mod.rs`: written from scratch
  - `Client` (main-thread handle) + `ClientInner` (network-thread side)
  - IPC: `Arc<Mutex<VecDeque<Command>>>` + `Arc<Mutex<VecDeque<Notify>>>`
  - `Command`: OpenSession, CloseSession, RouteUpdate, Tick, SendPacket, Destroy
  - `Notify`: PacketReceived, RouteChanged, SendRaw
  - `ClientInner.process_incoming()`: handles ROUTE_RESPONSE, CONTINUE_RESPONSE, SERVER_TO_CLIENT
  - `ClientInner.tick()`: drives check_for_timeouts, send_route_request, send_continue_request
  - No KX handshake - client_secret_key provided by caller (backend HTTP push)
  - 7 tests: initial state, open/close session, tick time, send no route, sequence increment, destroy stops pump, route update direct

- `src/server/mod.rs`: written from scratch
  - `Server` (main-thread handle) + `ServerInner` (network-thread side)
  - `Command`: Open, Close, RegisterSession, ExpireSession, SendPacket, Destroy
  - `Notify`: PacketReceived, SendRaw, SessionRegistered, SessionExpired
  - Per-session `SessionInfo`: session_id, version, private_key, relay_address, send_sequence, ReplayProtection
  - `ServerInner.process_incoming()`: verifies CLIENT_TO_SERVER header, replay check, extracts payload
  - `ServerInner.send_packet_inner()`: builds SERVER_TO_CLIENT packet with write_header + stamp_packet
  - No KX handshake - session_private_key pushed by backend HTTP
  - 9 tests: initial state, open/close, register/expire session, drain notify, unknown type, valid packet, replay rejection, destroy stops pump

- Added `pub fn stamp_packet()` (public alias for `stamp_filter`) in `route/mod.rs`
- Added `#[derive(Debug, Clone)]` to `ReplayProtection` in `route/trackers.rs`
- Enabled `pub mod client; pub mod server;` in `src/lib.rs`
- Result: **91/91 tests pass**

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Copy bitpacker/stream/read_write/platform/route::trackers unchanged | Not related to wire format; 95 tests already passing in rust-sdk | N/A |
| Rewrite mod address | rust-sdk serializes via bitstream (Stream trait); relay-xdp uses byte-level LE + RELAY_ADDRESS_IPV4/V6 constants | N/A |
| Rewrite mod crypto | relay-xdp only needs SHA-256 + XChaCha20-Poly1305; remove NaCl/BLAKE2/Ed25519/KX to reduce dependencies | N/A |
| Copy pittle/chonkle/fnv1a_64 after mapping HeaderData | FNV-1a and pittle/chonkle logic unchanged; only write_header/read_header need rewriting to match relay-xdp-common HeaderData | N/A |
| IPC using Arc<Mutex<VecDeque>> instead of mpsc | Matches relay-xdp threading model (Main Thread + Ping Thread use the same pattern) | N/A |
| 1 network thread for both send + recv | Simpler than two-thread model; sufficient for UDP non-blocking loop | N/A |
| mod server is the final destination | Server receives RELAY_CLIENT_TO_SERVER_PACKET from last relay hop, not a relay node; session_private_key received from RouteToken pushed by backend via HTTP | N/A |

## Tests Added/Modified

| Module | Test | Type | Status |
|--------|------|------|--------|
| `address` | `ipv4_roundtrip` | Unit | Pass |
| `address` | `ipv6_roundtrip` | Unit | Pass |
| `address` | `none_roundtrip` | Unit | Pass |
| `address` | `parse_ipv4` | Unit | Pass |
| `address` | `display_ipv4` | Unit | Pass |
| `address` | `ipv4_wire_bytes` | Unit | Pass |
| `address` | `encoded_len` | Unit | Pass |
| `crypto` | `sha256_known_vector` | Unit | Pass |
| `crypto` | `sha256_hello` | Unit | Pass |
| `crypto` | `xchacha_encrypt_decrypt_roundtrip` | Unit | Pass |
| `crypto` | `xchacha_wrong_key_fails` | Unit | Pass |
| `crypto` | `xchacha_with_aad` | Unit | Pass |
| `crypto` | `xchacha_short_ciphertext_fails` | Unit | Pass |
| bitpacker/stream/read_write/trackers | (copied) | Unit | 27 Pass |
| `route` | `header_write_read_roundtrip` | Unit | Pass |
| `route` | `header_wrong_key_fails` | Unit | Pass |
| `route` | `pittle_deterministic` | Unit | Pass |
| `route` | `chonkle_deterministic` | Unit | Pass |
| `route` | `route_manager_new_is_direct` | Unit | Pass |
| `route` | `route_manager_fallback_sets_flags` | Unit | Pass |
| `route` | `route_manager_reset_clears_all` | Unit | Pass |
| `route` | `confirm_pending_route_transitions_to_active` | Unit | Pass |
| `route` | `send_sequence_increments` | Unit | Pass |
| `route` | `prepare_send_packet_no_route_returns_none` | Unit | Pass |
| `route` | `client_to_server_packet_roundtrip` | Unit | Pass |
| `route` | `process_s2c_no_route_rejects` | Unit | Pass |
| `route` | `begin_next_route_bad_token_causes_fallback` | Unit | Pass |
| `tokens` | `route_token_roundtrip` | Unit | Pass |
| `tokens` | `route_token_wrong_key_fails` | Unit | Pass |
| `tokens` | `route_token_encrypted_size` | Unit | Pass |
| `tokens` | `continue_token_roundtrip` | Unit | Pass |
| `tokens` | `continue_token_wrong_key_fails` | Unit | Pass |
| `tokens` | `continue_token_encrypted_size` | Unit | Pass |
| `packets` | `client_ping_roundtrip` | Unit | Pass |
| `packets` | `client_pong_roundtrip` | Unit | Pass |
| `packets` | `relay_ping_roundtrip` | Unit | Pass |
| `packets` | `relay_pong_roundtrip` | Unit | Pass |
| `packets` | `relay_pong_too_small_fails` | Unit | Pass |
| `packets` | `server_ping_roundtrip` | Unit | Pass |
| `packets` | `server_pong_roundtrip` | Unit | Pass |
| `packets` | `session_ping_roundtrip` | Unit | Pass |
| `packets` | `route_response_roundtrip` | Unit | Pass |
| `packets` | `route_response_wrong_size_fails` | Unit | Pass |
| `packets` | `continue_response_roundtrip` | Unit | Pass |
| `packets` | `dispatch_decode_relay_pong` | Unit | Pass |
| `packets` | `dispatch_decode_unknown_type_fails` | Unit | Pass |
| `packets` | `packet_size_constants` | Unit | Pass |
| `client` | `client_initial_state_is_closed` | Unit | Pass |
| `client` | `client_open_session_sets_state_open` | Unit | Pass |
| `client` | `client_close_session_resets_state` | Unit | Pass |
| `client` | `client_tick_advances_time` | Unit | Pass |
| `client` | `client_send_packet_no_relay_route_yields_no_send_raw` | Unit | Pass |
| `client` | `client_sequence_increments_on_send` | Unit | Pass |
| `client` | `client_destroy_stops_pump` | Unit | Pass |
| `client` | `client_route_update_direct_type_does_not_fallback` | Unit | Pass |
| `server` | `server_initial_state_is_closed` | Unit | Pass |
| `server` | `server_open_sets_state_open` | Unit | Pass |
| `server` | `server_close_resets_state` | Unit | Pass |
| `server` | `server_register_session_stores_info` | Unit | Pass |
| `server` | `server_expire_session_removes_info` | Unit | Pass |
| `server` | `server_destroy_stops_pump` | Unit | Pass |
| `server` | `server_drain_notify_updates_session_count` | Unit | Pass |
| `server` | `server_incoming_unknown_type_is_ignored` | Unit | Pass |
| `server` | `server_client_to_server_with_valid_header_extracts_payload` | Unit | Pass |
| `server` | `server_client_to_server_replay_is_rejected` | Unit | Pass |

**Total: 91/91 tests pass**

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| `relay-sdk/src/` did not exist when copying modules | Run `mkdir -p src` before cp | No |
| `read_write.rs` imports `crate::address::Address` - compile failure before address was written | Create stub address/mod.rs to compile, rewrite in step 3 | No |
| `bitpacker/mod.rs` imports `MAX_PACKET_BYTES` from constants | Add `MAX_PACKET_BYTES = 1384` to relay-sdk constants.rs | No |
| mod address serialize format differs between rust-sdk and relay-xdp | Rewrite mod address - use byte-level encode/decode | No |
| HeaderData layout in relay-xdp-common differs from rust-sdk before copying pittle/chonkle | Map HeaderData exactly first, copy pittle/chonkle after; rewrite write_header/read_header | No |
| mod server scope confused with relay node | Confirmed: server in relay-sdk is the game server (destination), receives payload from last relay hop, session state in-memory | No |
| `ReplayProtection` missing `Debug + Clone` derives (required by `SessionInfo`) | Add `#[derive(Debug, Clone)]` to `ReplayProtection` in `route/trackers.rs` | No |
| `write_header` argument order wrong in server tests | Corrected argument order: packet_type, sequence, session_id, session_version, key, header | No |
| `stamp_filter` is private, needed by server's send path | Added `pub fn stamp_packet()` as public alias in `route/mod.rs` | No |

## Next Steps

1. **Low:** `mod ffi` stub + cbindgen generate `include/relay_generated.h`

## Files Changed

| Status | File |
|--------|------|
| A | `relay-sdk/Cargo.toml` |
| A | `relay-sdk/build.rs` |
| A | `relay-sdk/cbindgen.toml` |
| A | `relay-sdk/ARCHITECTURE.md` |
| A | `relay-sdk/src/lib.rs` |
| A | `relay-sdk/src/constants.rs` |
| A | `relay-sdk/src/address/mod.rs` (rewritten) |
| A | `relay-sdk/src/crypto/mod.rs` (new) |
| A | `relay-sdk/src/bitpacker/mod.rs` (copied) |
| A | `relay-sdk/src/stream/mod.rs` (copied) |
| A | `relay-sdk/src/read_write.rs` (copied) |
| A | `relay-sdk/src/platform/mod.rs` (copied) |
| A | `relay-sdk/src/platform/linux.rs` (copied) |
| A | `relay-sdk/src/route/mod.rs` (rewritten: pittle/chonkle/write_header/read_header/RouteManager) |
| A | `relay-sdk/src/route/trackers.rs` (copied) |
| A | `relay-sdk/src/tokens/mod.rs` (rewritten) |
| A | `relay-sdk/src/packets/mod.rs` (rewritten) |
| A | `relay-sdk/src/client/mod.rs` (new) |
| A | `relay-sdk/src/server/mod.rs` (new) |
| M | `relay-sdk/src/route/mod.rs` (add pub stamp_packet) |
| M | `relay-sdk/src/route/trackers.rs` (add derive Debug, Clone to ReplayProtection) |
| M | `relay-sdk/src/lib.rs` (enable pub mod client, pub mod server) |
| M | `Cargo.toml` (add relay-sdk to workspace members) |
| A | `docs/sessions/2026-04-22-relay-sdk-plan.md` |
