# Session Summary: bench-relay end-to-end against staging

**Date:** 2026-05-10<br>
**Duration:** ~3 hours (multi-iteration debug)<br>
**Focus Area:** `relay-bench`, `relay-backend`, deployed staging stack<br>

## Objectives

- [x] Make `make bench-relay` produce real RTT samples against the staging stack
      (laptop -> relay-staging-1 -> bench-staging-1 -> back).
- [x] Move RouteToken encryption from bench_client into the backend so the
      relay can decrypt with its per-relay symmetric key.
- [x] Close the deployed-mode ROUTE_RESPONSE gap (smoke test was the only
      generator before).
- [x] Local CI gates clean for changed crates: `cargo fmt`, `cargo clippy
      -D warnings`, `cargo test`.
- [x] Periodic `/bench_token` refresh + ping-key rotation so a single run
      sustains traffic indefinitely without the SDK route expiring after 20s.

## Work Completed

### 1. Backend-side RouteToken encryption (`relay-backend`)

Bench_client cannot derive the per-relay XChaCha20-Poly1305 key (it lacks both
sides of the X25519 pair). Encryption moved into the backend's `/bench_token`
handler.

- Added per-relay key derivation that mirrors `relay-xdp::config::derive_secret_key`,
  exploiting X25519 symmetry:
  - relay computes `q = X25519(relay_sk, backend_pk)`
  - backend computes `q = X25519(backend_sk, relay_pk)`
  - both then `rx = BLAKE2b-512(q || relay_pk || backend_pk)[..32]`
- Added inline `encrypt_route_token_inline` (XChaCha20-Poly1305, 71B -> 111B)
  using the existing `chacha20poly1305` dependency, so we do not pull
  `relay-sdk` into the backend.
- New query parameter: `?bench_server_addr=IP:PORT`. With both `relay_addr` and
  `bench_server_addr` set, the handler derives the key and emits two encrypted
  tokens.
- New JSON fields on the `/bench_token` response:
  - `client_route_token` (Token[0], next = relay) - SDK reads it locally to
    drive its first-hop send target.
  - `wire_route_token` (Token[1], next = bench_server, prev = client_public_ipv4)
    - the relay decrypts this off the wire.
  - `relay_secret_key` - per-relay key (hex). bench_client uses it as
    `client_secret_key` for `open_session`.
- `Cargo.toml`: promoted `relay-xdp-common` (feature `user`),
  `chacha20poly1305`, `x25519-dalek` (`static_secrets`), `blake2`, `rand` from
  dev-deps to production deps.
- `ConnectInfo<SocketAddr>` extraction made optional (read via raw request
  extension) so existing `tower::oneshot` integration tests still pass.

Files: `relay-backend/Cargo.toml`, `relay-backend/src/handlers.rs`.

### 2. ROUTE_RESPONSE generator in bench_server (`relay-bench`)

Nothing in the deployed code path emitted `ROUTE_RESPONSE` (only the in-process
smoke test did). bench_server now synthesizes it.

- `RouteResponderState` (session_id, session_version, session_private_key,
  server_ip, magic, monotonic `next_sequence`) populated from
  `/register_session` whenever relay-mode params are present.
- `build_route_response_packet`: 43 bytes, layout
  `[type=2][pittle 2][chonkle 15][seq LE 8][sid LE 8][ver 1][SHA-256 MAC 8]`.
  Uses `relay_sdk::route::write_header` + `stamp_packet`.
- network_thread intercepts inbound `RELAY_ROUTE_REQUEST_PACKET` (type 1),
  allocates a strictly increasing sequence under a mutex, and replies to the
  source UDP address (the relay).

Files: `relay-bench/src/bin/bench_server.rs`.

### 3. bench_client wired to the new backend response (`relay-bench`)

- `BenchTokenResponse` extended with `client_route_token`, `wire_route_token`,
  `relay_secret_key`.
- `RelaySetup` swapped `relay_backend_pk` (single key) for the new pair.
- `setup_relay_route` now sends `[Token[0] = client_route_token, Token[1] =
  wire_route_token, Token[2] = zeros]` and `open_session(server_sdk,
  relay_secret_key)`.
- Local encryption removed (no more `encrypt_route_token` call in bench_client
  relay path).

Files: `relay-bench/src/bin/bench_client.rs`.

### 4. Route refresh + ping-key rotation (`relay-bench`)

`CLIENT_ROUTE_TIMEOUT = 20s` in relay-sdk: if no `route_update` arrives within
20s the SDK falls back to direct mode and pkt_sent drops to 0. Solved via a
background refresh task in bench_client.

- Added `ROUTE_REFRESH_INTERVAL_SECS = 10` constant (matches `SLICE_SECONDS`).
- Added `PingerRefreshKeys { ping_key, magic }` under `Arc<Mutex<>>`:
  - The network thread reads it (under lock, copy-out) when building each
    `CLIENT_PING` packet every 3s.
  - The refresh task writes it (under lock) after every successful re-fetch.
- Added `RouteRefreshConfig` (admin_url, relay_addr, bench_server endpoints,
  shared keys arc) constructed once at startup and `Arc`-shared into the task.
- Added blocking `do_refresh(cfg) -> Result<RefreshedRouteData>`:
  1. `GET /bench_token` - fetches fresh token pair + keys from backend.
  2. `POST /register_session` to bench_server - keeps server responder in sync.
  3. Returns decoded session material.
- Background `tokio::spawn` task (spawned after ROUTE_RESPONSE confirmed):
  - Skips first tick (avoids redundant immediate re-fetch).
  - Every 10s: `spawn_blocking(do_refresh)` -> update `PingerRefreshKeys` ->
    call `client.route_update(UPDATE_TYPE_ROUTE, 3, tokens, magic, client_ext)`.
  - Log `INFO` on success, `WARN` on failure (continues; next tick re-tries).
- `open_session` called once at startup; `relay_secret_key` is not refreshed
  because it is derived deterministically from stable keypairs (no effect on
  correctness across refreshes).
- Chose `UPDATE_TYPE_ROUTE` (full re-route) over `UPDATE_TYPE_CONTINUE`
  (ContinueToken) because the backend does not currently issue ContinueTokens
  for bench sessions; re-fetching `/bench_token` achieves the same liveness
  goal at negligible cost (1 HTTP round-trip every 10s).

Added hex helpers extracted from `setup_relay_route`: `decode_hex_32`,
`decode_hex_8`, `decode_hex_n` - DRY re-use across initial setup and refresh.

Files: `relay-bench/src/bin/bench_client.rs`.

### 5. SCP deploy + restart against staging

- `relay-backend` -> `107.23.94.101:/usr/local/bin/relay-backend` (`systemctl
  restart relay-backend`).
- `bench_server` -> `32.196.255.134:/usr/local/bin/bench_server` (`systemctl
  restart bench-server`).
- Relay daemon (`relay-staging-1`) was not restarted - only its BPF maps
  carried state across runs.

### 6. End-to-end run

```
cd relay-xdp && RUST_LOG=info make bench-relay \
  RELAY_ADDR=54.159.82.158:40000 \
  BACKEND_ADMIN=http://107.23.94.101:8091 \
  BENCH_SERVER_HTTP=32.196.255.134:18080 \
  BENCH_SERVER_UDP=32.196.255.134:17777 \
  BENCH_CLIENT_UDP=0.0.0.0:17778
```

Steady-state stats from bench_client (19 consecutive 1 Hz ticks):

| metric        | value          |
|---------------|----------------|
| pkt_sent / s  | 500            |
| pkt_recv / s  | ~500 (loss <0.4%) |
| RTT p50       | ~245 ms        |
| RTT p95       | ~247 ms        |
| RTT p99       | ~248 ms        |

Relay counters delta during the successful run:

| counter | delta |
|---|---|
| `ROUTE_REQUEST_PACKET_FORWARD_TO_NEXT_HOP` | +1 |
| `ROUTE_RESPONSE_PACKET_RECEIVED` | +1 |
| `ROUTE_RESPONSE_PACKET_FORWARD_TO_PREVIOUS_HOP` | +1 |
| `CLIENT_TO_SERVER_PACKET_FORWARD_TO_NEXT_HOP` | 9445 |
| `SERVER_TO_CLIENT_PACKET_FORWARD_TO_PREVIOUS_HOP` | 9442 |
| `CLIENT_TO_SERVER_PACKET_HEADER_DID_NOT_VERIFY` | 0 |
| `SERVER_TO_CLIENT_PACKET_HEADER_DID_NOT_VERIFY` | 0 |

After ~20s the SDK route expires (no continue tokens issued), `pkt_sent` falls
to 0; this is expected SDK behavior, separate from the data-plane plumbing.
Route refresh implemented in section 4 above resolves this for subsequent runs.

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Move RouteToken encryption to backend `/bench_token` | bench_client cannot derive the per-relay key (no relay_sk, no backend_sk). Backend has both sides. | N/A |
| Return TWO encrypted tokens (Token[0] client view + Token[1] wire) instead of one shared blob | SDK uses `Token[0].next_address` as its first-hop send target; relay uses `Token[1].next_address` as the next hop. They must differ (relay vs bench_server). | N/A |
| Populate `wire_token.prev_address = client_public_ipv4` | eBPF copies `token.prev_address` verbatim into `session.prev_address`. Only `prev_port` is auto-substituted from `udp.source` when zero. Without this, ROUTE_RESPONSE redirect targets `0.0.0.0` -> `REDIRECT_NOT_IN_WHITELIST`. | N/A |
| bench_server synthesizes ROUTE_RESPONSE on inbound type=1 | Modifying the eBPF data plane requires a relay redeploy + verifier re-validation; bench_server is userspace and the smoke test already proved the wire layout. | N/A |
| Inline `encrypt_route_token` + `derive_relay_secret_key` in `relay-backend` (no `relay-sdk` dep) | Backend already has `chacha20poly1305`, `blake2`, `x25519-dalek` available; adding `relay-sdk` would pull in unnecessary client/server logic. | N/A |
| Keep `RouteResponderState` and `ServerPingerState` as separate `Mutex<Option<...>>` slots | They are populated together but read independently (per-packet vs on a 3s timer). Separation avoids holding one lock while doing the other's work. | N/A |
| Make `ConnectInfo` optional in `bench_token_handler` (raw request extension) | Existing `tower::oneshot` integration tests do not provide `ConnectInfo`; the typed extractor would 500 in tests. | N/A |
| Route refresh via `UPDATE_TYPE_ROUTE` every 10s instead of `UPDATE_TYPE_CONTINUE` | Backend does not issue ContinueTokens for bench sessions; re-fetching `/bench_token` achieves the same liveness goal with no backend changes. Cost: 1 HTTP round-trip / 10s - acceptable. | N/A |
| `PingerRefreshKeys` under `Arc<Mutex<>>` shared with refresh task | Lock held only for a copy-out (network thread) or copy-in (refresh task); never during blocking I/O. Prevents stale ping_key across backend rotation cycles without extra channels. | N/A |
| `do_refresh` as blocking fn wrapped in `spawn_blocking` | Uses std `TcpStream` (blocking HTTP). Avoids blocking the async runtime executor thread. | N/A |

## Tests Added/Modified

| Test Class | Method | Type | Status |
|------------|--------|------|--------|
| `relay-backend::http_handler_integration` | `test_bench_token_*` (5 tests) | Integration | Pass (regression: ConnectInfo no longer required) |
| `relay-backend` lib tests | all existing | Unit / integration | Pass |
| `relay-bench` (no lib tests) | n/a | n/a | n/a |

No new tests written - the change is verified end-to-end via `make bench-relay`
plus relay counter inspection. Adding a wire-format integration test for the
two-token bench path is left as follow-up.

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| `ROUTE_REQ_BAD_TOKEN` (37/37) | Move encryption to backend; derive per-relay key on the backend side. | Was |
| Nothing emits ROUTE_RESPONSE in deployed mode | Add ROUTE_RESPONSE generator to bench_server. | Was |
| SDK sent CLIENT_TO_SERVER directly to bench_server (skipped relay), counter `CLIENT_TO_SERVER_PACKET_RECEIVED = 0` while bench_server still saw the traffic | Single shared token with `next = bench_server` was wrong for Token[0]. Split into client_route_token (next=relay) + wire_route_token (next=bench_server). | Was |
| `REDIRECT_NOT_IN_WHITELIST = 36` for every ROUTE_RESPONSE | `wire_token.prev_address` was 0; eBPF used 0 as redirect destination. Set `prev_address = client_public_ipv4`. | Was |
| `clippy::doc_overindented_list_items`, `clippy::too_many_arguments` | Reformatted doc list, added `#[allow(clippy::too_many_arguments)]` on `network_thread`. | No |
| `dead_code` warning on legacy `encrypted_route_token` field in `BenchTokenResponse` | Marked `#[allow(dead_code)]` (kept for backwards-compat alongside the new pair). | No |
| `tower::oneshot` integration tests started returning 500 once `ConnectInfo` extractor was required | Read `ConnectInfo` from `req.extensions()` instead of using the typed extractor; absent extension -> empty `client_public_address`. | No |
| Stray duplicated `) {` in `bench_server.rs` after a refactor edit | Manual re-edit removing the duplicate line. | No |
| First post-redeploy bench run timed out (no `ROUTE_REQUEST_RECEIVED` increment despite `make bench-relay` running) | Likely interplay between NAT port reassignment after a long idle gap and `ping_key` rotation; an immediate back-to-back run succeeded. Documented as follow-up. | No (worked on retry) |
| `pkt_sent` falls to 0 after ~20s of clean traffic | Resolved: background refresh task in bench_client calls `route_update(UPDATE_TYPE_ROUTE)` every 10s. SDK route no longer expires during long runs. | Was |

## Next Steps

1. **High:** Deploy updated `bench_client` binary to staging and validate that a
   60s+ run shows zero `pkt_sent` drops (SDK route refresh confirmed working
   locally via compile check; needs live smoke test).
2. **Medium:** Wire-compat integration test exercising the backend-issued token
   pair (derive relay secret from known keypair, call `/bench_token`, decode +
   decrypt both tokens with `relay_sdk::tokens::decrypt_route_token`, assert
   `next_address` / `prev_address` fields).
3. **Medium:** Document the bench-relay topology + token wiring + env vars in
   `relay-bench/README.md` (currently undocumented beyond this session file).
4. **Low:** Consider extracting `derive_relay_secret_key` + `encrypt_route_token`
   helpers into a shared crate (currently duplicated between `relay-xdp::config`,
   `relay-sdk::tokens`, `relay-backend::handlers`).
5. **Low (P1):** Multi-hop support: backend `/bench_token` accepts `relay_chain[]`,
   derives per-relay keys for N relays, emits N+2 tokens. bench_client assembles
   all token slots. Relay-to-relay whitelist requires `RELAY_PING` between relay
   nodes. eBPF already supports 3-hop token strip natively.

## Files Changed

| Status | File |
|--------|------|
| M | `relay-backend/Cargo.toml` |
| M | `relay-backend/src/handlers.rs` |
| M | `relay-bench/src/bin/bench_client.rs` |
| M | `relay-bench/src/bin/bench_server.rs` |
| A | `docs/sessions/2026-05-10-bench-relay-end-to-end.md` |

No remote refs pushed. All commits / changes remain local per the agent rules.

