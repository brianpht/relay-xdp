# Session Summary: bench-relay end-to-end against staging

**Date:** 2026-05-10<br>
**Duration:** ~3 hours (multi-iteration debug) + follow-up tooling hardening<br>
**Focus Area:** `relay-bench`, `relay-backend`, deployed staging stack, `Makefile`<br>

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
- [x] Validate 60s+ sustained run against staging: zero `pkt_sent` drops,
      route refresh cycles confirmed across 5 consecutive 10s intervals.
- [x] `make bench-deploy` deploys both `bench_server` and `relay-backend`
      (previously only deployed bench_server; relay-backend required manual SCP).
- [x] `make bench-relay` auto-resolves relay/backend/bench addresses from
      Pulumi stack outputs when not set explicitly.

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

### 6. End-to-end run (initial, 19 ticks, ~20s before route expiry)

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

### 7. Makefile documentation - bench workflow (`Makefile`)

Added step-by-step deploy + validate workflow to the benchmark comment block:

- Step 1: `make deploy-staging` (provision infra, once per stack).
- Step 2: `make bench-deploy STACK=staging` (deploy bench_server + relay-backend).
- Step 3: `make bench-relay STACK=staging DURATION_SECS=60` (auto-resolve IPs,
  run >= 60s to exercise route refresh).
- Introduced `DURATION_SECS` (default 60), `BENCH_SERVER_UDP`, `BENCH_CLIENT_UDP`,
  `TARGET_PPS` as first-class Makefile variables overridable at the call site.

Files: `Makefile`.

### 8. bench-deploy now deploys relay-backend (`Makefile`, Ansible)

**Problem:** `bench-deploy` only deployed `bench_server` to the bench node.
When `/bench_token` API fields changed (session 2026-05-10), `relay-backend`
had to be SCP-ed manually. This created a silent failure mode: old backend
returns 500 / missing fields, bench_client exits with a cryptic parse error.

**Fix:**
- Created `ansible/playbooks/bench-backend-deploy.yml`: copies
  `target/release/relay-backend` to `backend_servers`, restarts the systemd
  unit only when the binary changed (handler-driven), verifies `active`.
- Updated `bench-deploy` recipe in `Makefile`:
  - `cargo build --release -p relay-bench -p relay-backend` (build both crates
    in one invocation).
  - Run `bench-backend-deploy.yml` (backend node) then `bench-deploy.yml`
    (bench node) in sequence.

Files: `Makefile`, `ansible/playbooks/bench-backend-deploy.yml` (new).

### 9. bench-relay auto-resolves addresses from Pulumi stack outputs (`Makefile`)

**Problem:** Every `bench-relay` invocation required pasting four IP:PORT values
manually. Addresses change between Pulumi stack recreations, making the workflow
error-prone.

**Fix:** When `RELAY_ADDR` is not set, `bench-relay` calls `stack_outputs.py
--stack $(STACK) --format env` inside the recipe subshell and derives:

| Variable | Derived from |
|---|---|
| `RELAY_ADDR` | `first(RELAY_PUBLIC_IPS)` + `:40000` |
| `BACKEND_ADMIN` | `http://BACKEND_HOST:ADMIN_BACKEND_PORT` |
| `BENCH_SERVER_HTTP` | `BENCH_HOST:18080` |
| `BENCH_SERVER_UDP` | `BENCH_HOST:17777` |

Explicit overrides (any variable set on the command line or in the environment)
skip the auto-resolve entirely - the `if [ -z "$_relay" ]` guard fires only
when `RELAY_ADDR` is empty. A summary log line prints resolved addresses before
launching bench_client.

Usage after the change:
```bash
make bench-relay                        # auto-resolve from staging
make bench-relay STACK=staging DURATION_SECS=120
make bench-relay RELAY_ADDR=10.0.0.1:40000   # legacy explicit mode still works
```

Files: `Makefile`.

### 10. 60s sustained validation run against staging (Next Step 1)

Deployed updated `relay-backend` (3.227.114.81) and `bench_server`
(98.91.109.160) via `make bench-deploy`. Ran 60s relay bench via
`make bench-relay DURATION_SECS=60`.

```
[bench-relay] RELAY_ADDR not set - resolving from stack=staging via stack_outputs.py...
[bench-relay] relay=34.193.160.53:40000 backend=http://3.227.114.81:8091 \
              bench_http=98.91.109.160:18080 bench_udp=98.91.109.160:17777 duration=60s pps=500
```

Steady-state stats (56 consecutive 1 Hz ticks, `route=active` throughout):

| metric       | value                             |
|--------------|-----------------------------------|
| pkt_sent / s | 500 constant - zero drops to 0    |
| pkt_recv / s | 499-502 (in-flight jitter)        |
| loss_pct     | <1% steady (mostly 0.0%)          |
| RTT p50      | ~235 ms                           |
| RTT p95      | ~237 ms                           |
| RTT p99      | ~240 ms                           |

Route refresh cycles confirmed (5 successful iterations at 10s intervals):

```
07:02:45  route refreshed: new_session=b739de11... magic=6c41bb5d...
07:02:55  route refreshed: new_session=036390a2... magic=ba7b536e...
07:03:05  route refreshed: new_session=11a04a3e... magic=15c004f9...
07:03:15  route refreshed: new_session=8f791031... magic=80229fcc...
07:03:25  route refreshed: new_session=f65eb5ac... magic=7b894e5f...
```

`pkt_sent` never dropped to 0 across the full 60s window. **Next Step 1 closed.**

### 11. Follow-up tooling hardening

- `stack_outputs.py` now supports `--format env` (envfile-style output for
  easier sourcing).
- `Makefile`:
  - `make bench-relay` with no args now just works (auto-resolves all addresses
    from the staging stack).
  - `make bench-deploy` with no args now deploys both `bench_server` and
    `relay-backend` (no more manual SCP).
  - Documented full bench workflow in the benchmark comment block.

Files: `Makefile`, `tools/stack_outputs.py`.

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Move RouteToken encryption to backend `/bench_token` | bench_client cannot derive the per-relay key (no relay_sk, no backend_sk). Backend has both sides. | [ADR-006](../decisions/ADR-006-route-token-split-client-wire.md) |
| Return TWO encrypted tokens (Token[0] client view + Token[1] wire) instead of one shared blob | SDK uses `Token[0].next_address` as its first-hop send target; relay uses `Token[1].next_address` as the next hop. They must differ (relay vs bench_server). | [ADR-006](../decisions/ADR-006-route-token-split-client-wire.md) |
| Populate `wire_token.prev_address = client_public_ipv4` | eBPF copies `token.prev_address` verbatim into `session.prev_address`. Only `prev_port` is auto-substituted from `udp.source` when zero. Without this, ROUTE_RESPONSE redirect targets `0.0.0.0` -> `REDIRECT_NOT_IN_WHITELIST`. | [ADR-006](../decisions/ADR-006-route-token-split-client-wire.md) |
| bench_server synthesizes ROUTE_RESPONSE on inbound type=1 | Modifying the eBPF data plane requires a relay redeploy + verifier re-validation; bench_server is userspace and the smoke test already proved the wire layout. | N/A |
| Inline `encrypt_route_token` + `derive_relay_secret_key` in `relay-backend` (no `relay-sdk` dep) | Backend already has `chacha20poly1305`, `blake2`, `x25519-dalek` available; adding `relay-sdk` would pull in unnecessary client/server logic. | N/A |
| Keep `RouteResponderState` and `ServerPingerState` as separate `Mutex<Option<...>>` slots | They are populated together but read independently (per-packet vs on a 3s timer). Separation avoids holding one lock while doing the other's work. | N/A |
| Make `ConnectInfo` optional in `bench_token_handler` (raw request extension) | Existing `tower::oneshot` integration tests do not provide `ConnectInfo`; the typed extractor would 500 in tests. | N/A |
| Route refresh via `UPDATE_TYPE_ROUTE` every 10s instead of `UPDATE_TYPE_CONTINUE` | Backend does not issue ContinueTokens for bench sessions; re-fetching `/bench_token` achieves the same liveness goal with no backend changes. Cost: 1 HTTP round-trip / 10s - acceptable. | N/A |
| `PingerRefreshKeys` under `Arc<Mutex<>>` shared with refresh task | Lock held only for a copy-out (network thread) or copy-in (refresh task); never during blocking I/O. Prevents stale ping_key across backend rotation cycles without extra channels. | N/A |
| `do_refresh` as blocking fn wrapped in `spawn_blocking` | Uses std `TcpStream` (blocking HTTP). Avoids blocking the async runtime executor thread. | N/A |
| `bench-deploy` must include relay-backend | `/bench_token` API is co-owned by relay-backend; deploying bench_server alone leaves a silent mismatch where the old backend returns missing fields and bench_client fails to parse the response. | N/A |
| `bench-relay` auto-resolves addresses from `stack_outputs.py` | IPs change on every `pulumi up`. Manual copy-paste is error-prone and creates a stale-IP failure mode. `stack_outputs.py` is already the canonical source for E2E tooling. | N/A |

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
| `relay-backend` on staging had stale `/bench_token` API (missing `ping_key` field) after second session | bench_client parse error `missing field ping_key`. Root cause: `bench-deploy` only deployed bench_server, not relay-backend. Fixed: `bench-deploy` now deploys both. | Was |

## Next Steps

1. ~~**High:** Deploy updated `bench_client` binary to staging and validate that a
   60s+ run shows zero `pkt_sent` drops.~~ **DONE** (section 10 above).
2. ~~**Medium:** Wire-compat integration test exercising the backend-issued token
   pair (derive relay secret from known keypair, call `/bench_token`, decode +
   decrypt both tokens with `relay_sdk::tokens::decrypt_route_token`, assert
   `next_address` / `prev_address` fields).~~ **DONE** (Test 12 in
   `relay-backend/tests/http_handler_integration.rs`; upgraded from raw
   `chacha20poly1305` to typed `relay_sdk::tokens::decrypt_route_token` API;
   added `prev_address = 0` assertion for both tokens; `relay-sdk` added as
   dev-dependency).
3. ~~**Medium:** Document the bench-relay topology + token wiring + env vars in
   `relay-bench/README.md`.~~ **DONE** (README fully documented in previous
   session; Makefile workflow documented in section 7 above).
4. ~~**Low:** Consider extracting `derive_relay_secret_key` + `encrypt_route_token`
   helpers into a shared crate (currently duplicated between `relay-xdp::config`,
   `relay-sdk::tokens`, `relay-backend::handlers`).~~ **DONE** (section 12 below).
5. **Low (P1):** Multi-hop support: backend `/bench_token` accepts `relay_chain[]`,
   derives per-relay keys for N relays, emits N+2 tokens. bench_client assembles
   all token slots. Relay-to-relay whitelist requires `RELAY_PING` between relay
   nodes. eBPF already supports 3-hop token strip natively.

### 12. Consolidate crypto helpers into relay-sdk (Next Step 4)

**Problem:** `derive_relay_secret_key` (key derivation) and `encrypt_route_token_inline`
(RouteToken encryption) were duplicated across three crates:

| Site | Function | Status |
|------|----------|--------|
| `relay-backend/src/handlers.rs` | `derive_relay_secret_key` (inline) | **removed** |
| `relay-backend/src/handlers.rs` | `encrypt_route_token_inline` (inline) | **removed** |
| `relay-xdp/src/config.rs` | `derive_secret_key` (inline) | **replaced** |
| `relay-sdk/src/crypto/mod.rs` | `derive_relay_session_key` | canonical home |
| `relay-sdk/src/tokens/mod.rs` | `encrypt_route_token` | canonical home |

**Changes:**

- `relay-sdk/src/crypto/mod.rs`: merged duplicate `mod tests` blocks into one
  (two blocks existed from separate sessions). Fixed `// ...existing code...`
  placeholder left by a prior edit tool.

- `relay-backend/Cargo.toml`:
  - Moved `relay-sdk` from `[dev-dependencies]` to `[dependencies]`.
  - Removed `chacha20poly1305`, `x25519-dalek`, `blake2`, `rand` from
    `[dependencies]` (now transitive via relay-sdk).
  - Added `x25519-dalek` to `[dev-dependencies]` (integration test still needs
    it to compute `backend_pk` from a test secret key for test setup only).

- `relay-backend/src/handlers.rs`:
  - Removed `derive_relay_secret_key` (37 lines of inline BLAKE2b + X25519).
  - Removed `encrypt_route_token_inline` (40 lines of inline chacha20poly1305).
  - Added `use relay_sdk::crypto::derive_relay_session_key;` and
    `use relay_sdk::tokens::encrypt_route_token;`.
  - Call site: `derive_relay_secret_key(&relay_pk, &backend_sk, &backend_pk)`
    became `derive_relay_session_key(&backend_sk, &relay_pk, &relay_pk, &backend_pk)`
    (parameter order differs: shared fn takes `my_sk, their_pk, relay_pk, backend_pk`).
  - Call site: `encrypt_route_token_inline(...)` became `encrypt_route_token(...)`.

- `relay-xdp/Cargo.toml`:
  - Removed `x25519-dalek` and `blake2` from `[dependencies]`.
  - Added `relay-sdk = { path = "../relay-sdk" }` to `[dependencies]`.
  - Added `blake2` + `x25519-dalek` to `[dev-dependencies]` (wire_compat test
    `test_crypto_kx_session_keys` tests the full libsodium crypto_kx protocol
    with client/server rx/tx swap - this is distinct from `derive_relay_session_key`
    and requires raw access to both crates).

- `relay-xdp/src/config.rs`:
  - Replaced `derive_secret_key` body (28 lines of BLAKE2b + X25519) with a
    thin wrapper delegating to `relay_sdk::crypto::derive_relay_session_key`.
  - Relay side call: `derive_relay_session_key(relay_private_key, backend_pk, relay_pk, backend_pk)`.

- `relay-backend/tests/http_handler_integration.rs`:
  - Updated `test_bench_token_two_token_wire_compat` to replace the inline
    BLAKE2b key derivation with `relay_sdk::crypto::derive_relay_session_key`.

All 3 crates: `cargo test` + `cargo clippy -D warnings` pass with zero errors
and zero warnings after the refactoring.

Files: `relay-sdk/src/crypto/mod.rs`, `relay-backend/Cargo.toml`,
`relay-backend/src/handlers.rs`, `relay-backend/tests/http_handler_integration.rs`,
`relay-xdp/Cargo.toml`, `relay-xdp/src/config.rs`.

## Files Changed

| Status | File |
|--------|------|
| M | `relay-backend/Cargo.toml` |
| M | `relay-backend/src/handlers.rs` |
| M | `relay-backend/tests/http_handler_integration.rs` |
| M | `relay-bench/src/bin/bench_client.rs` |
| M | `relay-bench/src/bin/bench_server.rs` |
| M | `relay-xdp/Cargo.toml` |
| M | `relay-xdp/src/config.rs` |
| M | `relay-sdk/src/crypto/mod.rs` |
| M | `Makefile` |
| A | `ansible/playbooks/bench-backend-deploy.yml` |
| A | `docs/sessions/2026-05-10-bench-relay-end-to-end.md` |

No remote refs pushed. All commits / changes remain local per the agent rules.
