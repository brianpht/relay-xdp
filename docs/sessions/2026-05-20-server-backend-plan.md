# Session Summary: server-backend planning

**Date:** 2026-05-20<br>
**Duration:** ~1 session (~8 interactions)<br>
**Focus Area:** server-backend - new matchmaking crate (Flow 6)<br>

## Objectives

- [x] Analyse Flow 6 in ARCHITECTURE.md and identify the role of server_backend
- [x] Analyse bench_client / bench_server to understand token minting + relay-sdk integration
- [x] Design HTTP routes for game server registration, game client session, and infra
- [x] Define game client integration path with relay-sdk after receiving session response
- [x] Define game client token refresh flow (UPDATE_TYPE_CONTINUE)
- [ ] Implement server-backend crate (planned - not yet started)

## Work Completed

### Flow 6 Analysis

Established the full role of `server_backend` in the architecture:

- `relay-backend` computes inter-relay costs via `Optimize2()` and publishes the result
  as a bitpacked binary via `GET /route_matrix`.
- `server_backend` combines the inter-relay cost matrix with client-to-relay and
  server-to-relay proximity (lat/lng based) to select the optimal relay chain for each
  game session.
- Token minting (XChaCha20-Poly1305 per-relay encryption) is delegated to
  `relay-backend`'s existing `GET /bench_token?relay_chain=...&bench_server_addr=...`
  admin endpoint for the simple version.

### Game Server Integration Point

The critical integration constraint: `server_backend` must push session keys to the
game server via webhook (`POST {callback_url}/notify_session`) **before** returning
tokens to the game client. If the game server has not called `ServerInner.register_session()`
before the client sends `ROUTE_REQUEST`, the relay forwards the packet and the game
server drops it (no matching session_id).

Webhook body:

```json
{
  "session_id": 12345678901234567,
  "session_version": 1,
  "session_private_key_hex": "hex(32B)",
  "relay_address": "5.6.7.8:40000",
  "ping_key_hex": "hex(32B)",
  "current_magic_hex": "hex(8B)"
}
```

### Game Client Integration Path

After `POST /sessions` the client must:

1. **Assemble token array** (order is mandatory):

```
tokens_bytes = client_route_token (111B)
             + relay_chain_tokens[0..N] (111B each)
             + zeros_pad (111B)          <- mandatory terminator

num_tokens = relay_chain.len() + 2
```

2. **Initialise relay-sdk** in order:

```
client.open_session(server_udp_addr, relay_secret_key)
inner.pump_commands()

client.route_update(UPDATE_TYPE_ROUTE, num_tokens, tokens_bytes, magic, client_ext_addr)
inner.pump_commands()
```

3. **Send CLIENT_PING** burst to `relay_chain[0]` before the SDK fires `ROUTE_REQUEST`
   so the relay's `whitelist_map` has an entry for the client IP:port. Without this
   the eBPF drops every non-ping packet from the client including ROUTE_REQUEST.

4. **Refresh tokens every 10 s** via `POST /sessions/{id}/refresh`. Use
   `UPDATE_TYPE_CONTINUE` (not `ROUTE`) on the SDK side so the relay runs
   CONTINUE_REQUEST instead of ROUTE_REQUEST - cheaper because the session already
   exists in `session_map`.

### Session Response Schema

Full response from `POST /sessions`:

| Field | Type | Description |
|---|---|---|
| `session_id` | u64 | Unique session identifier |
| `session_version` | u8 | Monotonic version (increments on refresh) |
| `session_private_key` | hex(32B) | Used for SHA-256 HMAC verify of ROUTE_RESPONSE |
| `relay_secret_key` | hex(32B) | relay[0] XChaCha20 key - passed to `open_session()` |
| `client_route_token` | hex(111B) | Token[0]: SDK reads locally, next = relay[0] |
| `relay_chain_tokens` | hex(111B)[] | Token[1..N]: one per relay, placed in token array |
| `relay_chain` | string[] | `["IP:PORT", ...]` relay addresses, first hop first |
| `server_udp_addr` | string | `"IP:PORT"` of the game server |
| `current_magic` | hex(8B) | DDoS filter epoch token for pittle/chonkle |
| `ping_key` | hex(32B) | SHA-256 CLIENT_PING token key |
| `client_public_address` | string | Client post-NAT public address detected by backend |

### Planned Module Structure

```
server-backend/
+-- Cargo.toml           tokio, axum, serde_json, anyhow, reqwest, uuid, relay-backend (path)
+-- src/
    +-- main.rs          entry point: spawn poller task + axum server
    +-- config.rs        env vars (SERVER_BACKEND_PORT, RELAY_BACKEND_URL, etc.)
    +-- state.rs         AppState: route matrix RwLock + server registry HashMap
    +-- poller.rs        1 Hz GET /route_matrix -> RouteMatrix::read() -> state
    +-- selector.rs      select_chain(): haversine scoring over RouteEntry list
    +-- handlers.rs      HTTP handlers (all routes below)
+-- tests/
    +-- integration.rs   3+ integration tests (no live relay required)
```

### HTTP Routes

**Game Server Registration:**

| Route | Method | Request | Response |
|---|---|---|---|
| `POST /servers` | POST | `{ server_id?, udp_addr, lat, lng, region?, callback_url }` | `{ server_id: Uuid }` |
| `DELETE /servers/{id}` | DELETE | - | `204` |
| `GET /servers` | GET | - | `[{ server_id, udp_addr, region, registered_at }]` |

**Game Client Session:**

| Route | Method | Request | Response |
|---|---|---|---|
| `POST /sessions` | POST | `{ server_id, client_lat, client_lng, client_ip? }` | SessionResponse (full schema above) |
| `POST /sessions/{id}/refresh` | POST | `{ client_lat, client_lng }` | SessionResponse with `session_version++` |
| `DELETE /sessions/{id}` | DELETE | - | `204` |

**Infra / Monitoring:**

| Route | Method | Response |
|---|---|---|
| `GET /health` | GET | `"OK"` |
| `GET /relay_status` | GET | `{ num_relays, last_matrix_update_ms, matrix_age_ms }` |

### Chain Selection Algorithm

`select_chain(client_lat, client_lng, server_lat, server_lng, matrix)`:

1. Parse `RouteMatrix` via `relay_backend::route_matrix::RouteMatrix::read()`.
2. For each `RouteEntry` (relay pair in triangular matrix):
   - `score = haversine(client, relay[0]) + route_cost[0] + haversine(relay[n], server)`
   - Proximity model: 1 ms per 100 km (Haversine), capped at 255 ms per relay.
3. Return relay `Vec<SocketAddrV4>` for the entry with lowest score.
4. Return `503` if route matrix is empty or not yet populated.

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Delegate token minting to relay-backend `/bench_token` | Avoids duplicating X25519 key exchange and per-relay symmetric key management in simple version. Can self-mint later by adding `RELAY_BACKEND_PRIVATE_KEY`. | N/A |
| Webhook must succeed before returning tokens to client | Guarantees game server has called `register_session()` before client sends ROUTE_REQUEST. 503 on webhook timeout prevents broken sessions. | N/A |
| Haversine + 1 ms / 100 km as proximity proxy | No real client-to-relay latency available at matchmaking time. Haversine is a reasonable geographic proxy. Can be overridden per-request via optional `client_rtt_to_relay` map. | N/A |
| Depend on relay-backend as path lib | Reuse `RouteMatrix::read()` and `RouteEntry` without re-implementing bitpacked parser. relay-backend already has a lib.rs. | N/A |
| In-memory HashMap for server registry | Sufficient for sample/demo scope. Upgrade to Redis (same pattern as relay-backend) if HA or multi-instance needed. | N/A |
| UPDATE_TYPE_CONTINUE on token refresh | Session already exists in relay session_map. CONTINUE_REQUEST is cheaper than ROUTE_REQUEST (no token chain re-parse by eBPF). Mirrors bench_client pattern. | N/A |

## Tests Added/Modified

No files changed this session (planning only). Tests will be added during implementation:

| File | Test | Type | Status |
|------|------|------|--------|
| `server-backend/src/selector.rs` | `test_select_chain_empty_matrix` | Unit | Done |
| `server-backend/src/selector.rs` | `test_select_chain_single_relay` | Unit | Done |
| `server-backend/src/selector.rs` | `test_select_chain_picks_london_as_entry` | Unit | Done |
| `server-backend/src/selector.rs` | `test_haversine_ms_same_point` | Unit | Done |
| `server-backend/src/selector.rs` | `test_haversine_ms_capped_at_255` | Unit | Done |
| `server-backend/tests/integration.rs` | `test_register_and_list_servers` | Integration | Done |
| `server-backend/tests/integration.rs` | `test_select_chain_with_fixture_matrix` | Integration | Done |
| `server-backend/tests/integration.rs` | `test_session_reject_unknown_server` | Integration | Done |
| `server-backend/tests/integration.rs` | `test_session_refresh_increments_version` | Integration | Done |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| Token minting requires per-relay symmetric key (X25519 KX) | Delegate to relay-backend `/bench_token` admin endpoint for simple version | No |
| Route matrix is bitpacked binary (non-trivial to parse standalone) | Add relay-backend as path dependency and reuse `RouteMatrix::read()` | No |
| CLIENT_PING must arrive before ROUTE_REQUEST or eBPF drops packets | Document clearly in client integration guide; bench_client pattern shows the burst approach | No |

## Next Steps

1. ~~**High:** Create `server-backend/Cargo.toml` and register in workspace `Cargo.toml`~~ **DONE** (2026-05-21)
2. ~~**High:** Implement `config.rs`, `state.rs`, `poller.rs` (1 Hz route matrix fetch)~~ **DONE** (2026-05-21)
3. ~~**High:** Implement `selector.rs` - `select_chain()` with Haversine scoring~~ **DONE** (2026-05-21)
4. ~~**High:** Implement `handlers.rs` - all 8 routes including webhook notify~~ **DONE** (2026-05-21)
5. ~~**High:** Implement `main.rs` - spawn poller + axum server~~ **DONE** (2026-05-21)
6. ~~**High:** Run CI checks: `cargo fmt --all` -> `cargo clippy --workspace --lib --bins -- -D warnings` -> `cargo test --workspace`~~ **DONE** (2026-05-21) - all pass, zero warnings
7. ~~**Medium:** Add 4 integration tests in `server-backend/tests/integration.rs`~~ **DONE** (2026-05-21)
8. ~~**Low:** Add `server-backend` to `README.md` workspace layout section~~ **DONE** (2026-05-21)

## Files Changed

| Status | File |
|--------|------|
| Added | `server-backend/Cargo.toml` |
| Added | `server-backend/src/lib.rs` |
| Added | `server-backend/src/main.rs` |
| Added | `server-backend/src/config.rs` |
| Added | `server-backend/src/state.rs` |
| Added | `server-backend/src/poller.rs` |
| Added | `server-backend/src/selector.rs` |
| Added | `server-backend/src/handlers.rs` |
| Added | `server-backend/tests/integration.rs` |
| Modified | `Cargo.toml` (added server-backend to workspace members) |
| Modified | `README.md` (added server-backend to workspace layout + configuration sections) |

