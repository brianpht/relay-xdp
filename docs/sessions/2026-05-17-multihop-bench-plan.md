# Session Summary: multi-hop bench planning (Next Step 5)

**Date:** 2026-05-17<br>
**Duration:** ~1 hour (planning + codebase analysis)<br>
**Focus Area:** `relay-bench`, `relay-backend`, `relay-sdk`, `relay-xdp-common`, `Makefile`<br>

## Objectives

- [x] Run `make bench-deploy` + `make bench-relay` against staging to confirm single-hop baseline.
- [x] Analyse eBPF token-strip logic and SDK `MAX_TOKENS` to derive multi-hop constraints.
- [x] Produce an implementation plan for multi-hop bench support (Next Step 5 from
      `docs/sessions/2026-05-10-bench-relay-end-to-end.md`).
- [x] Implement `MAX_RELAY_HOPS` constant in `relay-xdp-common` + align `MAX_TOKENS` in `relay-sdk`.
- [x] Extend `/bench_token` to accept `relay_chain` and emit per-hop encrypted tokens.
- [x] Extend `bench_client` to assemble `N+2` token vector and support `RELAY_CHAIN` env var.
- [x] Update `Makefile` with `RELAY_CHAIN` variable and refreshed bench workflow docs.
- [x] Validate 2-hop run against staging (relay-staging-1 -> relay-staging-2 -> bench-staging-1).

## Work Completed

### 1. Baseline bench-deploy + bench-relay run (2026-05-17)

Successfully deployed updated `relay-backend` and `bench_server` to staging, then ran a
60 s relay bench confirming single-hop baseline is healthy.

`make bench-deploy STACK=staging`:
- `backend-staging-1` (52.2.193.206): `relay-backend` deployed + `active`
- `bench-staging-1` (34.207.45.215): `bench_server` deployed + `active`

`make bench-relay STACK=staging DURATION_SECS=60` (auto-resolved addresses):

| metric       | value                          |
|--------------|--------------------------------|
| relay         | 52.201.126.193:40000           |
| pkt_sent / s | 500 constant - zero drops to 0 |
| pkt_recv / s | 498-502                        |
| loss_pct     | < 0.8%, mostly 0.0%            |
| RTT p50      | ~260 ms                        |
| RTT p95      | ~262 ms                        |
| RTT p99      | ~264 ms                        |
| route        | `active` throughout 60 s       |

Route refresh confirmed (5 cycles at 10 s intervals) - `pkt_sent` never dropped to 0.

### 2. eBPF token-strip analysis

Reviewed `relay-xdp-ebpf/src/main.rs::handle_route_request`:

```
// Minimum size check at each relay (packet_data after ETH+IP+UDP headers):
18 + RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES + RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES <= payload_bytes
=> 18 + 111 + 111 = 240 bytes minimum
```

eBPF strips exactly one token (111 B) per relay via `bpf_xdp_adjust_head`, then forwards
the remainder. There is no hop counter - the limit is pure packet size.

Token layout for N relays, `num_tokens = N+2`:

```
Token[0]    111 B   client_route_token  next = relay1     SDK decrypts locally
Token[1]    111 B   wire token relay1   next = relay2     encrypted with relay1 key
...
Token[N]    111 B   wire token relayN   next = bench_srv  encrypted with relayN key
Token[N+1]  111 B   zeros               trailing pad
```

ROUTE_REQUEST body = `(N+1) * 111` bytes. With `RELAY_MTU = 1200`:
max body = 1200 - 18 = 1182 B -> at most 10 wire tokens -> theoretical max = 9 relays.

**Design cap = 3 relays**: matches staging topology (3 relay nodes) and is the practical
safe limit for production deployments. `MAX_RELAY_HOPS = 3` in source gives `num_tokens_max = 5`
and ROUTE_REQUEST = `18 + 4*111 = 462 B` - well within MTU.

`relay-sdk/src/constants.rs` currently has `MAX_TOKENS = 7` (not derived from any hop
constant). This is mis-aligned: it allows up to 5-relay chains which are untested and
unsupported in staging. See Decision 1 below.

### 3. Implementation plan

#### 3.1 relay-xdp-common/src/lib.rs - Add MAX_RELAY_HOPS

Add one constant as the single source of truth for max relay chain length:

```rust
pub const MAX_RELAY_HOPS: usize = 3;
```

This is shared by eBPF (verifier sees it at compile time), userspace relay-xdp,
relay-backend, and (via relay-sdk dep) bench_client.

#### 3.2 relay-sdk/src/constants.rs - Align MAX_TOKENS

Change:
```rust
// Before
pub const MAX_TOKENS: usize = 7;

// After (= MAX_RELAY_HOPS + 2 from relay-xdp-common)
pub const MAX_TOKENS: usize = 5; // MAX_RELAY_HOPS(3) + client_view(1) + zeros(1)
```

Existing tests use `num_tokens = 2` and `3` - both remain inside `[2..=5]`, no test changes.

#### 3.3 relay-backend/src/handlers.rs - relay_chain query + N-hop token build

1. Extend `BenchTokenQuery`:
   ```rust
   relay_chain: Option<Vec<String>>,  // "IP:PORT" list, supersedes relay_addr when set
   ```

2. Clamp immediately:
   ```rust
   if relay_chain.len() > relay_xdp_common::MAX_RELAY_HOPS {
       return StatusCode::BAD_REQUEST.into_response();
   }
   ```

3. `build_encrypted_bench_token_chain(relay_chain, bench_server_addr, ...)`:
   - For each relay[i]:
     - Derive `key_i = derive_relay_session_key(backend_sk, relay_pk_i, relay_pk_i, backend_pk)`
     - Build Token[i+1]:
       - `next_address = relay[i+1].ip` (or `bench_server` for last hop)
       - `prev_address = relay[i-1].public_ip` from `relay_data.relay_addresses` (or
         `client_public_ipv4` for i=0)
       - `prev_port = 0` (eBPF auto-substitutes `udp.source` for first-hop; for inner hops
         the relay's outbound port is not known ahead of time so leave 0)
     - Encrypt with `key_i`
   - Return `client_route_token` (Token[0], encrypted with `key_0 = relay1 key`) +
     `relay_chain_tokens: Vec<hex>` (Token[1..N])

4. JSON response adds:
   ```json
   "relay_chain_tokens": ["<hex111B>", "<hex111B>", ...]
   ```
   Existing `client_route_token` / `wire_route_token` / `relay_secret_key` kept for
   1-hop backward compat when `relay_addr` (not `relay_chain`) is used.

#### 3.4 relay-bench/src/bin/bench_client.rs - Token assembly + RELAY_CHAIN env

1. Extend `BenchTokenResponse`:
   ```rust
   #[serde(default)]
   relay_chain_tokens: Vec<String>,
   ```

2. Extend `BenchMode::Relay`:
   ```rust
   relay_chain: Vec<String>,  // populated from RELAY_CHAIN env var
   ```
   `RELAY_CHAIN` env var = comma-separated `IP:PORT` list. Falls back to single
   `RELAY_ADDR` when `RELAY_CHAIN` is not set (no breaking change).

3. `setup_relay_route` with chain:
   ```rust
   let mut tokens = Vec::with_capacity(ENCRYPTED_ROUTE_TOKEN_BYTES * (N + 2));
   tokens.extend_from_slice(&client_route_token);          // Token[0]
   for wire_tok in &relay_chain_tokens { tokens.extend_from_slice(wire_tok); } // Token[1..N]
   tokens.extend_from_slice(&[0u8; ENCRYPTED_ROUTE_TOKEN_BYTES]);              // Token[N+1]
   client.route_update(UPDATE_TYPE_ROUTE, N + 2, tokens, magic, client_ext);
   ```

4. `RouteRefreshConfig` carries `relay_chain: Vec<String>` so the 10 s refresh task
   re-fetches the N-hop token set and reassembles the same token vector.

5. `open_session` still uses `relay1_secret_key` (unchanged - relay1 key is stable
   across refreshes because keypairs are stable).

#### 3.5 Makefile - RELAY_CHAIN variable

```makefile
RELAY_CHAIN ?=   # comma-separated IP:PORT list for multi-hop: relay1,relay2,...
```

`bench-relay` recipe: when `RELAY_CHAIN` is non-empty pass `RELAY_CHAIN="$(RELAY_CHAIN)"`
to `bench_client` env instead of `RELAY_ADDR`.

Usage:
```bash
make bench-relay RELAY_CHAIN=52.201.126.193:40000,52.48.191.174:40000 DURATION_SECS=60
make bench-relay RELAY_ADDR=52.201.126.193:40000 DURATION_SECS=60   # legacy 1-hop
```

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| `MAX_RELAY_HOPS = 3` as single source of truth in `relay-xdp-common` | Shared by eBPF + userspace + relay-sdk via existing dep chain. Prevents the current mis-alignment between `MAX_TOKENS = 7` (SDK) and the 3-hop design intent. | N/A |
| Lower `MAX_TOKENS` from 7 to 5 (`MAX_RELAY_HOPS + 2`) | 5-relay chains are untested, unsupported in staging, and add verifier risk. Aligning to 3 makes the invariant explicit without sacrificing any real use case. | N/A |
| `relay_chain[]` query param supersedes `relay_addr` when present | Backward compat: existing single-hop bench calls continue to use `relay_addr` unchanged. New multi-hop path is opt-in. | N/A |
| `prev_port = 0` for inner-hop wire tokens (relay[i] -> relay[i+1]) | eBPF auto-substitutes `udp.source` only when `prev_port == 0` (first-hop guard). For inner hops the relay's outbound ephemeral port is unknown at token-build time; leaving 0 relies on the same eBPF substitution, which fires correctly at every hop. | N/A |
| `open_session` key unchanged across multi-hop refresh | `relay_secret_key = relay1 key` is derived from stable X25519 keypairs; it is the same value after every refresh. Re-deriving would be a no-op and adds complexity. | N/A |

## Tests Added/Modified

| Test Class | Method | Type | Status |
|------------|--------|------|--------|
| `relay-backend::http_handler_integration` | `test_bench_token_chain_two_relays` (new) | Integration | Pass |
| `relay-sdk` route manager | existing `begin_next_route` tests (`num_tokens = 2, 3`) | Unit | Pass (unchanged - stay within new `MAX_TOKENS = 5`) |
| `relay-xdp-common` wire_compat | existing struct size checks | Unit | Pass (no struct changes) |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| `MAX_TOKENS = 7` in relay-sdk allows 5-relay chains which eBPF + staging do not support | Lower to `MAX_RELAY_HOPS + 2 = 5`; add `MAX_RELAY_HOPS` constant to relay-xdp-common | Planning only (no runtime failure yet) |
| `prev_address` for inner-hop tokens (relay[i] -> relay[i+1]) is unknown to the client | Use `relay_data.relay_addresses[relay_index]` in `build_encrypted_bench_token_chain` - backend knows all relay public IPs from `relays.json` | Planning only |

## Next Steps

1. ~~**High:** Implement Buoc 3.1 + 3.2 (`MAX_RELAY_HOPS` + `MAX_TOKENS` alignment). CI gate
   (`cargo fmt`, `cargo clippy -D warnings`, `cargo test --workspace`) must pass before
   proceeding.~~ **Done 2026-05-17.**
2. ~~**High:** Implement Buoc 3.3 (relay-backend `/bench_token` chain support) with
   integration test `test_bench_token_chain_two_relays` (derive keys for 2 known relay
   keypairs, call `/bench_token?relay_chain[]=...`, decrypt both wire tokens, assert
   `next_address` / `prev_address`).~~ **Done 2026-05-17.**
3. ~~**High:** Implement Buoc 3.4 + 3.5 (bench_client `RELAY_CHAIN` + Makefile). Run
   `make bench-relay RELAY_CHAIN=52.201.126.193:40000,52.48.191.174:40000 DURATION_SECS=60`
   against staging. Confirm `CLIENT_TO_SERVER_PACKET_FORWARD_TO_NEXT_HOP` on both
   relay-staging-1 and relay-staging-2.~~ **Done 2026-05-17** (code + CI pass + staging validation).

   Staging 2-hop validation run summary (`make bench-relay RELAY_CHAIN=52.201.126.193:40000,52.48.191.174:40000 DURATION_SECS=20`):

   | metric            | value                                         |
   |-------------------|-----------------------------------------------|
   | mode              | `relay-multi-hop`                             |
   | hops              | 2                                             |
   | pkt_sent/s        | 500 constant                                  |
   | pkt_recv/s        | 498-502 (steady state)                        |
   | loss_pct          | ~0% steady (first second 31% startup)         |
   | RTT p50           | ~382 ms (~+128 ms vs single-hop)              |
   | RTT p95           | ~384 ms                                       |
   | RTT p99           | ~385 ms                                       |
   | route             | `active` throughout                           |

   Per-relay counter deltas (eBPF stats_map dump):

   | counter                                       | relay1 | relay2 |
   |-----------------------------------------------|--------|--------|
   | `RELAY_COUNTER_ROUTE_REQUEST_PACKET_FORWARD_TO_NEXT_HOP` (34) | 4      | 6      |
   | `RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_FORWARD_TO_NEXT_HOP` (77) | 9999   | 13997  |
   | `RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_FORWARD_TO_PREVIOUS_HOP` (87) | 9996   | 13994  |

   Both relays forwarded ROUTE_REQUEST, CLIENT_TO_SERVER, and SERVER_TO_CLIENT
   packets, confirming the 2-hop data path is functional end-to-end.

   Pre-existing latent bug exposed and fixed during staging validation:
   - `relay-xdp/src/ping_thread.rs` constructed `relay_map` keys with the port
     stored in the wrong half of the u64 key (`(port as u32).to_be() & 0xFFFF`
     yielded `0x0000` for any port). eBPF reads the key as
     `((*ip).saddr as u64) << 32 | (*udp).source as u64`, so every relay-to-relay
     RELAY_PING failed `RELAY_PING_PACKET_UNKNOWN_RELAY` (counter 15) and
     `update_whitelist` was never reached - leaving peer relays missing from
     `whitelist_map`. The bug was harmless in single-hop (no relay-to-relay
     forwarding) but caused 100% packet drop at `REDIRECT_NOT_IN_WHITELIST`
     (counter 124) when relay1 tried to forward ROUTE_REQUEST to relay2. Fix:
     use `port.to_be() as u64` (u16-level byte swap) so the key low 16 bits
     match what eBPF reads from `(*udp).source`.
4. **Medium:** Add `test_bench_token_chain_three_relays` (upper bound = `MAX_RELAY_HOPS`).
   Add `test_bench_token_chain_four_relays` to assert HTTP 400 (clamp enforcement).
5. **Low:** Document multi-hop token layout in `relay-bench/README.md` (token slot
   table: index, role, encrypted-with, next_address field).

## Files Changed

| Status | File |
|--------|------|
| M | `relay-xdp-common/src/lib.rs` - added `MAX_RELAY_HOPS = 3` |
| M | `relay-sdk/src/constants.rs` - lowered `MAX_TOKENS` from 7 to 5 |
| M | `relay-backend/src/handlers.rs` - `relay_chain` query param, `build_encrypted_bench_token_chain`, `relay_chain_tokens` in JSON, `MAX_RELAY_HOPS` clamp |
| M | `relay-backend/tests/http_handler_integration.rs` - added `test_bench_token_chain_two_relays` (Test 13) |


| M | `relay-bench/src/bin/bench_client.rs` - `RELAY_CHAIN` env var, `relay_chain_tokens` in response + `RelaySetup`, N+2 token assembly in `setup_relay_route` + refresh task |
| M | `Makefile` - `RELAY_CHAIN ?=` variable, `bench-relay` recipe updated to pass `RELAY_CHAIN` env when set |
| M | `relay-xdp/src/ping_thread.rs` - fix relay_map key construction (port was being placed in wrong u64 byte position, causing 100% RELAY_PING_UNKNOWN_RELAY drops on every peer ping) |

<!-- Remaining planned changes: staging validation run -->
<!-- make bench-relay RELAY_CHAIN=52.201.126.193:40000,52.48.191.174:40000 DURATION_SECS=60 -->

