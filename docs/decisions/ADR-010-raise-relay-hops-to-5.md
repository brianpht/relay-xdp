# ADR-010: Raise MAX_RELAY_HOPS from 3 to 5

**Date:** 2026-05-18<br>
**Status:** Accepted<br>
**Deciders:** developer<br>
**Related Tasks:** `relay-xdp-common`, `relay-sdk`, `relay-backend`, `relay-bench`<br>
**Related ADRs:** [ADR-006](ADR-006-route-token-split-client-wire.md)<br>
**Related Sessions:** [Session 2026-05-17](../sessions/2026-05-17-multihop-bench-plan.md)<br>

## Context

`relay-xdp-common::MAX_RELAY_HOPS` is the single source of truth governing how many
relay nodes a route chain may traverse. It propagates to:

- `relay-sdk::MAX_TOKENS = MAX_RELAY_HOPS + 2` - validated at `begin_next_route`; chains
  longer than this are rejected client-side with `FLAGS_BAD_ROUTE_TOKEN`.
- `relay-backend` `/bench_token` `relay_chain` length clamp - returns HTTP 400 if exceeded.
- `relay-bench` `RELAY_CHAIN` env var bound - bench harness documentation and validation.

`relay-backend::optimizer::Optimize2` already explores five route patterns, the longest
being `i -> (x) -> k -> (y) -> j` which stores 5 relay indices in
`route_relays: [i32; MAX_ROUTE_RELAYS=5]`. With `MAX_RELAY_HOPS = 3`, these
4-relay and 5-relay routes were silently un-deployable: server_backend could pick
them from the route matrix, but `relay-sdk` would reject the resulting 6- or 7-token
chain at `begin_next_route`. This was a latent mismatch between the control plane
(optimizer) and the data plane (SDK + eBPF).

Static analysis of `relay-xdp-ebpf::handle_route_request` confirms eBPF is agnostic
to chain length:

- The size check `>= 18 + 2 * 111 = 240 B` is a minimum (1 self token + 1 trailing
  token / pad). No per-packet upper bound is applied.
- Decryption operates on the first token only (`packet_data + 18`).
- The strip is fixed at `bpf_xdp_adjust_head(+RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES)` -
  always exactly one 111 B token per hop.
- No hop counter, no loop over N, no per-N branching. Verifier complexity is constant
  in N.

Physical ceiling = `(RELAY_MTU - 18) / 111 = 10` wire tokens = 9 relays.
`MAX_RELAY_HOPS = 3` was set in session 2026-05-17 as a conservative policy bound
matching the 3-node staging topology, not as an eBPF hard limit.

## Options Considered

### Option A: Lower optimizer to match 3-hop cap

- **Description:** Strip the `i -> (x) -> k -> j`, `i -> k -> (y) -> j`, and
  `i -> (x) -> k -> (y) -> j` patterns from `optimize2`; shrink `MAX_ROUTE_RELAYS` to 3.
- **Pros:** Conservative; no staging re-validation needed.
  | **Cons:** Discards optimizer work already producing useful routes. Long-haul
  cross-region paths that benefit from 4-/5-relay routing become permanently
  unavailable. Shrinking `route_num_relays` bit width in the route matrix wire
  format is a breaking change for `server_backend` consumers of `/route_matrix`.
  | **Effort:** Impl: Medium / Migration: High / Maintenance: Low

### Option B: Keep 3-hop cap, add optimizer post-filter

- **Description:** Leave `MAX_RELAY_HOPS = 3` and silently drop 4-/5-relay entries
  inside `optimize2` or the `route_matrix` write path with a debug-assert guard.
- **Pros:** Bounded blast radius if `server_backend` is sensitive to cap changes.
  | **Cons:** Same loss of routing capability as Option A; permanently maintains
  dead-code paths in the optimizer. The mismatch problem (optimizer produces routes
  the data plane cannot execute) is masked rather than resolved. | **Effort:** Impl:
  Low / Migration: None / Maintenance: Medium

### Option C: Raise cap to 5 to match optimizer

- **Description:** Change `MAX_RELAY_HOPS` from 3 to 5 in `relay-xdp-common`. SDK
  and bench harness auto-align. No change needed in eBPF, userspace relay-xdp, or
  the kernel module.
- **Pros:** Eliminates the control/data-plane mismatch. Optimizer routes 4-/5-relay
  deep become deployable end-to-end. Wire format unchanged (`MAX_ROUTE_RELAYS = 5`
  already). Single constant edit + one test update + docs.
  | **Cons:** Requires staging validation for 4-/5-hop chains (verifier load,
  end-to-end packet forwarding, per-hop latency budget). Current staging has only
  3 relay nodes, so 5-hop cannot be fully exercised there without adding instances.
  | **Effort:** Impl: Low / Migration: Low / Maintenance: Low

> Option A (Do Nothing from the optimizer's perspective) was rejected because
> it discards valuable routing capability and introduces a wire-breaking change.

## Decision

**Chosen: Option C - Raise MAX_RELAY_HOPS to 5**

## Rationale

Options A and B both discard the 4-/5-relay routing breadth that the optimizer
already computes. Shrinking the optimizer (Option A) also requires a wire-format
break. Option B papers over the root cause: the optimizer's cap and the data
plane's cap must agree.

Option C resolves the mismatch at the source. eBPF is proven stateless w.r.t.
chain length. The only remaining risk is staging validation, which is deferred but
tracked. The wire format is unchanged because `route_relays: [i32; MAX_ROUTE_RELAYS=5]`
in the route matrix already has sufficient capacity.

ROUTE_REQUEST at 5-hop = `18 + 6 * 111 = 684 B`, comfortably within
`RELAY_MTU = 1200 B`, leaving 516 B of headroom for payload.

## Consequences

- **Positive:** Single source of truth honored - `MAX_RELAY_HOPS = 5` governs
  eBPF, userspace, relay-sdk, relay-backend, and relay-bench.
- **Positive:** Optimizer routes 4-/5-relay deep are now deployable end-to-end.
  server_backend can safely pick any route from the route matrix.
- **Positive:** No wire format change. `RouteMatrix` already encodes
  `route_num_relays` in `[0..=MAX_ROUTE_RELAYS=5]`; `server_backend` deserializers
  are unaffected.
- **Positive:** No eBPF rebuild required; eBPF logic is unchanged.
- **Positive:** `relay-sdk::MAX_TOKENS` const-assert (`== MAX_RELAY_HOPS + 2`)
  ensures compile-time drift detection if either constant changes independently.
- **Negative:** 4-/5-hop staging validation requires either adding 2 extra relay
  instances or running the `RELAY_NO_BPF=1` userspace parity path. Not yet done.
- **Negative:** Per-hop latency scales linearly. Operators must evaluate whether
  5-hop routes are acceptable for their latency budget vs. 1-/2-hop alternatives.
- **Neutral:** `MAX_PACKET_BYTES = 1384`, `RELAY_MTU = 1200`, `RELAY_ROUTE_TOKEN_BYTES = 71`,
  `RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES = 111` all unchanged.

## Affected Components

| Component | Impact | Description |
|-----------|--------|-------------|
| `relay-xdp-common/src/lib.rs` | Low | `MAX_RELAY_HOPS` 3 -> 5; doc comment updated with MTU budget for N=5 and reference to this ADR. |
| `relay-sdk/src/constants.rs` | Low | `MAX_TOKENS` 5 -> 7; hardcoded literal (not expression) so cbindgen exports `relay_MAX_TOKENS = 7` to C/C++ FFI consumers. Const-assert `MAX_TOKENS == MAX_RELAY_HOPS + 2` added as compile-time drift guard. |
| `relay-sdk/include/relay_generated.h` | Low | Regenerated by cbindgen; `relay_MAX_TOKENS` updated to 7. |
| `relay-backend/tests/http_handler_integration.rs` | Low | Test 15 (`test_bench_token_chain_four_relays_rejected`) renamed to `test_bench_token_chain_exceeds_max_relays_rejected`; rejection chain now 6 relays (> new cap of 5). Tests 13 and 14 (2- and 3-relay chains) unmodified - both still inside the new cap. |
| `relay-bench/README.md` | Low | `RELAY_CHAIN` cap updated to "currently 5". Design constraint table extended with 4-hop and 5-hop rows. Clarification that eBPF is stateless and the cap is a policy bound. |
| `relay-xdp-ebpf/src/main.rs` | None | No changes required; `handle_route_request` is already N-agnostic. |
| `relay-backend/src/optimizer.rs` | None | No changes required; already produces routes up to 5 relays. |
| `relay-backend/src/constants.rs` | None | `MAX_ROUTE_RELAYS = 5` unchanged; wire layout already matches the new cap. |

## Revisit When

- Staging topology is expanded to 5+ relay nodes: run `make bench-relay
  RELAY_CHAIN=r1:40000,r2:40000,r3:40000,r4:40000,r5:40000` to close the
  end-to-end validation gap noted in the Negative consequence above.
- A latency analysis shows 5-hop p99 RTT exceeds acceptable thresholds for
  interactive game traffic: consider lowering the cap or making it configurable
  per route matrix entry.
- The physical ceiling (9 relays) needs to be approached: update the MTU budget
  table and re-run eBPF verifier load checks at the new limit.
- `server_backend` adds its own cap enforcement: ensure it aligns with
  `MAX_RELAY_HOPS` from `relay-xdp-common` rather than a hardcoded constant.

## Migration Plan

1. `relay-xdp-common::MAX_RELAY_HOPS` changed from 3 to 5 - zero migration required
   for relay-xdp or eBPF (no struct or wire format change).
2. `relay-sdk::MAX_TOKENS` bumped from 5 to 7 - existing clients calling
   `begin_next_route` with `num_tokens <= 5` are unaffected (valid range stays
   `2..=MAX_TOKENS`, only upper bound widens).
3. `relay-backend` `/bench_token` clamp auto-adjusts via `relay_xdp_common::MAX_RELAY_HOPS` -
   no migration needed; previously rejected 4- and 5-relay chains now return HTTP 200.
4. `server_backend` consumers of `/route_matrix`: no action needed; route entries with
   `route_num_relays = 4` or `5` were always present in the wire format
   (`MAX_ROUTE_RELAYS = 5` unchanged). If `server_backend` was silently discarding
   these entries due to its own internal cap, it should now be updated to use them.
5. Run CI gate: `cargo fmt --all`, `cargo clippy --workspace --lib --bins -- -D warnings`,
   `cargo test --workspace`. All pass at commit `0b7c0eb`.
