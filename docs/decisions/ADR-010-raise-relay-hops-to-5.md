# ADR-010: Raise MAX_RELAY_HOPS from 3 to 5

**Status:** Accepted
**Date:** 2026-05-18
**Deciders:** relay-xdp maintainers

## Context

`relay-xdp-common::MAX_RELAY_HOPS` is the single source of truth for the maximum
number of relay nodes a single route chain can traverse. It feeds:

- `relay-sdk::MAX_TOKENS = MAX_RELAY_HOPS + 2` (`route_update` validation)
- `relay-backend` `/bench_token` `relay_chain` clamp (HTTP 400 above the cap)
- documentation + bench harness `RELAY_CHAIN` env var bound

`relay-backend::optimizer::Optimize2` already explores route patterns up to
5 relays (`[i, x, k, y, j]`, written into `route_relays: [i32; MAX_ROUTE_RELAYS=5]`).
With `MAX_RELAY_HOPS = 3`, the optimizer's 4-relay and 5-relay routes were
silently un-deployable: server_backend could pick them, but `relay-sdk` would
reject the resulting 6- or 7-token chain at `begin_next_route` with
`FLAGS_BAD_ROUTE_TOKEN`. This was a latent mismatch between control plane
(optimizer) and data plane (SDK + eBPF) capabilities.

Static analysis of `relay-xdp-ebpf::handle_route_request` confirms eBPF is
fully agnostic to chain length:

- Size check `>= 18 + 2 * 111 = 240 B` is a *minimum* (1 self token + 1 trailing
  token / pad). No upper bound enforced.
- Decryption operates on the first token only (`packet_data + 18`).
- Strip is fixed at `bpf_xdp_adjust_head(+RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES)` -
  always exactly one 111 B token.
- No hop counter, no loop over N, no per-N branching. Verifier complexity is
  constant in N.

Physical ceiling = `(RELAY_MTU - 18) / 111 = 10` wire tokens = 9 relays.
`MAX_RELAY_HOPS = 5` sits comfortably below this hard limit.

## Decision

Raise `relay_xdp_common::MAX_RELAY_HOPS` from 3 to 5.

`relay-sdk::MAX_TOKENS` is derived as `MAX_RELAY_HOPS + 2` (= 7 after this
change), so SDK + backend + bench harness auto-align without further edits to
their cap constants.

Optimizer (`MAX_ROUTE_RELAYS = 5` in `relay-backend::constants`) needs no
change: it already produced these routes; raising the cap simply lets them flow
through to clients.

## Considered Alternatives

### A. Lower optimizer to match 3-hop cap (rejected)

Strip the `i -> (x) -> k -> j`, `i -> k -> (y) -> j`, and
`i -> (x) -> k -> (y) -> j` patterns from `optimize2` and shrink
`MAX_ROUTE_RELAYS` to 3.

- Pros: conservative, no staging re-validation.
- Cons: discards optimizer work already producing useful routes; long-haul
  cross-region paths that benefit from 4-5 relay routing become unavailable;
  shrinks wire layout (`route_num_relays` bit width changes) - a breaking
  change for `server_backend` consumers of `/route_matrix`.

### B. Keep 3-hop cap and add an optimizer post-filter (rejected)

Leave `MAX_RELAY_HOPS = 3` and drop 4-/5-relay entries inside `optimize2` /
`route_matrix` write path with a debug-assert.

- Pros: bounded blast radius if `server_backend` is sensitive.
- Cons: same loss of routing capability as Alternative A, with the additional
  cost of permanently maintained dead-code paths in the optimizer.

### C. (chosen) Raise cap to 5

- Pros: aligns control and data planes; unlocks the routing breadth the
  optimizer was already computing; zero code change in eBPF / userspace
  relay-xdp / kernel module; only constant + one test + docs touched.
- Cons: requires staging validation that real 4-/5-hop chains forward
  end-to-end (verifier load, MTU headroom, per-hop latency budget).

## Consequences

### Positive

- Single source of truth honored: `MAX_RELAY_HOPS = 5` everywhere.
- Optimizer routes 4-5 relay deep are now deployable end-to-end.
- `relay-sdk::MAX_TOKENS` derived (not hardcoded) - future bumps need one edit.
- No wire format change. `RouteMatrix` already encodes `route_num_relays` in
  `[0..=MAX_ROUTE_RELAYS=5]`. `server_backend` deserializers continue to read
  the same byte stream.
- No eBPF rebuild required (logic unchanged).

### Negative / Risk

- Staging topology has 3 relay nodes (production same). 5-hop chains cannot be
  exercised in staging without adding 2 more relay instances. Functional
  parity tests at 4-/5-hop must run in `RELAY_NO_BPF=1` mode or via
  `tests/compose-test.sh` with extra relay containers.
- ROUTE_REQUEST size at 5-hop = 684 B (still well under MTU 1200), so MTU is
  not a concern. Per-hop latency budget scales linearly - operators must
  decide whether 5-hop routes are worth the added latency vs. direct.

### Neutral

- `MAX_PACKET_BYTES = 1384` and `RELAY_MTU = 1200` unchanged.
- `RELAY_ROUTE_TOKEN_BYTES = 71` / `RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES = 111`
  unchanged.

## Validation Plan

1. CI: `cargo fmt --all`, `cargo clippy --workspace --lib --bins -- -D warnings`,
   `cargo test --workspace` all pass with the new constant.
2. Updated unit + integration tests:
   - `relay-backend::test_bench_token_chain_exceeds_max_relays_rejected` now
     uses 6-relay chain (formerly 4) to assert HTTP 400.
   - Existing `test_bench_token_chain_two_relays` and
     `test_bench_token_chain_three_relays` remain valid (both inside the new
     cap).
3. Staging (follow-up session): add 2 stub relay instances or run
   `RELAY_NO_BPF=1` userspace parity test for a synthetic 5-hop chain.
4. eBPF verifier check: load the eBPF object on kernel 6.5+ and confirm
   acceptance; no change in `bpftool prog show` complexity since N is not in
   any loop.

## Files Touched

| Status | File | Change |
|--------|------|--------|
| M | `relay-xdp-common/src/lib.rs` | `MAX_RELAY_HOPS: 3 -> 5`; expanded doc comment |
| M | `relay-sdk/src/constants.rs` | `MAX_TOKENS` now derived from `relay_xdp_common::MAX_RELAY_HOPS` |
| M | `relay-backend/tests/http_handler_integration.rs` | Test 15 renamed + uses 6-relay chain to exceed new cap |
| M | `relay-bench/README.md` | RELAY_CHAIN cap doc + design constraint table extended to 5-hop |
| A | `docs/decisions/ADR-010-raise-relay-hops-to-5.md` | This ADR |

## References

- ADR-006-route-token-split-client-wire.md - token layout (client_view + wire + zeros_pad)
- `relay-xdp-ebpf/src/main.rs::handle_route_request` - per-hop processing logic
- `relay-backend/src/optimizer.rs::optimize2` - route enumeration patterns
- `docs/sessions/2026-05-17-multihop-bench-plan.md` - origin of `MAX_RELAY_HOPS = 3`

