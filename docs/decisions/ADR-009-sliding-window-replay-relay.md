# ADR-009: Sliding-Window Replay Protection in eBPF Relay (Parity with SDK)

**Date:** 2026-05-18<br>
**Status:** Proposed<br>
**Deciders:** developer<br>
**Related Tasks:** -<br>
**Related ADRs:** -<br>
**Related Sessions:** [Session 2026-05-18](../sessions/2026-05-18-audit-risk-perf.md)<br>

## Context

Every session-bearing packet handler in `relay-xdp-ebpf/src/main.rs` enforces replay protection with a strict single-counter check:

```rust
if packet_sequence <= (*session).payload_client_to_server_sequence {
    return count_drop(...);  // RELAY_COUNTER_*_ALREADY_RECEIVED
}
// ... verify ...
(*session).payload_client_to_server_sequence = packet_sequence;
```

This appears at six call sites: `handle_route_response`, `handle_client_to_server`, `handle_server_to_client`, `handle_continue_response`, `handle_session_ping`, `handle_session_pong` ([relay-xdp-ebpf/src/main.rs:1205,1288,1371,1529,1606,1683](../../relay-xdp-ebpf/src/main.rs)). The relay tracks four sequence counters per `SessionData`:

| Counter | Direction |
|---------|-----------|
| `payload_client_to_server_sequence` | C→S data |
| `payload_server_to_client_sequence` | S→C data |
| `special_client_to_server_sequence` | C→S control (ping) |
| `special_server_to_client_sequence` | S→C control (route response, continue response, pong) |

Each counter is a strict high-water mark. **Any out-of-order packet is dropped as a replay**, even when it is legitimate.

By contrast, `relay-sdk` (game server / game client end of the same wire protocol) implements a 256-slot sliding-window replay buffer ([relay-sdk/src/route/trackers.rs:14-50](../../relay-sdk/src/route/trackers.rs)):

```rust
pub struct ReplayProtection {
    most_recent_sequence: u64,
    received_packet: Box<[u64; REPLAY_PROTECTION_BUFFER_SIZE]>,
}
```

This is a textbook UDP replay window (IPsec / DTLS / WireGuard all use the same pattern). It accepts any packet whose sequence is within `REPLAY_PROTECTION_BUFFER_SIZE` of the high-water mark and not previously seen, and rejects everything older.

**Concrete failure mode under the current eBPF behaviour:** a real-world UDP path that introduces a small amount of network reordering (multi-path routing, ECMP rehash on a TCP flow's neighbour, queue depth jitter) will drop the older-but-legitimate packet. For a 60 Hz game session, even rare reordering produces visible packet-loss telemetry. The session keeps working because the lost packets are below the application's loss tolerance, but the relay's `RELAY_COUNTER_*_ALREADY_RECEIVED` counters incorrectly attribute the loss to "replay" - mis-classifying real loss as attack noise.

**Consequences of inaction:** false-positive replay drops are indistinguishable from real replay attacks in metrics; legitimate out-of-order packets are dropped; the relay's behaviour diverges from the SDK that wraps it. Any DDoS-tuning work that uses `*_ALREADY_RECEIVED` as a signal is poisoned.

## Options Considered

### Option A: Status quo - single high-water-mark counter

- **Description:** Keep `if seq <= last { drop }`.
- **Pros:** No code changes; minimal per-packet work; minimal stack/map footprint.
- **Cons:** False-positive replay drops on any UDP reordering. Diverges from SDK. Mis-classifies real packet loss as replay.
- **Effort:** Impl: 0 / Migration: 0 / Maintenance: low

### Option B: Sliding window in `SessionData` (parity with SDK), 64-bit bitmap

- **Description:** Replace each `*_sequence: u64` counter with a `(high_water: u64, bitmap: u64)` pair. A 64-slot sliding window: the bitmap's bit `i` represents `high_water - i`. On receiving sequence `s`:
  - If `s > high_water`: shift bitmap left by `(s - high_water)` (saturating clamp at 64), set bit 0, update `high_water = s`. Accept.
  - If `s == high_water`: replay, drop.
  - If `s < high_water` and `high_water - s >= 64`: too old, drop.
  - If `s < high_water` and `(high_water - s) < 64`: check bit `(high_water - s)`. If set, replay - drop. Else set it. Accept.

  Each session has four counters → adds 4 × 8 = 32 B per session. Total session size grows from 104 B to 136 B.
- **Pros:** Matches the SDK exactly in spirit (smaller window, but the same property). 64 slots cover any reasonable UDP reordering. All operations fit in 2-3 arithmetic instructions; no extra map lookups. Bounded loops (verifier-friendly).
- **Cons:** Adds 32 B per session × 200K sessions = 6.4 MB to session_map allocation. Wire-compat tests need updating (`SessionData` size changes - this is a verifier-visible change). Need a migration story for in-flight sessions on deploy (existing sessions get re-initialised; safe because they will accept the next high-water-mark packet either way).
- **Effort:** Impl: medium / Migration: medium / Maintenance: low

### Option C: 256-slot bitmap (full parity with SDK)

- **Description:** Same as Option B but with a `[u64; 4]` bitmap per counter → 256-slot window.
- **Pros:** Exact parity with SDK; covers truly pathological reordering.
- **Cons:** Adds 4 × 32 = 128 B per session × 200K = 25.6 MB. The lookup logic needs a bounded loop over 4 u64 slots - still verifier-friendly but more code. Lookup window in real games is overkill at 256 slots (60 Hz game = 4 seconds of reorder tolerance at sequence-per-tick); 64 slots gives a still-generous ~1 second.
- **Effort:** Impl: medium / Migration: medium / Maintenance: low

### Option D: Pluggable replay-policy env var

- **Description:** Read a `RELAY_REPLAY_POLICY=strict|window64|window256` env var at startup, set a `RelayConfig` byte, and switch in eBPF.
- **Pros:** Operator can roll back. Easy A/B testing.
- **Cons:** Doubles the code path in eBPF (verifier complexity). The branch is on a config-map read - small cost - but the verifier-visible diff is large. Pluggability is over-engineering: pick one, ship it.
- **Effort:** Impl: high / Migration: low / Maintenance: high

## Decision

**Chosen: Option B - 64-slot sliding window per direction, parity in spirit with SDK**

## Rationale

Option A (status quo) has a clear correctness gap that conflates network reordering with attack. Option B fixes it at minimal cost (32 B per session, ~6 MB total), aligns the relay's semantics with the SDK's, and uses a well-known UDP replay pattern that every modern UDP-based VPN/transport implements.

Option C buys 4x more reorder tolerance at 4x the per-session memory; the extra tolerance is not justified by any observed game-traffic reorder distribution. We can promote 64→256 later if telemetry shows the 64-slot window is exhausted (i.e. drops with reason "too old, gap > 64" appear in counters).

Option D is over-engineered. Pluggability is justified for performance trade-offs (e.g. ADR-008 fanout is opt-in by env var because the cost/benefit varies by deployment), not for correctness improvements. Replay-protection policy is a correctness decision.

A key deciding factor: the BPF verifier already accepts a bounded loop over 64 bits with constant trip count - we have similar patterns in the DDoS filter. No verifier risk. Stack usage is unchanged (we just add fields to `SessionData`, which lives in a map, not on stack).

## Consequences

- **Positive:** Eliminates false-positive replay drops under normal UDP reordering. Restores `*_ALREADY_RECEIVED` counter as a meaningful attack signal. Brings eBPF relay into semantic parity with relay-sdk. Documents the replay-window-size invariant in `relay-xdp-common`.
- **Negative:** `SessionData` grows 104 → 136 B (~30% wire-struct expansion); `session_map` total memory at 200K capacity grows ~6 MB. Wire-format tests in `relay-xdp/tests/wire_compat.rs` need updating. In-flight sessions on a rolling deploy are reinitialised; clients with packets in flight may see a brief sequence-counter mismatch (but their next-sequence packet succeeds).
- **Neutral:** Per-packet eBPF cost change is negligible (a few arithmetic instructions replacing a single compare).

## Affected Components

| Component | Impact | Description |
|-----------|--------|-------------|
| `relay-xdp-common/src/lib.rs` | Modified | `SessionData` adds four `(u64, u64)` pairs replacing the four single `u64` sequence fields. Update the `const _: () = assert!(size_of::<SessionData>() == 136)` line. |
| `relay-xdp-ebpf/src/main.rs` | Modified | New `#[inline(always)] fn replay_check_and_advance(high_water: *mut u64, bitmap: *mut u64, seq: u64) -> bool`. Six call sites updated to use the helper. |
| `relay-xdp/src/manager.rs` | None | Userspace does not track replay; it only iterates session_map for stats. |
| `relay-xdp/tests/wire_compat.rs` | Modified | Update size assertion. Add a test that exercises the helper directly (no-BPF path). |
| `relay-xdp-common` `wire_compat` | Modified | Update size constant. |
| `relay-backend/*` | None | Backend does not see session replay state. |
| `relay-sdk/*` | None | SDK already has its own (256-slot) implementation. |
| `docs/ARCHITECTURE.md` | Updated | Update `SessionData` field offsets table. Cross-reference the SDK's `ReplayProtection` to make the relationship explicit. |
| `docs/PERFORMANCE_DESIGN.md` | Updated | Note the per-session memory growth in the "BPF Map Access Patterns" section. |

## Revisit When

- Telemetry shows the 64-slot window is exhausted (i.e. legitimate-loss reason "gap > 64" exceeds a small fraction of all drops). Promote to 256 slots (Option C).
- The SDK changes its window size; we should re-evaluate parity.
- A future kernel adds a built-in BPF helper for sliding-window replay - very unlikely, but would let us drop the open-coded helper.

## Migration Plan

1. **Phase 1 (struct change):** Update `relay-xdp-common`. Verify both `cargo test --workspace` and `cargo run -p xtask -- build-ebpf-rust` succeed; the `const _: () = assert!(...)` ensures any forgotten size update fails at compile.
2. **Phase 2 (eBPF helper):** Add `replay_check_and_advance` and replace the six call sites. Build eBPF; verify the verifier accepts the new code via `bpftool prog show`.
3. **Phase 3 (parity test):** New unit test in `relay-xdp/tests/wire_compat.rs` (or a dedicated `replay_window.rs`) exercising:
   - In-order sequences accept.
   - Reordered-by-1 accepts.
   - Reordered-by-63 accepts.
   - Reordered-by-64 rejects (too old).
   - Same sequence twice rejects (replay).
   - Sequence skip forward of 100 advances window, makes window[1..100] available, rejects further reorders.
4. **Phase 4 (parity with SDK):** Reuse the SDK's `ReplayProtection` test vectors where applicable; document any intentional differences (window size).
5. **Phase 5 (staging):** Deploy to staging. Watch `RELAY_COUNTER_*_ALREADY_RECEIVED` for any unexpected drop in counts (which would indicate the change masked a real replay attack). Expected: counter drops to ~0 if our staging traffic has no actual replays.
6. **Phase 6 (production):** Deploy. Watch counters. No rollback flag needed; the change is monotonic (a stricter check would re-introduce the original bug).

