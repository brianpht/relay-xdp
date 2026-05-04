# ADR-004: Replay-Protection Window for `/relay_update`

**Date:** 2026-05-04<br>
**Status:** Proposed<br>
**Deciders:** developer<br>
**Related Tasks:** Phase 1 action P1-01 (audit v2)<br>
**Related ADRs:** N/A<br>
**Related Sessions:** [Session 2026-05-04 v2](../sessions/2026-05-04-project-audit-plan-v2.md)<br>

## Context

`relay-backend` ingests encrypted relay state via HTTP `POST /relay_update`. Decryption today (`relay-backend/src/handlers.rs:146 decrypt_relay_request`) is:

```
[header 8B plaintext] + [MAC 16B] + [ciphertext] + [nonce 24B]
```

`crypto_box::SalsaBox::decrypt_in_place_detached` provides AEAD integrity and confidentiality. It does **not** provide freshness. An attacker who captures one valid request from any relay can replay the bytes indefinitely against the backend; every replay decrypts successfully and is processed as if fresh.

Two independent freshness signals are available:

1. **The 24-byte nonce** that ships in the wire format. AEAD nonces are typically random per-message, so seeing the same `(relay, nonce)` pair twice is by itself a strong replay signal.
2. **`current_time` inside the decrypted `RelayUpdateRequest`** (see `relay-backend/src/relay_update.rs`). This is the relay-side clock at the moment the request was built. It is not currently validated against the backend's wall clock.

Consequences of inaction:

- An attacker on-path can capture a single legitimate `/relay_update` and replay it to keep the backend's view of relay state frozen at the captured moment - effectively a stale-data injection attack.
- A misconfigured cache or proxy in front of `/relay_update` (today: none, but could happen) can produce the same effect accidentally.
- The cost of detection is asymmetric: zero for legitimate clients (they never replay) and high for attackers (every replay is rejected on the second attempt within a window).

## Options Considered

### Option A: Per-relay nonce LRU + payload-timestamp freshness check

- **Description:** Keep a `parking_lot::Mutex<HashMap<RelayIndex, lru::LruCache<[u8; 24], ()>>>` in `AppState`. Before decrypting, look up `(relay_index, nonce_bytes)`; if hit, reject. After successful decrypt, insert. Independently, after parsing the decrypted `RelayUpdateRequest`, reject when `|req.current_time - state.now| > 30s`. Capacity per relay: 1024 nonces (covers `~17 minutes` of traffic at the 1 Hz `RELAY_UPDATE_PERIOD_SEC`). Two new counters: `relay_update_replay_rejected`, `relay_update_clock_skew_rejected`.
- **Pros:** Minimal change surface (single struct + two checks). No protocol change - existing relays interoperate unchanged. The LRU cap is bounded; with `2048 relays * 1024 nonces * (24 + overhead)B ~= 60-80 MB` worst case, well within budget.
- **Cons:** Two state stores to keep in sync (nonce LRU + clock-skew check). The 30s window must accommodate clock drift between relay and backend; that bound has to be documented and enforced operationally (NTP).
- **Effort:** Impl: low / Migration: none / Maintenance: low

### Option B: Server-issued nonce challenge (challenge-response)

- **Description:** Backend issues a fresh server-side nonce on each `GET /relay_challenge`; relay must echo it inside the next encrypted `/relay_update`. Backend verifies the echoed nonce belongs to a recent challenge.
- **Pros:** Strong freshness without timestamp comparison; immune to clock drift.
- **Cons:** Doubles the round-trip count for every relay update (1 Hz becomes 2 round trips per second per relay). Requires a wire-format change to carry the echoed challenge - breaks the existing `RelayUpdateRequest` layout and forces a coordinated relay/backend rollout. Adds a new endpoint and state store.
- **Effort:** Impl: medium / Migration: high (wire-format break) / Maintenance: medium

### Option C: Do nothing

- **Description:** Continue accepting any AEAD-valid ciphertext.
- **Pros:** Zero work.
- **Cons:** Replay attack is open. Documented in audit v2 as a Critical finding.
- **Effort:** none

## Decision

**Chosen: Option A - Per-relay nonce LRU + payload-timestamp freshness check**

## Rationale

Option B is correctness-strong but pays a permanent latency tax (2x round trips at 1 Hz, every relay, forever) and forces a coordinated wire-format break. The replay risk does not warrant that cost.

Option C is non-viable - the audit explicitly classifies missing replay protection as Critical.

Option A defends both axes (already-seen nonce + stale clock) with implementation cost that fits in a single Phase 1 PR and zero protocol change. The 30s clock-skew window is generous enough for a relay/backend NTP-synchronized to within a few hundred milliseconds in practice; operations already runs `chrony`/`systemd-timesyncd` on production hosts.

The deciding factor: AEAD integrity already binds the nonce to the ciphertext. The nonce is therefore a free and unforgeable replay tag. Caching it costs `O(relays * 1024)` memory and `O(1)` lookup per request - effectively free at our request rate.

## Consequences

- **Positive:** Replay attack window collapses from "infinite" to "<= 30s + LRU eviction window". Both the rejection counters surface in `/metrics` so operations can see attacks and clock-skew issues distinctly. No protocol change - existing relays unaffected.
- **Negative:** Backend state grows linearly with relay count. NTP misconfiguration on a relay now causes silent drop instead of silent processing - operations playbook must mention the new `relay_update_clock_skew_rejected` counter. Relays whose clock drifts past 30s during a network partition will have their first-after-recovery update rejected; the next one (with refreshed `current_time`) succeeds.
- **Neutral:** The 30s window is a tunable. If real-world clock drift turns out to demand more, the constant moves; the algorithm does not change.

## Affected Components

| Component | Impact | Description |
|-----------|--------|-------------|
| `relay-backend/src/handlers.rs` | Modified | `decrypt_relay_request` checks nonce LRU before decrypt; inserts after |
| `relay-backend/src/state.rs` | Modified | `AppState` gains `nonce_cache: Arc<Mutex<HashMap<u64, LruCache<[u8; 24], ()>>>>` |
| `relay-backend/src/relay_update.rs` | Modified | After-parse clock-skew check against `state.now` |
| `relay-backend/src/metrics.rs` | Modified | Two new counters exported |
| `relay-backend/Cargo.toml` | Modified | Add `lru` crate (or use existing dep if present) |
| `relay-backend/tests/e2e_encrypted.rs` | New / extended | Replay rejected; stale `current_time` rejected; post-eviction replay accepted |
| `relay-xdp` | None | No client-side change required |
| `docs/ARCHITECTURE.md` | Updated | Note replay-protection window in `/relay_update` description |

## Revisit When

- Clock-skew rejection rate in production exceeds a low threshold (suggests NTP fleet issue or window too tight).
- Per-relay nonce cache memory becomes a constraint (e.g., relay count grows past `2048`).
- A future protocol change adds a server-issued challenge for unrelated reasons - at that point Option B becomes nearly free and may supersede this ADR.
- A formal security review demands stronger freshness guarantees than `30s + LRU`.

## Migration Plan

1. Implement `AppState.nonce_cache` and the LRU helper.
2. Wire the pre-decrypt lookup and post-decrypt insert in `decrypt_relay_request`.
3. Wire the post-parse clock-skew check; export two counters.
4. Add `tests/e2e_encrypted.rs` cases (replay rejected, stale rejected, post-eviction replay accepted).
5. Run the full CI suite (`cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`, `cargo xtask func-test`, docker-compose suite).
6. Land as a single commit; no staged rollout needed (server-side only, backwards compatible).