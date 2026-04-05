# Session Summary: Next Actions Plan - Prioritized Roadmap

**Date:** 2026-04-05  
**Duration:** ~1 hour  
**Focus Area:** Project-wide roadmap and prioritization

## Objectives

- [x] Audit remaining work across all components (eBPF, userspace, backend, kernel module)
- [x] Categorize into three tiers: correctness hardening, feature gaps, operational readiness
- [x] Prioritize concrete next actions with file-level detail
- [x] Define first action (session expiry checks in eBPF) with implementation plan

## Work Completed

### Project-Wide Audit

- Identified 3 security-critical eBPF correctness gaps (session expiry, IP fragment drop, missing counters)
- Cataloged 4 feature gaps vs. Go original (internal address tracking, `RELAY_DEDICATED`, hot reload, GCS/HTTP URL)
- Listed 4 operational readiness items (Prometheus metrics, Docker, CI/CD, dead code cleanup)
- Produced 10 prioritized concrete actions with affected files

### eBPF Correctness Analysis (Goal A)

- **A1 - Session expiry checks:** 7 session-based handlers lack `expire_timestamp` vs `current_timestamp` check. Counter constants (indices 43, 55, 64, 74, 84, 93, 103) are defined but never incremented. Expired sessions forward traffic until userspace cleanup at 1 Hz.
- **A2 - IP fragment drop:** `frag_off` is never checked after IPv4 parse. `RELAY_COUNTER_DROP_FRAGMENT` (index 122) exists but is never triggered. Must check `frag_off & 0x3FFF != 0`.
- **A3 - Missing counters:** `SESSION_CREATED` (index 6) and `SESSION_CONTINUED` (index 7) are defined but never incremented in `handle_route_request` / `handle_continue_request`.

### Feature Gap Analysis (Goal B)

- **B1 - Internal address per-relay:** `handlers.rs` has comments "not tracked per-relay yet". Needs `internal_address` in `RelayManager` state and JSON schema.
- **B2 - `RELAY_DEDICATED` env var:** `RelayConfig.dedicated` is always 0. Needs env var support in `config.rs`.
- **B3 - Hot reload:** Currently loads relay data once at startup. Needs `arc-swap` + file watcher. (Phase 2)
- **B4 - GCS/HTTP URL:** Extend `load_json` to fetch from `gs://` or `http(s)://`. (Phase 2)

### Operational Readiness Analysis (Goal C)

- **C1 - Prometheus `/metrics`:** 150 counters reported by relay-xdp need exposure.
- **C2 - Docker packaging:** Dockerfiles for both relay-xdp and relay-backend.
- **C3 - CI/CD:** GitHub Actions for test, build-ebpf, clippy, format.
- **C4 - Dead code cleanup:** Remove `#[allow(dead_code)]` suppressions across relay-xdp/src.

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Session expiry checks first | Highest-impact security fix - expired sessions forward traffic for up to 1s | N/A |
| IP fragment drop second | Security-critical - fragments can bypass stateful checks | N/A |
| Hot reload and GCS/HTTP deferred to Phase 2 | Core correctness and parity more important than convenience features | N/A |

## Tests Added/Modified

No tests added in this planning session. Tests expected for upcoming actions:

| Test Class | Method | Type | Status |
|------------|--------|------|--------|
| `wire_compat` | Session expiry counter verification | Unit | Planned |
| `func_parity` | Session expiry drop behavior | Functional | Planned |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| No issues - planning session only | N/A | No |

## Next Steps

1. ~~**Critical:** Add session expiry checks in all 7 eBPF session-based handlers; file: `relay-xdp-ebpf/src/main.rs`~~ **DONE**
2. ~~**Critical:** Add IP fragment drop check after IPv4 header parse; file: `relay-xdp-ebpf/src/main.rs`~~ **DONE**
3. ~~**High:** Increment `SESSION_CREATED` / `SESSION_CONTINUED` / `SESSION_DESTROYED` counters; files: `relay-xdp-ebpf/src/main.rs`, `relay-xdp/src/main_thread.rs`~~ **DONE**
4. ~~**High:** Add `RELAY_DEDICATED` env var support; files: `relay-xdp/src/config.rs`, `main_thread.rs`~~ **DONE**
5. ~~**Medium:** Add internal address per-relay tracking; files: `relay-backend/src/{database,handlers,relay_manager}.rs`~~ **DONE**
6. ~~**Medium:** Remove `#[allow(dead_code)]` suppressions; multiple `relay-xdp/src` files~~ **DONE**
7. **Medium:** Hot reload for relay data with file watcher; files: `relay-backend/src/{state,main,database}.rs`
8. ~~**Medium:** Add Prometheus `/metrics` endpoint; file: `relay-backend/src/handlers.rs`~~ **DONE**
9. **Low:** GCS/HTTP URL support for `RELAY_DATA_FILE`; files: `relay-backend/src/database.rs`, `Cargo.toml`
10. ~~**Low:** Dockerfiles + CI/CD pipeline; new files at root~~ **DONE**

## Open Questions

| Question | Context |
|----------|---------|
| Is the advanced packet filter needed? | Counter index 5 (`ADVANCED_PACKET_FILTER_DROPPED_PACKET`) exists but nothing triggers it. Go original may have had full chonkle re-computation. |
| Are real route tokens needed? | `test_token` is `[0u8; 111]` in relay update responses. Real tokens need per-relay secret key derivation in the backend. |
| ~~What triggers `RELAY_DEDICATED` behavior?~~ | **RESOLVED:** `config.dedicated != 0` in eBPF changes XDP_PASS to XDP_DROP for non-relay traffic (non-UDP, fragments, wrong port/addr, IPv6). Set via `RELAY_DEDICATED=1` env var. |

## Files Changed

| Status | File |
|--------|------|
| A | `docs/sessions/2026-04-05-next-actions-plan.md` |
| M | `relay-xdp-ebpf/src/main.rs` - session expiry checks (7 handlers) + IP fragment drop + SESSION_CREATED/CONTINUED counters |
| M | `relay-xdp/src/config.rs` - added `dedicated: bool` field + `RELAY_DEDICATED` env var |
| M | `relay-xdp/src/main_thread.rs` - pass `config.dedicated` to BPF config_map + SESSION_DESTROYED counter |
| M | `relay-xdp/tests/backend_response_integration.rs` - added `dedicated` field to test Config |
| M | `relay-backend/src/database.rs` - added `internal_address` to JSON schema + `relay_internal_addresses` to RelayData + 3 unit tests |
| M | `relay-backend/src/handlers.rs` - populate `relay_internal`/`expected_has_internal_address`/`expected_internal_address` from RelayData |
| M | `relay-backend/tests/http_handler_integration.rs` - added `relay_internal_addresses` field to test RelayData |
| M | `relay-backend/tests/e2e_encrypted.rs` - added `relay_internal_addresses` field to test RelayData |
| M | `relay-xdp/src/config.rs` - removed blanket `#[allow(dead_code)]`, added targeted suppression on `relay_name` |
| M | `relay-xdp/src/bpf.rs` - replaced blanket `#[allow(dead_code)]` with per-field suppressions on `interface_index`/`attached_mode` |
| M | `relay-xdp/src/manager.rs` - removed module-level `#![allow(dead_code)]`, deleted unused `RelaySet::clear()` |
| M | `relay-xdp/src/platform.rs` - removed module-level `#![allow(dead_code)]` (all functions actively used) |
| M | `relay-xdp/src/encoding.rs` - removed module-level `#![allow(dead_code)]`, deleted unused `read_address_raw`/`read_bytes`, moved `write_address_ipv4` to `#[cfg(test)]` |
| A | `relay-backend/src/metrics.rs` - Prometheus `/metrics` endpoint, hand-rolled text exposition format, per-relay counters + backend internal metrics |
| M | `relay-backend/src/constants.rs` - added `COUNTER_NAMES` (snake_case) and `COUNTER_DISPLAY_NAMES` (RELAY_COUNTER_* prefix) static arrays |
| M | `relay-backend/src/state.rs` - added `last_optimize_ms: AtomicU64` field |
| M | `relay-backend/src/main.rs` - added `metrics` module, init `last_optimize_ms`, store optimize duration after each cycle |
| M | `relay-backend/src/handlers.rs` - added `/metrics` route + `metrics_handler`, refactored `get_counter_names` to use `COUNTER_DISPLAY_NAMES` |
| M | `relay-backend/src/lib.rs` - added `pub mod metrics` |
| M | `relay-backend/tests/http_handler_integration.rs` - added `last_optimize_ms` to test AppState |
| M | `relay-backend/tests/e2e_encrypted.rs` - added `last_optimize_ms` to test AppState |
| M | `relay-backend/tests/json_loader_integration.rs` - added `last_optimize_ms` to test AppState |
| A | `relay-backend/Dockerfile` - multi-stage Docker build (rust:bookworm -> debian:bookworm-slim) |
| A | `relay-xdp/Dockerfile` - 3-stage Docker build (eBPF nightly -> userspace stable -> runtime) |
| A | `.dockerignore` - exclude target/, .git/, *.ko, docs/, .github/ |
| M | `.github/workflows/rust.yml` - added `docker-backend` and `docker-relay-xdp` CI jobs (ghcr.io push on master/tags) |

