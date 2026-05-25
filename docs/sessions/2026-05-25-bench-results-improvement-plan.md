# Session Summary: Benchmark Results Analysis and Improvement Plan

**Date:** 2026-05-25<br>
**Duration:** ~1 session (~8 interactions)<br>
**Focus Area:** Benchmark evaluation (docs/BENCH_RESULTS.md) - gap analysis and next-step planning for P1-P6 improvement areas<br>

## Objectives

- [x] Analyse `docs/BENCH_RESULTS.md` (staging run 2026-05-24) - understand all results and findings
- [x] Assess current codebase state for each improvement area P1-P6
- [x] Identify root cause of server-backend refresh spike (P1)
- [x] Verify profiling counter pipeline end-to-end (P6)
- [x] Determine which items need code changes vs can be run immediately
- [x] Produce phased implementation plan for P1-P6

## Work Completed

### Benchmark Results Summary (2026-05-24 staging run)

All three bench targets passed. Key numbers:

| Benchmark | PPS | RTT p50 | RTT p99 | Loss (steady) | Result |
|-----------|-----|---------|---------|--------------|--------|
| bench-local (loopback) | 1000 | 1.2 ms | 3.0 ms | 0.0% | PASS |
| bench-relay (single-hop) | 500 | 255 ms | 285 ms | < 0.6% | PASS |
| bench-server-backend (matchmaking) | 500 | 280 ms | 291 ms | < 0.8% | PASS |

Notable: 255 ms p50 (bench-relay) is entirely cross-region wire latency (laptop -> us-east-1).
eBPF per-packet processing overhead is sub-microsecond and unmeasurable from laptop.

### Gap Analysis - P1 through P6

Codebase inspection of all 6 improvement areas:

| Item | Code state | What exists | What is missing |
|------|-----------|-------------|----------------|
| P1 (refresh spike) | Needs change | `server-backend/src/handlers.rs refresh_session` | `notify_game_server` is sequential `await` - blocks client response |
| P2 (co-located bench) | Needs Makefile | `BENCH_HOST` resolved from Pulumi outputs | No `bench-relay-colocated` target; `bench_client` never deployed to bench node |
| P3 (multi-hop bench) | Ready - no code needed | `RELAY_CHAIN` env var, multi-hop token layout, Makefile bench-relay target | Staging run not yet executed |
| P4 (high PPS stress) | Depends on P2 | `TARGET_PPS` env var exists | Co-located client needed for meaningful results |
| P5 (near-MTU payload) | Ready - no code needed | `PAYLOAD_BYTES` env var exists | Staging run not yet executed |
| P6 (profiling counters) | Needs xtask change | eBPF `profile_now()`/`profile_record()` gated by `#[cfg(feature = "profiling")]`, counters 133-139 defined, relay-backend `/metrics` exposes them | `xtask/src/main.rs build_ebpf_rust()` does not pass `--features profiling` |

### P1 Root Cause (Confirmed)

`refresh_session` in `server-backend/src/handlers.rs` is fully sequential:

```
bench_client POST /sessions/{id}/refresh
  -> server-backend: mint_tokens (relay-backend /bench_token, same host, ~5 ms)
  -> server-backend: notify_game_server (webhook to bench_server, await, timeout 3000 ms)
  -> server-backend: return SessionResponse
bench_client: route_update -> ROUTE_REQUEST -> ROUTE_RESPONSE
```

With a cold webhook TCP connection, the `notify_game_server` await can take up to 3 s.
Total chain: ~127 ms (cross-region to SB) + ~5 ms (mint) + ~3000 ms (cold webhook) + ~127 ms (return) + ~510 ms (ROUTE_REQUEST/RESPONSE round trip) = ~3.8 s.
This matches the observed 4 s spike at t = 39 s in the bench-server-backend run.

Fix: fire `notify_game_server` with `tokio::spawn` (background), return `SessionResponse` to bench_client immediately after `mint_tokens`. Reduces client-perceived latency to ~260 ms (2x cross-region RTT + mint only). Risk is low because bench_server and server-backend are co-located in us-east-1 (near-zero webhook failure rate).

### P6 Profiling Pipeline (Confirmed End-to-End)

Full pipeline is wired; only the build flag is missing:

```
relay-xdp-ebpf (--features profiling)
  -> profile_now() / profile_record() write counters[133..139] in stats_map (PerCpuArray)
  -> relay-xdp main_thread.rs reads all 150 counters, serializes in update payload (Writer)
  -> POST /relay_update to relay-backend (1 Hz)
  -> relay-backend /metrics exposes relay_counter_RELAY_COUNTER_PROFILE_* as Prometheus gauges
```

Post-processing: `avg_ns = PROFILE_STAGE_NS / PROFILE_SAMPLES` per stage (parse, filter, map_lookup, crypto, rewrite, total).

`xtask/src/main.rs build_ebpf_rust()` passes hardcoded cargo args with no `--features` forwarding.
Fix: add `build-ebpf-rust-profiling` command outputting `relay_xdp_rust_profiling.o`.

### P3 Multi-Hop - Code Confirmed Ready

`RELAY_CHAIN` env var is parsed in `relay-bench/src/bin/bench_client.rs` (comma-separated IP:PORT).
Makefile `bench-relay` target already handles `RELAY_CHAIN` override path.
Multi-hop token layout (N relay tokens + trailing zeros) is fully implemented.
No code change needed - staging run only.

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| P1 fix: fire-and-forget webhook (tokio::spawn) instead of parallel join | bench_server and server-backend are co-located (us-east-1), failure rate near-zero; blocking the client for webhook latency is the dominant cause of the 4 s spike | N/A |
| P6: add separate `build-ebpf-rust-profiling` xtask command rather than modifying default | Profiling build changes eBPF behavior (extra ktime calls); default build must stay unmodified for production | N/A |
| P4 requires P2 (co-located client) | 500 PPS from laptop produces <500 ns eBPF processing share; stress testing session_map LRU (200K) needs co-located 10K+ PPS to generate meaningful load | N/A |

## Tests Added/Modified

None - this session was analysis and planning only. No code was changed.

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| xtask does not forward `--features` to eBPF build | Planned fix: add `build-ebpf-rust-profiling` command in Phase 2b | No (P6 blocked but not production-critical) |
| bench_client binary is never deployed to bench node | Planned fix: add `bench-relay-colocated` Makefile target with scp + ssh remote run | No (P4 blocked until P2 done) |

## Next Steps

1. ~~**High - P5:** Run `make bench-relay STACK=staging PAYLOAD_BYTES=1200 DURATION_SECS=60` - validate near-MTU (1200 B) payload traverses eBPF correctly, no change needed.~~
   **DONE 2026-05-25** - PASS. RTT p50=248 ms, p99=270 ms, loss <0.6% steady-state. Identical profile to 128B baseline. No fragmentation or drops. Infra re-provisioned; new relay IPs recorded in BENCH_RESULTS.md.
2. ~~**High - P3 2-hop:** Run `make bench-relay RELAY_CHAIN=34.198.54.153:40000,52.215.28.227:40000 STACK=staging DURATION_SECS=60` - expected p50 ~340 ms. *(IPs updated from infra re-provision; old: 44.194.204.240, 54.229.160.49)*~~
   **DONE 2026-05-25** - PASS. RTT p50=381 ms, p99=466 ms, loss <1.0% steady-state. Inter-relay delta: +132 ms (us-east-1 <-> eu-west-1 transatlantic round-trip, 66 ms each way). Plan estimate was +85 ms; actual +132 ms because the bench_server is co-located in us-east-1, so the eu-west-1 leg is traversed twice (r1 -> r2 -> bench_server). Route active 100% of 60s run.
3. ~~**High - P3 3-hop:** Run with chain `34.198.54.153:40000,52.215.28.227:40000,13.250.83.214:40000` - expected p50 ~470 ms.~~
   **DONE 2026-05-25** - PASS. RTT p50=720 ms, p99=796 ms, loss <1.4% (window artifact only). Actual delta vs 2-hop: +339 ms (eu-west-1->ap-southeast-1 ~160 ms one-way + ap-southeast-1->us-east-1 ~179 ms one-way). Plan estimate of ~470 ms was wrong - both new legs are long-haul, not regional. Route active 100% of 60s run. P3 fully resolved.
4. ~~**High - P1:** Change `notify_game_server(...).await` to `tokio::spawn(...)` in `server-backend/src/handlers.rs refresh_session`. Update integration tests. CI: fmt + clippy + test.~~
   **DONE 2026-05-25** - `notify_game_server` signature changed to take `Arc<AppState>`. In `refresh_session`: blocking `.await` replaced with `tokio::spawn` fire-and-forget. `create_session` webhook remains synchronous (game server must register before client connects). Integration test sleep bumped 50ms -> 200ms. All 3 CI checks pass (fmt + clippy zero warnings + all tests green). Re-ran `bench-server-backend` after deploy: **4s spike gone**. p50 256 ms, p99 max 322 ms (1s at t=10s only). Steady-state 264-273 ms p99. See BENCH_RESULTS.md Step 9.
5. **Medium - P6:** Add `build-ebpf-rust-profiling` command in `xtask/src/main.rs`. Deploy profiling build to staging relay, read `/metrics` counters, compute avg ns per stage vs targets in `docs/PERFORMANCE_DESIGN.md`.
6. **Medium - P2:** Add `bench-relay-colocated` Makefile target: build + scp bench_client + ssh remote run against relay-staging-1 from bench-staging-1 (same AZ). Expected p50 < 1 ms.
7. **Low - P4:** After P2 is complete, run `make bench-relay-colocated STACK=staging TARGET_PPS=10000 DURATION_SECS=300`. Watch `relay_counter_session_evict` in relay-backend `/metrics`.

## Files Changed

| Status | File |
|--------|------|
| Modified | `docs/BENCH_RESULTS.md` - added Steps 6-8 (P5, P3 2-hop, P3 3-hop results), updated infra IPs, summary table, improvement areas |
| Modified | `ansible/ansible.cfg` - replaced removed `community.general.yaml` callback with `ansible.builtin.default` + `result_format=yaml` |
| Modified | `server-backend/src/handlers.rs` - P1 fix: `notify_game_server` takes `Arc<AppState>`; `refresh_session` webhook fired via `tokio::spawn` (fire-and-forget) |
| Modified | `server-backend/tests/integration.rs` - bump post-refresh sleep 50ms -> 200ms for async webhook delivery |
