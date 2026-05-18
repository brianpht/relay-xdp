# Session Summary: Full-Workspace Audit, Risk Analysis, Performance Review

**Date:** 2026-05-18<br>
**Duration:** ~1 session (~20 interactions)<br>
**Focus Area:** Cross-cutting - relay-xdp (userspace), relay-xdp-ebpf, relay-xdp-common, module/, relay-backend, relay-sdk, relay-bench, xtask, ansible, infra<br>

## Objectives

- [x] Static audit of every workspace crate + module + ansible + infra
- [x] Baseline test pass (`cargo test --workspace`) + functional parity (`xtask func-test`)
- [x] Collect criterion micro-benchmark numbers for relay-sdk hot paths
- [x] Catalogue correctness, security, and performance findings with file:line refs
- [x] Draft three ADRs for the highest-impact performance/correctness changes
- [ ] Apply any code changes (out of scope for this audit; covered by follow-up tasks)

## Work Completed

### Baseline verification

| Command | Result |
|---------|--------|
| `cargo test --workspace` | 416 passed, 16 ignored, 0 failed |
| `cargo run -p xtask -- func-test` | 15 passed, 0 failed (RELAY_NO_BPF=1 parity) |
| `cargo clippy --workspace --lib --bins` | 0 warnings (rust 1.87.0) |
| `cargo bench -p relay-sdk --bench relay_sdk -- --quick` | See bench numbers below |

### Bench baseline (relay-sdk, `--quick`, x86_64 dev laptop)

| Bench | Time | Note |
|-------|------|------|
| `packet_codec/route_response_encode` | 1.67 ns | trivial codec |
| `packet_codec/route_response_decode` | 1.15 ns | |
| `packet_codec/session_ping_encode` | 2.20 ns | |
| `packet_codec/relay_ping_encode` | 2.75 ns | |
| `header_hmac/write_header` | 81 ns | SHA-256 userspace (sha2 crate) |
| `header_hmac/read_header_valid` | 87 ns | SHA-256 verify |
| `header_hmac/read_header_invalid_key` | 113 ns | mismatch branch slower |
| `filter/generate_pittle` | 6.9 ns | DDoS filter component 1 |
| `filter/generate_chonkle` | 16.9 ns | FNV-1a 8 bytes |

> `token_crypto/*` and `route_manager/*` rows reported nonsensical seconds-scale
> times under `--quick`; ignored - re-run with full sample size before relying
> on those numbers.

### Audit findings

Findings are grouped by impact (P0 high impact / clear win, P1 medium, P2 low /
nice-to-have) and category. Severity reflects production risk, not effort to fix.

#### eBPF data plane (relay-xdp-ebpf)

| ID | Sev | Category | Finding |
|----|-----|----------|---------|
| E-01 | P0 | Correctness | Single-counter replay check (`if seq <= last { drop }`) in every session handler ([main.rs:1205,1288,1371,1529,1606,1683](../../relay-xdp-ebpf/src/main.rs)) drops legitimately out-of-order packets. relay-sdk already implements a 64-slot sliding window ([relay-sdk/src/route/trackers.rs:14-50](../../relay-sdk/src/route/trackers.rs)). Parity gap with the SDK. See ADR-009. |
| E-02 | P0 | Performance | No XDP_REDIRECT / cpumap. All forwarded traffic uses XDP_TX, which is constrained to the RX queue's TX peer on most NICs. Multi-core scaling depends entirely on NIC RSS hashing of saddr - a single hot client/server flow pin-pins a single core. See ADR-008. |
| E-03 | P0 | Performance / Security | ROUTE_REQUEST decrypts a full XChaCha20-Poly1305 token (~1 μs) before any per-source rate limiting. A spoofed-source flood that satisfies the pittle/chonkle byte ranges (~10⁻⁹ probability for blind random, but a knowledgeable attacker can replay valid magics) can burn CPU. Add a per-saddr token bucket map ahead of `decrypt_route_token` ([main.rs:1082](../../relay-xdp-ebpf/src/main.rs)). |
| E-04 | P1 | Correctness | `BPF_NOEXIST` insert in `handle_route_request` ([main.rs:1127](../../relay-xdp-ebpf/src/main.rs)) silently drops the new SessionData when a session with the same `(session_id, session_version)` already exists. Legitimate session re-creation after a brief LRU eviction will keep stale `next_*`, `prev_*` until the next CONTINUE_REQUEST. Consider `BPF_ANY` plus an explicit `session_version > existing` guard. |
| E-05 | P1 | Correctness | NAT port refresh only happens on first-hop session creation (`session.prev_port = (*udp).source` at [main.rs:1120](../../relay-xdp-ebpf/src/main.rs)). If the client's NAT mapping rotates mid-session, all server→client traffic continues going to the stale port until the session expires. SDK side has no signalling for this. |
| E-06 | P1 | Performance | The 26-branch DDoS filter ([main.rs:1837-1858](../../relay-xdp-ebpf/src/main.rs)) is the second-largest fixed cost after the SHA-256. Replace with 4 × 256-byte lookup tables in `.rodata`; the verifier handles `.rodata` reads with no extra cost. Userspace bench shows pittle 7ns + chonkle 17ns, so the filter check itself should target ≤10ns. |
| E-07 | P1 | Performance | `verify_ping_token` and `verify_session_header` are `#[inline(never)]` to work around an LLVM eBPF register-materialisation bug ([main.rs:704,741](../../relay-xdp-ebpf/src/main.rs)). With Rust 1.87 + the inline-asm kfunc wrappers, the original bug may be moot - inlining could save the BPF call frame setup (~20-40 ns per packet × every session packet). Worth re-testing the assumption on a current toolchain. |
| E-08 | P1 | Correctness | Hard-coded `if packet_bytes > 1400` at [main.rs:1826](../../relay-xdp-ebpf/src/main.rs) does not use `RELAY_MAX_PACKET_BYTES` (1384) or `RELAY_MTU` (1200). The constant 1400 should reference a named constant in `relay-xdp-common`. |
| E-09 | P1 | Observability | `RELAY_COUNTER_PACKETS_RECEIVED` is incremented at [main.rs:1774](../../relay-xdp-ebpf/src/main.rs) before the `packet_bytes > 1400` and IHL/fragment drops; this overcounts "received" packets relative to "drops + forwarded". Move the counter increment after the parse-time drops. |
| E-10 | P2 | Performance | `relay_reflect_packet` allocates a 12-byte stack buffer to swap MAC addresses ([main.rs:560-563](../../relay-xdp-ebpf/src/main.rs)). Two 48-bit register loads + writes would compile to fewer instructions; minor. |
| E-11 | P2 | Performance | Pittle/chonkle are rewritten on every forwarded packet (`write_pittle_chonkle` in `relay_redirect_packet`). Skippable for internal hop forwarding when both relays already trust each other via whitelist - but breaks parity with the C reference and any SDK-side filter on receive. Not worth the divergence. |
| E-12 | P2 | Correctness | `clobber_abi("C")` in inline-asm kfunc wrappers ([main.rs:162,189,219,237](../../relay-xdp-ebpf/src/main.rs)) is the BPF target's ABI; over-clobbering r6-r9 (callee-saved) is harmless but adds spill/reload. Specific clobber list (`r0, r1, r2, r3, r4, r5`) would be tighter; small win and very fragile to specify. Leave as-is. |
| E-13 | P2 | Maintainability | Profile counters live alongside operational counters (indices 133-139); enabling `--features profiling` taxes the hot path with 7 extra `bpf_ktime_get_ns` calls per packet. Acceptable for measurement; just document it does not run in production. |

#### Userspace control plane (relay-xdp)

| ID | Sev | Category | Finding |
|----|-----|----------|---------|
| U-01 | P0 | Performance | `update_timeouts` ([main_thread.rs:604-688](../../relay-xdp/src/main_thread.rs)) iterates session_map (up to 200K entries) and whitelist_map (up to 200K) via Aya's per-entry `bpf_map_get_next_key` + `bpf_map_lookup_elem` syscalls every second. At 100% session occupancy that is ~400K syscalls/sec just for the timeout scan. Switch to `BPF_MAP_LOOKUP_BATCH` + `BPF_MAP_DELETE_BATCH` (kernel ≥ 5.6). See ADR-007. |
| U-02 | P0 | Performance | Single `Mutex<BpfContext>` ([bpf.rs:42](../../relay-xdp/src/bpf.rs)) is shared between main thread (1Hz scan, holds lock across entire iteration phase) and ping thread (10Hz BPF relay_map updates, rare). Under cleanup phases main holds the lock for tens of milliseconds, blocking the only path the ping thread has to ack relay set changes. Replace with finer-grained per-map handles or move both threads' BPF access into a single owner-thread + delta channel. |
| U-03 | P0 | Correctness (style) | Rule "NEVER `unwrap()` in production paths" is violated in [ping_thread.rs:137,151,200](../../relay-xdp/src/ping_thread.rs) (`try_into().unwrap()`, `lock().unwrap()` × 2). The `try_into` is statically safe (8 bytes of a 26-byte buffer); the two `lock().unwrap()` are real production paths that will panic the ping thread on mutex poisoning. Use `unwrap_or_else` + log, or match. |
| U-04 | P1 | Performance | `update_data[encrypt_start..].to_vec()` ([main_thread.rs:375](../../relay-xdp/src/main_thread.rs)) clones the payload before in-place encrypt. Re-use a pre-sized `Vec<u8>` buffer split off via `Vec::split_off(encrypt_start)`, or maintain a separate `Vec` and concat at the end. 1Hz cadence, ~few KB - minor. |
| U-05 | P1 | Performance | `SalsaBox::new(&server_pk, &client_sk)` ([main_thread.rs:385](../../relay-xdp/src/main_thread.rs)) does scalar multiplication on every update. Cache once after `Config` is loaded; ~50-100 μs saved per 1Hz tick. |
| U-06 | P1 | Performance | HTTP POST is synchronous on the main loop ([main_thread.rs:403-409](../../relay-xdp/src/main_thread.rs)); backend latency directly stalls the per-second BPF map timeout scan and the stats accumulation. Move HTTP I/O to a dedicated thread reading from the encrypted-payload queue. |
| U-07 | P1 | Performance | `let old_ids: HashSet<u64> = ... ; let new_ids: HashSet<u64> = ...;` ([main_thread.rs:555-556](../../relay-xdp/src/main_thread.rs)) re-builds two hash sets each tick. Keep a single `HashSet<u64>` between iterations and reuse. |
| U-08 | P1 | Maintainability | No `/metrics` endpoint on the relay (`bpf.rs:46` TODO). Stats are only exposed via the 1Hz HTTP POST to the backend; if backend is unreachable the local relay is dark. Adding a small HTTP server with the same Prometheus format used by relay-backend ([relay-backend/src/metrics.rs](../../relay-backend/src/metrics.rs)) is straightforward. |
| U-09 | P1 | Security | `RELAY_MAX_UPDATE_ATTEMPTS = 30` hard counter ([main_thread.rs:158](../../relay-xdp/src/main_thread.rs)) shuts the relay down after 30 consecutive backend failures. No exponential backoff or jitter on retries; a thundering-herd outage drops every relay simultaneously after ~30s. Add 1.5x exponential backoff capped at 30s; reset on success. |
| U-10 | P1 | Performance | The ELF loader in [bpf.rs](../../relay-xdp/src/bpf.rs) + [kfunc.rs](../../relay-xdp/src/kfunc.rs) (~1.7k lines) is a one-shot startup cost; not a runtime hot path. But the existing `#[inline(never)]` workaround it relies on (see E-07) means we still pay the function-call cost per packet. Verify with profiling. |
| U-11 | P2 | Maintainability | `unwrap()`/`expect()` in `kfunc.rs` (`u64::from_le_bytes(table.rel_data[base..base+8].try_into().expect("8 bytes"))` 7×) - all gated on prior length checks, but each is one panic site that should use `?` against an `anyhow::Error` with `with_context`. |

#### Kernel module (module/relay_module.c)

| ID | Sev | Category | Finding |
|----|-----|----------|---------|
| M-01 | P1 | Security | `__chacha20poly1305_decrypt` ([relay_module.c:71-104](../../module/relay_module.c)) writes the MAC into a stack-local `union` and uses `crypto_memneq` - good. But the kfunc accepts `data: void *, data__sz: int` from BPF and trusts the size verbatim. If a future caller passes a non-trusted size (e.g. from packet field) without bounds check on the BPF side, the in-place ChaCha can scribble past the packet. Currently every call site passes a const; document the contract in a banner comment. |
| M-02 | P2 | Performance | `bpf_relay_sha256` allocates a `SHASH_DESC_ON_STACK` per call ([relay_module.c:148-153](../../module/relay_module.c)). For SHA-256 the descriptor is tiny (~80 bytes on x86_64); per-CPU static allocation would shave a memset and a few cycles, but adds preempt-disable bookkeeping in XDP NAPI context. Net: not worth it. |
| M-03 | P2 | Observability | Self-test only runs in `module_init`. No runtime counters of total kfunc invocations or decrypt-fail counts. Could be added via debugfs but operational counters already come through stats_map - duplication not justified. |

#### relay-xdp-common

| ID | Sev | Category | Finding |
|----|-----|----------|---------|
| C-01 | P2 | Correctness | `#[repr(C, packed)]` on `PingTokenData`, `HeaderData`, `RouteToken`, `ContinueToken` makes `&packed_struct.field` UB on misaligned reads. eBPF + userspace only ever hash these as raw bytes, so it works in practice; but `cargo +nightly miri` will flag any future code that takes references. Document this in a doc-block on each struct. |
| C-02 | P2 | Performance | `RelayStats { counters: [u64; 150] }` = 1200 B. PerCpuArray: 1200 × NR_CPUS bytes. On a 64-core box: 75 KB; on a 192-core (c7i.48xlarge): 230 KB. Still fine but worth knowing. |

#### relay-backend

| ID | Sev | Category | Finding |
|----|-----|----------|---------|
| B-01 | P1 | Performance | `Optimize2` allocates `working: vec![Indirect{...}; num_relays]` *inside* the inner per-`i` loop ([optimizer.rs:257](../../relay-backend/src/optimizer.rs)). At num_relays=1024 and num_segments × num_relays per-segment, that is hundreds of allocations per route matrix build. Hoist the buffer outside the loop (and `working[..num_routes].sort_by_key(...)` in place). Optimize2 ran in ~tens to hundreds of milliseconds per matrix on the prior C reference; expect similar here. |
| B-02 | P1 | Performance | `working[..num_routes].to_vec()` then `row[j] = result` ([optimizer.rs:294-299](../../relay-backend/src/optimizer.rs)) heap-allocates per cell. Replace `Vec<Vec<Indirect>>` cell with a slice-backed `SmallVec<[Indirect; MAX_INDIRECTS]>` or two flat arrays + length. |
| B-03 | P1 | Correctness | `h.join().unwrap()` ([optimizer.rs:306,447](../../relay-backend/src/optimizer.rs)) panics the whole backend if any scoped worker dies. Acceptable for a deterministic compute path, but a `?`-propagation with logged context would survive partial failures. |
| B-04 | P1 | Performance | `relay_update_handler` allocates `plaintext_body = ciphertext.to_vec()` then `Vec::with_capacity(HEADER_SIZE + plaintext_body.len()); full.extend_from_slice(...)` ([handlers.rs:293,307](../../relay-backend/src/handlers.rs)) - two allocations per request. Decrypt directly into a single `BytesMut` and reuse via `arc_swap` or per-task pool. |
| B-05 | P1 | Security | Body size cap is 2 MiB ([handlers.rs:93](../../relay-backend/src/handlers.rs)) - the largest legitimate payload (1000 relays × ~24 B + counters ~1.2 KB + headers) is far below 2 MiB. Tightening to 64 KiB protects against malicious-actor amplification of decrypt cost. |
| B-06 | P1 | Security | `decrypt_relay_request` does the nonce-cache lookup *after* the address-parse + relay-index lookup ([handlers.rs:243-275](../../relay-backend/src/handlers.rs)). An attacker can probe the relay registry by replaying nonces against unknown source addresses and observing differential timing. Hash nonce + relay_index first, fail closed, then look up. Latency cost is one HashMap probe. |
| B-07 | P1 | Performance | Per-relay-counter Prometheus rendering ([metrics.rs:38-85](../../relay-backend/src/metrics.rs)) calls `get_relay_counters(relay.id)` inside the inner `for relay in ...` loop, doing one HashMap lookup per (counter × relay) pair. Cache once per relay outside the counter loop, or pre-build a `Vec<(name, value)>` per relay first. |
| B-08 | P1 | Performance | `format!("{}", request.address)` ([handlers.rs:149,332](../../relay-backend/src/handlers.rs)) allocates a `String` per request just to compute `relay_id`. Provide a `relay_id_from_addr(&SocketAddrV4)` overload that hashes the wire bytes directly. |
| B-09 | P1 | Maintainability | `expect("system clock before unix epoch")` ([main.rs:234,269](../../relay-backend/src/main.rs)) - panic at 03:14:07 UTC, 19 January 2038. Replace with `unwrap_or_else(|_| Duration::ZERO)` per the same pattern already used in `handlers.rs:127`. |
| B-10 | P2 | Observability | No latency histogram for `/relay_update` or `bench_token`. P95/P99 unmeasurable without scraping ingress. Add a tiny in-process histogram. |
| B-11 | P2 | Correctness | `route_matrix_interval_ms` default 1000ms ([config.rs:70](../../relay-backend/src/config.rs)) drives `Optimize2`; if the optimization takes longer than the interval, the tokio interval will lag-burst (tokio `MissedTickBehavior::Burst` is default). Set `interval.set_missed_tick_behavior(Skip)` to avoid catch-up bursts during overload. |

#### relay-sdk

| ID | Sev | Category | Finding |
|----|-----|----------|---------|
| S-01 | P1 | Performance | `BytePool` is used for outbound SERVER_TO_CLIENT (good) but `pump_commands()` and `process_incoming()` allocate temporary `Vec<u8>` and `Vec<Notify>` per call ([server/mod.rs](../../relay-sdk/src/server/mod.rs) hot loop). Reuse via `&mut self`-owned buffers. |
| S-02 | P2 | Performance | `read_write::Reader::read_u16_le` etc. use `try_into().expect("infallible: ...")` after `check_read(2)` ([read_write.rs:132](../../relay-sdk/src/read_write.rs)). The compiler will elide the bounds check in release after the explicit check, but a single `unsafe { *(p as *const u16) }` with debug assertion would be cleaner. Style: trade-off. |
| S-03 | P2 | Correctness | `route_manager/update_begin_next_route` bench reported ~2.5 s under `--quick`; this is suspicious. Re-measure with default sample size and a sane payload (the bench may be iterating a worst-case internal loop). Document expected ranges. |

#### relay-bench

| ID | Sev | Category | Finding |
|----|-----|----------|---------|
| N-01 | P1 | Performance | Tight network loop ([bench_client.rs:768-826](../../relay-bench/src/bin/bench_client.rs)) holds `client_arc.lock().unwrap()` 4× per iteration. The `Mutex<Client>` becomes a serialisation point under high RTT-measurement load. Split outbound and inbound paths to two `RwLock`s or use lock-free `crossbeam::ArrayQueue`. |
| N-02 | P1 | Performance | `sock.set_read_timeout(Some(Duration::from_millis(1)))` ([bench_client.rs:739](../../relay-bench/src/bin/bench_client.rs)) means 1000 wake-ups/s for the network thread regardless of traffic. Use `mio::Poll`/`tokio::net::UdpSocket` or `recv_from` without timeout + a separate timer thread for shutdown polling. |
| N-03 | P2 | Performance | `payload[0..8].try_into().unwrap()` ([bench_client.rs:798](../../relay-bench/src/bin/bench_client.rs)) is statically safe but violates the no-unwrap rule. Cosmetic. |

#### infra & ansible

| ID | Sev | Category | Finding |
|----|-----|----------|---------|
| I-01 | P0 | Performance | No CPU pinning / IRQ affinity in `relay-xdp.service` ([relay-xdp.service.j2](../../ansible/roles/relay-xdp/templates/relay-xdp.service.j2)). With XDP_REDIRECT + cpumap (ADR-008) we need explicit `CPUAffinity=…` so the userspace control plane shares no cores with the NIC RX queues. Also missing: `set_irq_affinity` for the NIC and `rx-usecs`/`tx-usecs` ethtool coalescing tuning. |
| I-02 | P1 | Performance | sysctl set ([common/tasks/main.yml:56-69](../../ansible/roles/common/tasks/main.yml)) covers UDP rmem/wmem and `netdev_max_backlog`. Missing: `net.core.busy_poll`, `net.core.busy_read`, `net.core.dev_weight`. For XDP-attached NICs, `dev_weight=300` (default 64) reduces NAPI poll cost when high-pps. |
| I-03 | P1 | Security | systemd unit grants `CAP_SYS_ADMIN` "for some aya operations on older kernels" ([relay-xdp.service.j2:27](../../ansible/roles/relay-xdp/templates/relay-xdp.service.j2)). On kernel 6.5+ (our minimum) `CAP_BPF + CAP_NET_ADMIN` is sufficient. Drop `CAP_SYS_ADMIN`. |
| I-04 | P2 | Correctness | `relay-nic-tune.sh.j2` ([relay-nic-tune.sh.j2:30](../../ansible/roles/relay-xdp/templates/relay-nic-tune.sh.j2)) parses ethtool output with `awk`; resilient enough but does not check `ethtool -l` exit status. A driver that does not support `-l` will silently leave CUR_COMBINED empty and the script will then run `ethtool -L … combined ""` which fails noisily. Add an empty-string guard. |
| I-05 | P2 | Observability | No node-exporter / process-exporter declared in ansible roles. Operational metrics for the relay-xdp host (memory pressure, NIC queue drops, NAPI poll budgets) come from somewhere else? Document. |

### Cross-cutting findings

- **DDoS filter parity**: `relay-xdp/src/packet_filter.rs` (userspace ping path) and `relay-xdp-ebpf/src/main.rs::compute_pittle/compute_chonkle` produce identical output - verified by `tests/pittle_chonkle_parity.rs` (15 tests). No drift.
- **Wire-format invariants**: `relay-xdp-common` has 15 `const _: () = assert!(...)` size guards and runtime offset checks in `wire_compat.rs` (30 tests, all passing). Solid.
- **Replay protection gap**: SDK has full sliding-window (`REPLAY_PROTECTION_BUFFER_SIZE = 256` slots); eBPF relay has single-counter. See ADR-009.
- **Map-access amplification**: relay-xdp userspace + relay-backend both do per-entry lookups when bulk ops would suffice (U-01 + B-07). Pattern repeats.

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Adopt `BPF_MAP_LOOKUP_BATCH`/`DELETE_BATCH` for session+whitelist timeout scan | Cuts 400K syscalls/sec to ~2 at full session occupancy | [ADR-007](../decisions/ADR-007-batch-bpf-map-ops.md) |
| Add XDP_REDIRECT + cpumap path for multi-core scaling | XDP_TX limits forwarding to RX queue's core; single hot client flow caps at single-core PPS | [ADR-008](../decisions/ADR-008-cpumap-xdp-redirect.md) |
| Add sliding-window replay protection (parity with SDK) | Single-counter check drops legitimate OOO packets and weakens replay protection | [ADR-009](../decisions/ADR-009-sliding-window-replay-relay.md) |
| Per-saddr rate limit before XChaCha20 decrypt | Adds DDoS-amplification protection at <50ns/packet cost | Tracked as part of ADR-008 follow-up |
| Defer relay-xdp `/metrics` endpoint to a separate session | Small standalone change; not architecture | TODO list below |

## Tests Added/Modified

None - audit-only session. Baseline tests verified:

| Test Class | Method | Type | Status |
|------------|--------|------|--------|
| All workspace tests | `cargo test --workspace` | Unit + integration | 416 pass, 16 ignored |
| `func_parity::*` | All 15 | Integration | Pass |
| relay-sdk benches | `criterion --quick` | Bench | Numbers captured above |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| `token_crypto/*` + `route_manager/*` bench rows reported nonsensical multi-second timings under `--quick` | Documented; recommend full-sample re-run before relying on those numbers | No |
| Custom `run_subagent` agent unavailable in this environment | Did the multi-crate audit manually with grep + targeted reads | No |

## Next Steps

1. **High:** Land ADR-007 (batch map ops). Single-file change in `main_thread.rs::update_timeouts`. Estimated 1 session. Measure session-scan duration before/after with profiling counters.
2. **High:** Land ADR-009 (sliding-window replay). Adds 256 B to each `SessionData`; need wire_compat size update + new const assert. Estimated 1 session.
3. **High:** Address U-03 (`unwrap()` in `ping_thread.rs`) - rule violation, simple fix.
4. **Medium:** Prototype ADR-008 (cpumap/XDP_REDIRECT). Requires Ansible CPU-pinning changes + an XDP map type addition. Estimated 2-3 sessions; measure on a multi-core staging instance.
5. **Medium:** Land E-06 (DDoS-filter lookup table). Measure post-change pre-crypto cost; should drop to ~10 ns.
6. **Medium:** Hoist optimizer allocations (B-01, B-02). Verify Optimize2 latency P95 drops by adding `last_optimize_ms` histogram.
7. **Medium:** Backend tightening: B-04, B-05, B-06 (security & alloc cleanup).
8. **Medium:** Land I-01 (CPU pinning) and I-02 (dev_weight/busy_poll sysctls); blocks meaningful XDP_REDIRECT benchmarking.
9. **Low:** Land U-09 (exponential-backoff on `RELAY_MAX_UPDATE_ATTEMPTS`). Operational reliability win.
10. **Low:** Land U-05 (cache `SalsaBox`), U-04, U-06 (HTTP I/O off main loop), U-07 (HashSet reuse) - small wins compounding the 1Hz update.
11. **Low:** Add relay-xdp `/metrics` endpoint mirroring `relay-backend/src/metrics.rs` format. Eliminates the dark-relay scenario.
12. **Low:** Re-test E-07 assumption (`#[inline(never)]` still needed?) on current LLVM/Rust. If fixed upstream, drop the annotations and re-measure.

## Files Changed

| Status | File |
|--------|------|
| A | `docs/sessions/2026-05-18-audit-risk-perf.md` |
| A | `docs/decisions/ADR-007-batch-bpf-map-ops.md` |
| A | `docs/decisions/ADR-008-cpumap-xdp-redirect.md` |
| A | `docs/decisions/ADR-009-sliding-window-replay-relay.md` |

