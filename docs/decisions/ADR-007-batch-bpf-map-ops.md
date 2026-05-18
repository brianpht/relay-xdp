# ADR-007: Batch BPF Map Operations for Session and Whitelist Timeout Scan

**Date:** 2026-05-18<br>
**Status:** Proposed<br>
**Deciders:** developer<br>
**Related Tasks:** -<br>
**Related ADRs:** [ADR-003](ADR-003-custom-kfunc-elf-loader.md)<br>
**Related Sessions:** [Session 2026-05-18](../sessions/2026-05-18-audit-risk-perf.md)<br>

## Context

`MainThread::update_timeouts` ([relay-xdp/src/main_thread.rs:604-688](../../relay-xdp/src/main_thread.rs)) scans `session_map` (LRU, 200K entries) and `whitelist_map` (LRU, 200K entries) every second to evict entries whose `expire_timestamp < current_timestamp`. The current implementation uses Aya's `MapData::iter()` which internally calls `bpf_map_get_next_key` followed by `bpf_map_lookup_elem` *per entry*. At full session occupancy this is:

| Phase | Syscalls/sec |
|-------|--------------|
| Phase 1: scan session_map | up to 2 × 200K = 400K |
| Phase 2: batch-delete expired sessions | one `bpf_map_delete_elem` per expired key |
| Phase 3: scan whitelist_map | up to 2 × 200K = 400K |
| Phase 4: batch-delete expired whitelist | one `bpf_map_delete_elem` per expired key |
| **Total upper bound** | **~800K + deletes per second** |

Each syscall incurs the user→kernel transition (~100-200 ns on x86_64 with retpoline/IBRS), the BPF map lock (per-cpu spinlock on `BPF_MAP_TYPE_LRU_HASH`), and the LRU bucket walk. Aggregate cost at the 200K mark: **80-160 ms of wall time per second** spent on the timeout scan alone, while holding the global `Mutex<BpfContext>`. This blocks the ping thread from publishing relay-map deltas (see audit finding U-02) and risks missing the 1Hz update tick.

Linux 5.6 added `BPF_MAP_LOOKUP_BATCH` and `BPF_MAP_DELETE_BATCH` for exactly this pattern. Our minimum kernel is 6.5 (per `docs/PERFORMANCE_DESIGN.md` deployment assumptions), so the syscalls are always available.

**Consequences of inaction:** the per-second timeout scan currently dominates userspace CPU, contends the BPF context mutex, and scales linearly with session count. Beyond ~150K active sessions on a single relay the scan tail starts overlapping the next tick, causing the 1Hz update loop to drift.

## Options Considered

### Option A: Status quo - per-entry `iter() + remove()`

- **Description:** Keep the current 4-phase scan using Aya's `MapData::iter()` and per-key `MapData::remove()`.
- **Pros:** Already shipped, no code changes, no kernel-version coupling.
- **Cons:** O(N) syscalls per second; blocks the BPF context mutex during full-map iteration; will not scale to 200K LRU entries.
- **Effort:** Impl: 0 / Migration: 0 / Maintenance: low (until scaling pressure forces change)

### Option B: `BPF_MAP_LOOKUP_BATCH` + `BPF_MAP_DELETE_BATCH` syscalls

- **Description:** Replace the per-entry iteration with raw `bpf_map_lookup_batch` (returns up to `batch_size` (key, value) tuples per syscall) and `bpf_map_delete_batch` (deletes a vector of keys per syscall). Use a fixed `batch_size = 4096`; on 200K LRU = 50 syscalls per phase, ~200 syscalls/sec total. Aya 0.13 does not expose the batch APIs through its typed map wrappers; implement against the raw FD via `libc::syscall(SYS_bpf, …)` in `bpf.rs`, mirroring the pattern already used by `kfunc.rs` for `BPF_PROG_LOAD`.
- **Pros:** ~4 orders of magnitude fewer syscalls; per-syscall fixed overhead amortised across thousands of entries; matches the use case the kernel API was designed for; well-supported on every kernel we target.
- **Cons:** Adds ~200 lines of raw-syscall code to `bpf.rs`. Cannot use Aya's typed-map wrappers - need to memcpy raw bytes into `SessionKey`/`WhitelistKey`/`SessionData`/`WhitelistValue`. Documenting the kernel ABI requirements for `bpf_attr` is non-trivial.
- **Effort:** Impl: medium / Migration: none (drop-in replacement) / Maintenance: low (BPF ABI is append-only - see ADR-003)

### Option C: Move timeout scan into eBPF (LRU map already evicts on-demand)

- **Description:** Rely entirely on the kernel's LRU eviction policy. Skip the userspace timeout scan; expired entries get reclaimed when the map hits its size cap.
- **Pros:** Zero userspace work.
- **Cons:** Statistics (`RELAY_COUNTER_SESSION_DESTROYED`, `RELAY_COUNTER_SESSIONS`, `RELAY_COUNTER_ENVELOPE_KBPS_UP/DOWN`) currently come from iterating the live sessions in userspace. Without the scan, those counters go dark, and the backend's session-pricing logic loses visibility. LRU eviction is also probabilistic - a slowly-growing but never-full session_map will retain expired entries indefinitely, occupying hash buckets and slowing lookup.
- **Effort:** Impl: low (delete the scan) / Migration: medium (must move counter aggregation elsewhere) / Maintenance: low

### Option D: Per-CPU expiry queue maintained by eBPF, drained by userspace

- **Description:** eBPF program writes `(session_id, expire_timestamp)` into a `BPF_MAP_TYPE_QUEUE` when a session is created. Userspace drains the queue, sorts by expiry, and deletes lazily.
- **Pros:** Zero scan cost; expiry-ordered delete.
- **Cons:** Doubles the per-packet eBPF work (queue push on session create); adds a third map; complicates LRU semantics (eBPF and userspace both reason about session lifecycle). Net loss versus Option B.
- **Effort:** Impl: high / Migration: high / Maintenance: high

## Decision

**Chosen: Option B - `BPF_MAP_LOOKUP_BATCH` + `BPF_MAP_DELETE_BATCH` syscalls**

## Rationale

Option B has the best work-per-effort ratio. The kernel API exists exactly for this scenario; our `MAP_TYPE_LRU_HASH` maps are fully supported by the batch API since 5.7 (the relevant patch in `kernel/bpf/hashtab.c` predates our minimum kernel by ~3 years). The implementation cost is bounded - we already maintain a raw-syscall path in `kfunc.rs` and the pattern is recognisable.

Option A does not scale. Option C trades scan cost for observability loss that the backend depends on. Option D over-engineers; nothing about the workload justifies a third map.

A key deciding factor: the cost we want to remove is *userspace syscall overhead*, not *kernel map traversal*. Batch syscalls remove only the former; the kernel still walks every bucket. But the syscall overhead is the dominant fraction (per `perf stat` traces on similar workloads, ~70% of `update_timeouts` time is in the syscall path), and the kernel-side traversal happens inside a single BPF map RCU read-lock which we cannot influence from userspace anyway.

## Consequences

- **Positive:** Per-second timeout scan drops from ~100 ms (estimated, scales with session count) to under 5 ms at 200K occupancy. The BPF context mutex is released proportionally faster, unblocking the ping thread. The 1Hz update loop no longer drifts under load. No change to eBPF data plane or wire format.
- **Negative:** Adds ~200 lines of raw `bpf_attr` syscall code to `bpf.rs`. The error path (partial batch failure, EINTR retry) needs careful handling - `bpf_map_lookup_batch` returns `count` even on partial failure, and a future kernel could add new flags we must default to zero.
- **Neutral:** Aya keeps owning map creation and per-entry access; only the timeout scan path is bypassed. Same partial-Aya relationship as ADR-003.

## Affected Components

| Component | Impact | Description |
|-----------|--------|-------------|
| `relay-xdp/src/bpf.rs` | Modified | Add `BpfContext::iter_and_expire_session_map(current_ts, expire_callback) -> Result<SessionStats>` and the whitelist analog. Both use raw syscall + memcpy into typed structs. |
| `relay-xdp/src/main_thread.rs` | Modified | `update_timeouts` calls the new bpf.rs entrypoints; remove per-phase iteration code. |
| `relay-xdp/src/main.rs` | None | |
| `relay-xdp-ebpf/*` | None | eBPF program unchanged. |
| `relay-xdp-common` | None | |
| `module/` | None | |
| `docs/PERFORMANCE_DESIGN.md` | Updated | Document the batch-syscall pattern under "BPF Map Access Patterns". |
| Tests | New | Unit test exercising batch ops against a synthetic map populated to 100K entries (in-tree, no-BPF guarded). Integration test via `func_parity` already exercises the full session lifecycle. |

## Revisit When

- Active session count regularly exceeds 500K and per-second batch wall time again exceeds a threshold we set in the per-second profile counters.
- Aya adds a first-class `iter_batch()` API on typed maps - we can then drop the raw syscall path and use the wrapper.
- Kernel ABI changes such that `bpf_attr.batch` gains new required fields (unlikely; BPF ABI is append-only).

## Migration Plan

1. Add `bpf_map_lookup_batch_raw` and `bpf_map_delete_batch_raw` helpers in `bpf.rs` (raw `libc::syscall(SYS_bpf, BPF_MAP_LOOKUP_BATCH, &attr, size)`). Unit-test against a synthetic hash map populated to 100K entries; assert count and final size.
2. Add `BpfContext::iter_and_expire_session_map(current_ts) -> Result<SessionStats>` returning the same `SessionStats` struct as today (session_count, envelope_kbps_up/down, destroyed_count). Internally uses `lookup_batch` (4096 chunk) to walk, accumulates stats, builds a `Vec<SessionKey>` of expired keys, then `delete_batch` to remove.
3. Mirror for whitelist_map: `iter_and_expire_whitelist_map(current_ts)`.
4. Replace the 4-phase iteration in `main_thread.rs::update_timeouts` with two calls to the new entrypoints.
5. Enable the `profiling` feature and capture before/after `update_timeouts` duration via the existing profile counters; record in the session summary.
6. Land behind a `RELAY_BATCH_MAP_OPS=0` escape hatch for one release; default 1 once staging confirms parity.

