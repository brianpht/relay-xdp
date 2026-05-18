# ADR-008: XDP_REDIRECT via cpumap for Multi-Core Forwarding

**Date:** 2026-05-18<br>
**Status:** Proposed<br>
**Deciders:** developer<br>
**Related Tasks:** -<br>
**Related ADRs:** [ADR-003](ADR-003-custom-kfunc-elf-loader.md), [ADR-005](ADR-005-c6in-ena-express.md)<br>
**Related Sessions:** [Session 2026-05-18](../sessions/2026-05-18-audit-risk-perf.md)<br>

## Context

Every forwarded packet in `relay-xdp-ebpf/src/main.rs` returns `XDP_TX` (see `handle_route_*`, `handle_*_to_*`, `handle_session_*`, `handle_continue_*`). `XDP_TX` instructs the driver to enqueue the packet on the TX ring *paired with the RX ring that received it*. On AWS ENA and most modern NICs the pairing is symmetric: RX queue N → TX queue N. Together with NIC-side RSS hashing (5-tuple by default), this implies:

- All traffic from a single client/server flow lands on **one** RX queue.
- That single queue's softirq (NAPI poll) runs on **one** CPU core.
- Both DDoS-filter, crypto verify, and `XDP_TX` rewrite for that flow consume that core's cycles.
- A heavily-played game session with high outbound pps can saturate **one** core regardless of total core count.

`docs/PERFORMANCE_DESIGN.md` § 1 names XDP_PASS the "slow path" and counts cycles aggressively, but does not address the per-core throughput cap. ADR-005 chose `c6in.8xlarge` (32 vCPU, ENA Express) - 32-way RSS gives us 32x headroom *across many flows*, but per-flow we are stuck at one core's processing budget.

XDP_REDIRECT with `BPF_MAP_TYPE_CPUMAP` decouples packet *reception* (NIC driver, one core per RX queue) from packet *processing* (any core). The driver enqueues the raw packet descriptor into a kernel-managed per-CPU ring; a kthread on the target CPU dequeues, runs a second XDP program (or just passes to the stack), and TXes from a different queue. This lets us:

- Spread per-flow load across an N-core fanout group.
- Hash inbound packets by `(session_id, packet_type)` instead of `(saddr, sport, daddr, dport)` so route-request and route-response for the same session share a core (cache locality for `SessionData`).
- Keep the userspace control plane on its own pinned cores, never sharing with the NIC NAPI cores.

The downside is a context switch into the cpumap kthread, ~200 ns per packet on x86_64 NUMA-local. For the relay's per-packet budget (1 µs target), this is 20% overhead - not free.

**Consequences of inaction:** per-flow throughput remains pinned to one core's XDP processing rate (~10-15 Mpps for our handler complexity on c6in-class hardware, give or take). A single chatty game session that bursts to ~200 kpps will be fine; a heavily-used relay carrying many such sessions through one RSS bucket will not.

## Options Considered

### Option A: Status quo - XDP_TX everywhere, rely on NIC RSS

- **Description:** Keep returning `XDP_TX` from every handler. Tune RSS to a strong 5-tuple hash and trust that flow distribution across N queues is roughly uniform.
- **Pros:** Zero new complexity. Lowest per-packet latency (no cpumap dequeue). Already shipped.
- **Cons:** A single hot flow / hot session cannot exceed one-core throughput. Userspace control plane is at the mercy of NIC IRQ affinity - no isolation.
- **Effort:** Impl: 0 / Migration: 0 / Maintenance: low

### Option B: XDP_REDIRECT via cpumap with a pinned fanout group

- **Description:** Reserve `N_FANOUT` cores (e.g. 8 cores) as the redirect target group. Build a `BPF_MAP_TYPE_CPUMAP` with `N_FANOUT` entries, each backed by a kthread that re-runs the relay's TX-side logic (rewrite headers, recompute filter bytes, TX). The eBPF XDP entry point dispatches via `bpf_redirect_map(&cpu_map, hash(session_id) % N_FANOUT, 0)`. Userspace control plane is pinned (via `taskset` / systemd `CPUAffinity=`) to a disjoint core set. NIC IRQs are affined to a third disjoint set via `set_irq_affinity`.
- **Pros:** Per-flow throughput is no longer one-core-bounded - a hot session can use up to N_FANOUT cores' worth of TX work. Session map cache locality is preserved (hash-by-session-id). Control plane gets dedicated CPUs and is not preempted by NAPI. NIC NUMA placement becomes explicit.
- **Cons:** Adds ~200 ns/packet for cpumap dequeue. Requires a second tiny XDP program (the cpumap target program). Doubles the eBPF surface: now we have a "RX" XDP and a "TX" XDP. Adds an Ansible CPU-pinning role and an environment variable (`RELAY_XDP_FANOUT_CORES`). Adds risk of misconfiguration (overlapping CPU sets silently degrade throughput).
- **Effort:** Impl: high / Migration: medium / Maintenance: medium

### Option C: AF_XDP for the slow path only, XDP_TX for the fast path

- **Description:** Keep XDP_TX for the >95% of packets that match the fast-forward path. Use AF_XDP (zero-copy user-mode socket) for `RELAY_PONG_PACKET` and anything else currently going to XDP_PASS, so the ping thread receives in zero-copy. cpumap not used.
- **Pros:** Removes one of the few XDP_PASS sites; ping thread no longer pays the kernel socket cost. Smaller change than Option B.
- **Cons:** Does not solve the per-flow cap (the actual goal). The XDP_PASS volume is already negligible (relay-to-relay pong, ~10 pps per peer).
- **Effort:** Impl: medium / Migration: low / Maintenance: low

### Option D: Multi-RX-queue stitching via XDP_REDIRECT to a different TX queue (devmap)

- **Description:** Use `BPF_MAP_TYPE_DEVMAP` to redirect to a different egress device/queue instead of cpumap. Keeps processing on the RX-side CPU but uses a target TX queue that may share a different CPU's wakeup.
- **Pros:** Cheaper than cpumap (no kthread).
- **Cons:** Does not solve per-flow CPU cap (processing still happens on the RX CPU). Mostly useful for multi-NIC setups, which we do not have.
- **Effort:** Impl: medium / Migration: low / Maintenance: low

## Decision

**Chosen: Option B - XDP_REDIRECT via cpumap with a pinned fanout group**

## Rationale

Option B is the only choice that actually addresses the per-flow throughput cap. Option A keeps the cap. Option C and Option D are tangential.

The 200 ns dequeue cost is acceptable in our budget: total per-packet headroom is ~1 µs, current measured fast path is ~600-700 ns (estimated from `--features profiling` counters once enabled), leaving 300+ ns of headroom even after cpumap.

A key deciding factor is the CPU-pinning side benefit. Right now, when the userspace control plane scans 200K sessions (see ADR-007), it may be running on the same core as NAPI for one of the RX queues. The two compete for the L1/L2 cache, and the scan stalls packet processing. With explicit pinning - and only with explicit pinning - we can guarantee no overlap. Option B forces us to do the pinning work anyway, so we get the isolation as a no-cost side effect.

The eBPF complexity cost is bounded: the cpumap-target program is short (~100 lines), and we already maintain ~2000 lines of eBPF. Adding a TX-side mirror handler is straightforward.

## Consequences

- **Positive:** Per-flow throughput no longer one-core-bounded; relay can handle hot sessions at multi-core throughput. Userspace control plane and NIC NAPI are explicitly isolated. NUMA placement is explicit and documented. The TX-side eBPF program is a natural place to add observability and per-CPU congestion counters.
- **Negative:** ~200 ns of additional per-packet latency. Two eBPF programs to maintain instead of one. New environment variable + Ansible role for CPU pinning. Misconfiguration (overlapping CPU sets) silently degrades performance - need a startup check.
- **Neutral:** Same XDP attach mode (native on ENA, SKB fallback). cpumap support landed in kernel 4.15; well within our 6.5 minimum.

## Affected Components

| Component | Impact | Description |
|-----------|--------|-------------|
| `relay-xdp-ebpf/src/main.rs` | Modified | RX entry point dispatches via `bpf_redirect_map(&cpu_map, hash, 0)` after DDoS filter and packet-type identification. The session-bearing packet types redirect; ping/pong still XDP_TX (low pps, latency-sensitive). |
| `relay-xdp-ebpf/src/cpumap_target.rs` | New | New attach point: cpumap-program type. Implements the forwarding work that today lives in `handle_*_packet`. Initially a copy with shared helpers in `mod common`. |
| `relay-xdp/src/bpf.rs` | Modified | Load two programs; attach RX to NIC, attach cpumap target via `bpf_prog_attach` to each cpumap entry. Add `cpumap` to the BPF maps list. |
| `relay-xdp/src/kfunc.rs` | Modified | Patch both code sections (kfunc calls now appear in two programs). |
| `relay-xdp/src/config.rs` | Modified | New env vars: `RELAY_XDP_FANOUT_CORES` (comma-separated CPU list), `RELAY_XDP_FANOUT_QSIZE` (cpumap queue size, default 8192). |
| `relay-xdp-common/src/lib.rs` | Modified | Add `MAX_FANOUT_CORES` const, `RELAY_COUNTER_CPUMAP_*` counters. |
| `ansible/roles/relay-xdp/*` | Modified | Add `relay-cpu-pin.sh` template that consumes `relay_xdp_fanout_cores`, `relay_xdp_userspace_cores`, `relay_xdp_irq_cores` and applies systemd CPUAffinity + ethtool IRQ pinning. systemd unit gets `CPUAffinity=` directive. |
| `docs/PERFORMANCE_DESIGN.md` | Updated | New section "CPU placement", per-flow scaling, cpumap dequeue cost. |
| `docs/ARCHITECTURE.md` | Updated | Add cpumap to the BPF Map Schema. Update BPF program list to two programs. |
| Tests | New | `func_parity` integration test exercising the cpumap path under `RELAY_NO_BPF=0` (requires a CI runner with multiple cores and root). |
| Benches | New | Relay-bench loadgen scenario: single 200 kpps flow, measure p50/p99 latency before/after on the same hardware. |

## Revisit When

- Single-flow PPS demand stops growing (i.e. one core's XDP_TX throughput would always be enough). cpumap then becomes pure overhead.
- The kernel adds a "RX-side fanout" XDP action that does not need a cpumap kthread (e.g. via a `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY`-like NIC-driven distribution). Currently no such proposal upstream.
- We move to a NIC with hardware-offloaded XDP (e.g. Mellanox CX-6 with `XDP_FLAGS_HW_MODE`); offloaded XDP cannot use cpumap.

## Migration Plan

1. **Phase 0 (CPU pinning, prerequisite):** Land Ansible role for CPU pinning without changing eBPF. Pin userspace to cores 0-3, leave NIC NAPI on whatever cores it picks. Measure baseline. Ship to staging only.
2. **Phase 1 (eBPF code split):** Extract the per-packet-type handlers into a `common.rs` module shared by `main.rs` (RX) and a new `cpumap_target.rs` (TX). No behaviour change yet; verify byte-for-byte parity via `func_parity`.
3. **Phase 2 (loader):** Update `bpf.rs` to load and attach two programs. Cpumap target initially attached but unused; RX continues to use XDP_TX. Add `relay_cpumap_attached` startup log line.
4. **Phase 3 (dispatch):** RX entry point uses `bpf_redirect_map` for session-bearing packet types when `RELAY_XDP_FANOUT_CORES` is set. Keep ping/pong on XDP_TX. Add per-CPU counters of redirect hits/misses.
5. **Phase 4 (validation):** Run staging traffic for 1 week. Compare counters: redirect hit rate >95%, miss reason breakdown, no observed verifier failures, no socket buffer drops (`net.core.dropped_packets`).
6. **Phase 5 (production):** Default `RELAY_XDP_FANOUT_CORES` in production Ansible inventory; keep env var as override / disable path.
7. **Phase 6 (cleanup):** After 1 month of production stability, remove the XDP_TX dispatch path for session-bearing packet types and require fanout configuration.

