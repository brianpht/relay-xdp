# ADR-001: Use RELAY_NO_BPF=1 for Docker Compose Integration Tests

**Date:** 2026-04-05<br>
**Status:** Accepted<br>
**Deciders:** developer<br>
**Related Tasks:** Docker Compose integration test suite<br>
**Related ADRs:** N/A<br>
**Related Sessions:** [Session 2026-04-05](../sessions/2026-04-05-compose-integration-test-plan.md)<br>

## Context

The project needs multi-process integration tests that exercise real network communication between relay-xdp nodes and relay-backend. Current in-process tests (tower::oneshot, mock HTTP backends) cover wire format and logic but cannot validate cross-process HTTP, UDP ping, Redis leader election, or startup/shutdown behavior.

relay-xdp uses XDP/eBPF for packet processing, which requires:
- `--privileged` or `CAP_BPF + CAP_SYS_ADMIN + CAP_NET_ADMIN`
- `--net=host` (XDP attaches to host NIC, not container veth)
- Host kernel 6.5+ with `relay_module.ko` loaded

These constraints prevent running multiple relay-xdp containers in isolated Docker networks.

## Options Considered

### Option A: Full XDP mode in Docker

- **Description:** Run relay-xdp containers with `--privileged --net=host` and require kernel module on CI host.
- **Pros:** Tests the full eBPF path | **Cons:** All containers share host network namespace (port conflicts), requires custom CI runner with kernel 6.5+ and module loaded, cannot run 3 relays on same host | **Effort:** Impl: High / Migration: High / Maintenance: High

### Option B: RELAY_NO_BPF=1 userspace-only mode in Docker Compose

- **Description:** Run relay-xdp in userspace-only mode (`RELAY_NO_BPF=1`) on a standard Docker bridge network. Each container gets its own network namespace with a unique static IP. eBPF/XDP is skipped entirely.
- **Pros:** Standard Docker networking, no privileged mode, runs on any CI runner, tests real HTTP + UDP + Redis across processes | **Cons:** Does not test eBPF packet processing path | **Effort:** Impl: Medium / Migration: Low / Maintenance: Low

### Option C: Do nothing

- **Description:** Rely on existing in-process tests only.
- **Pros:** No additional infrastructure | **Cons:** Cannot catch cross-process bugs (serialization over TCP, UDP ping across namespaces, Redis race conditions, env var misconfiguration) | **Effort:** Impl: None / Migration: None / Maintenance: None

## Decision

**Chosen: Option B - RELAY_NO_BPF=1 userspace-only mode in Docker Compose**

Use Docker Compose with `RELAY_NO_BPF=1` to test multi-process communication. eBPF-specific behavior remains covered by `wire_compat` and `func_parity` test suites.

## Rationale

- Option A is infeasible: `--net=host` means all containers share one network, making multi-relay topology impossible on a single host.
- Option C leaves real gaps: in-process tests use mocks/oneshot and cannot catch network serialization bugs, Redis race conditions, or process lifecycle issues.
- Option B covers the largest untested gap (cross-process communication) with standard CI infrastructure. The eBPF path is already validated by separate test suites that do not require Docker.

## Consequences

- **Positive:** Real HTTP, UDP, and Redis communication tested across processes. Catches config/env var mismatches. Runs on standard GitHub Actions runners.
- **Negative:** eBPF packet processing is not tested in compose. Separate bare-metal testing still needed for full XDP validation.
- **Neutral:** Requires a `Dockerfile.nobpf` to avoid wasting ~12 minutes building the eBPF nightly stage that is never used.

## Affected Components

| Component | Impact | Description |
|-----------|--------|-------------|
| `relay-xdp` | Medium | New `Dockerfile.nobpf` (2-stage build without eBPF) |
| `relay-backend` | Low | Existing Dockerfile reused as-is |
| `.github/workflows` | Low | New `compose-test` CI job |
| `tests/` | Medium | New `docker-compose.test.yml`, `compose-test.sh`, fixture JSON |

## Revisit When

- A self-hosted CI runner with kernel 6.5+ and `relay_module.ko` becomes available, enabling Option A
- A kernel BPF testing framework (e.g. bpf-conformance, virtme-ng) matures enough to run XDP programs in a VM on standard runners

## Migration Plan

1. Build `relay-xdp/Dockerfile.nobpf` (skip eBPF nightly stage)
2. Create `docker-compose.test.yml` with static-IP bridge topology (redis + backend + relay-a/b/c)
3. Create `tests/compose-test.sh` with curl-based assertion suite
4. Add `compose-test` job to `.github/workflows/rust.yml` (runs after `test` job)
5. Generate deterministic test keypairs via `tests/gen-test-keys.sh`
