# ADR-004: E2E Deployed Test Flow Against Live Pulumi Stack

**Date:** 2026-05-05<br>
**Status:** Accepted<br>
**Deciders:** developer<br>
**Related Tasks:** `tests/e2e-deployed.sh`, `infra/stack_outputs.py`, `ansible/playbooks/e2e-verify.yml`<br>
**Related ADRs:** [ADR-001](ADR-001-compose-nobpf.md), [ADR-002](ADR-002-pulumi-infra-over-manual-inventory.md)<br>
**Related Sessions:** `docs/sessions/2026-05-05-e2e-deployed-test-plan.md`<br>

## Context

The project has two existing test layers:

1. **Docker Compose (`RELAY_NO_BPF=1`)** - 10 HTTP assertions against a local 5-service topology
   with hardcoded IPs (172.28.0.x). Covers cross-process HTTP, UDP ping, Redis. Does not test
   eBPF, real network, or live infrastructure.
2. **`relay_sdk_smoke`** - 13 assertions split across HTTP backend checks (groups 1-2) and
   SDK client/server state (groups 3-4). Runs against either Compose or a real endpoint.

No automated test harness runs against a live Pulumi-provisioned stack. Once `pulumi up`
completes and Ansible deploys software, the only verification is manual: `systemctl status`,
`bpftool prog list`, `lsmod`, `journalctl`. This leaves the following gaps uncovered:

- XDP program loading and kfunc resolution on real hardware (c5n.xlarge native mode,
  t3.medium SKB fallback).
- Real UDP relay path: client -> relay-a -> relay-b -> relay-c -> server, with live RTT
  measurements and session key validation.
- Backend HTTP endpoints at production ports (8090 public, 8091 admin) vs Compose ports
  (80/81).
- `route_matrix` convergence across all 3 deployed relay nodes.
- Per-relay `relay_counters` statistics after actual packet flow.

The gap between Compose tests and a live stack means a failed deploy can appear healthy
until a game client connects and experiences packet loss.

## Options Considered

### Option A: Developer laptop as test runner (within `admin_cidr`)

- **Description:** Run `tests/e2e-deployed.sh` and `relay_sdk_smoke --e2e-udp` from the
  developer's laptop. The laptop IP is already in `admin_cidr` (Pulumi Security Group rule
  for port 8091). No additional infrastructure is required.
- **Pros:** Zero extra infra cost, uses existing SG rules, fast iteration, forensic access
  to relay logs on failure | **Cons:** Requires developer to be on the right IP; not
  suitable for unattended CI without stored credentials | **Effort:** Impl: Low /
  Maintenance: Low

### Option B: Dedicated CI runner with live AWS credentials

- **Description:** Run E2E tests from a GitHub Actions runner with OIDC IAM role.
  `admin_cidr` would be set to a fixed CI egress IP or `0.0.0.0/0` for port 8091.
- **Pros:** Fully automated post-merge validation | **Cons:** Requires stored AWS credentials,
  OIDC role setup, fixed CI egress IP or open admin port, adds ~15 min to CI pipeline,
  costs ~$0.50/run in EC2 hours | **Effort:** Impl: Medium / Maintenance: Medium

### Option C: Do nothing - rely on manual Ansible verify steps

- **Description:** Keep current `ansible/README.md` manual checklist:
  `systemctl`, `bpftool`, `lsmod`, `journalctl`.
- **Pros:** No new code | **Cons:** Not automated, skipped under time pressure,
  cannot catch UDP/relay path regressions | **Effort:** Impl: None / Maintenance: High
  (human labour every deploy)

## Decision

**Chosen: Option A - Developer laptop as test runner, with Option B as future escalation**

Run E2E tests from the developer's laptop. Option B (CI runner) is documented as a future
escalation path when team size or deploy frequency justifies the additional infrastructure.

## Rationale

- Option C is insufficient: manual verification cannot catch route convergence failures
  or UDP path regressions. Every deploy requires human attention to a checklist.
- Option B is premature: with a single operator and infrequent production deploys, the
  cost and complexity of OIDC + fixed CI egress IP outweighs the benefit. The current
  `admin_cidr` SG rule already covers the developer laptop without any changes.
- Option A provides full E2E coverage (HTTP + UDP + XDP liveness) at zero extra infra
  cost by reusing existing SG rules and leveraging `infra/stack_outputs.py` to replace
  the hardcoded Compose IPs with live Pulumi output values.

Key deciding factors:
- UDP/40000 is already open to `0.0.0.0/0` in `infra/network.py` - no SG change needed
  for the relay data path.
- `POST /relay_update` on port 8090 is public-facing - session injection tests the same
  code path as a real game server, not a test-only endpoint.
- Leaving the stack alive on failure preserves relay logs, `bpftool` state, and
  `journalctl` output for root-cause analysis - more valuable than auto-teardown.

## Session Injection: `/relay_update` vs Test-Only Endpoint

The E2E test registers sessions via `POST ${BACKEND_HOST}:${BACKEND_PORT}/relay_update`,
the same endpoint used by production game servers. A test-only injection endpoint was
considered and rejected for the following reasons:

- It would require a code change in `relay-backend` that is never active in production,
  adding dead code and a maintenance surface.
- Testing via `/relay_update` validates the full production code path: route optimization,
  session table write, relay propagation via 1 Hz update cycle.
- Port 8090 is already open to `0.0.0.0/0` by the production SG rule in `network.py`.
  No additional SG change is required.

This principle - test production paths, not test-only shortcuts - is consistent with
the approach taken in ADR-001 (using `RELAY_NO_BPF=1` to preserve the relay processing
logic path even when eBPF is absent).

## Leave-Up-On-Failure Policy

On any assertion failure, `tests/e2e-deployed.sh` exits non-zero and leaves the stack
running. Rationale:

- Live relay logs (`journalctl -u relay-xdp --since "10 min ago"`) show the packet flow
  state at the exact moment of failure.
- `bpftool prog list` and `bpftool map dump` show whether XDP was loaded and what the
  session/whitelist map contains.
- `pulumi destroy` is a destructive, irreversible operation: all EIPs are released and
  node IPs change on next `pulumi up`.
- A separate `make e2e-teardown` target is provided for explicit cleanup when
  investigation is complete.

One exception: `make e2e-teardown` refuses to destroy the `production` stack (guarded
by a shell `[ "$STACK" = "production" ]` check).

## `--reuse-stack` Shortcut

The `e2e-deployed` Makefile target accepts `REUSE_STACK=1` to skip `pulumi up` when the
stack is already provisioned with valid outputs. This reduces iteration time by 5-10
minutes on fast-iteration runs where only the Ansible deployment or test assertions have
changed, not the infrastructure.

```makefile
make e2e-deployed REUSE_STACK=1 STACK=staging
```

## `infra/stack_outputs.py` Shared Parser

Instead of duplicating Pulumi JSON parsing logic between `inventory_gen.py` and the E2E
shell script, a shared `infra/stack_outputs.py` helper was introduced. It accepts a
`--format env` flag and emits shell `export` statements consumed by `tests/e2e-deployed.sh`
via `eval`. Both `inventory_gen.py` and the E2E test now use the same parsing logic,
reducing the risk of divergence when Pulumi output keys change.

```
python infra/stack_outputs.py --stack staging --format env
# export BACKEND_HOST=1.2.3.4
# export BACKEND_PORT=8090
# export ADMIN_BACKEND_PORT=8091
# export RELAY_PUBLIC_IPS="10.x.x.x 10.y.y.y 10.z.z.z"
# export RELAY_IDS="relay-staging-1 relay-staging-2 relay-staging-3"
```

## `route_matrix` Convergence Poll

The Group 4 UDP test in `relay_sdk_smoke` must not run before all 3 relay nodes have
registered with the backend. A 20-second poll on `GET ${ADMIN_BACKEND_PORT}/route_matrix`
checks that the response body size exceeds a minimum threshold (indicating all 3 relay
entries are present). This prevents flaky failures caused by the relay update cycle
(1 Hz) not completing before the first UDP packet is sent.

## Consequences

- **Positive:** Full E2E coverage from `pulumi up` through live UDP packet delivery.
  Catches eBPF load failures, kfunc resolution errors, session map mismatches, and
  route convergence issues that Compose tests cannot reach. Ansible `e2e-verify.yml`
  playbook provides per-node liveness checks (`systemctl`, `bpftool`, `lsmod`, `ss`,
  `journalctl`) that run before HTTP/UDP assertions.
- **Negative:** Requires developer laptop to be within `admin_cidr` at test time.
  Stack must remain running (costs ~$0.02/hr in EIP charges) until `make e2e-teardown`
  is run. `route_matrix` convergence poll adds up to 20 seconds of latency before
  Group 4 UDP assertions begin.
- **Neutral:** Compose tests (`tests/compose-test.sh`) are unchanged and continue to
  run in CI. The E2E deployed test is an additional layer for pre-production validation,
  not a replacement for Compose tests.

## Affected Components

| Component | Impact | Description |
|-----------|--------|-------------|
| `tests/e2e-deployed.sh` | New | 10+ HTTP assertions against live backend; TCP preflight on 8091; loops over `${RELAY_IDS}` |
| `infra/stack_outputs.py` | New | Shared Pulumi JSON parser; `--format env` output consumed by `e2e-deployed.sh` |
| `infra/test_stack_outputs.py` | New | Unit tests for `stack_outputs.py` parser |
| `infra/inventory_gen.py` | Modified | Imports from `stack_outputs.py` instead of duplicating parse logic |
| `ansible/playbooks/e2e-verify.yml` | New | Per-node liveness checks; runs after `site.yml`, before HTTP/UDP assertions |
| `relay-sdk/src/bin/relay_sdk_smoke.rs` | Modified | Group 4 UDP E2E (gated by `RELAY_E2E_UDP=1`); group tags on all output lines; final JSON summary |
| `Makefile` | Modified | `e2e-deployed` + `e2e-teardown` targets |

## Revisit When

- Team size grows beyond 1 operator: add Option B (GitHub Actions + OIDC) as automated
  nightly CI. No structural changes are needed - `tests/e2e-deployed.sh` is already
  parameterized via environment variables from `stack_outputs.py`.
- `admin_cidr` is set to a fixed CI egress IP: the TCP preflight check on 8091 becomes
  the only gate rather than a diagnostic aid.
- UDP path test coverage needs to expand beyond echo equality to latency distribution
  or packet reorder detection.

## Operator Runbook

```
# Full E2E flow (provision + deploy + verify + test)
make e2e-deployed STACK=staging RELAY_VERSION=<git-sha>

# Fast iteration (skip pulumi up, redeploy + test only)
make e2e-deployed STACK=staging RELAY_VERSION=<git-sha> REUSE_STACK=1

# Teardown after investigation complete
make e2e-teardown STACK=staging

# Production (explicit opt-in required)
make e2e-deployed STACK=production RELAY_VERSION=<git-sha>
# Note: e2e-teardown refuses to destroy production stack
```

## Migration Plan

1. `infra/stack_outputs.py` implemented and unit-tested (`infra/test_stack_outputs.py`).
2. `infra/inventory_gen.py` updated to import from `stack_outputs.py`.
3. `tests/e2e-deployed.sh` implemented: TCP preflight, warmup wait, 10+ HTTP assertion
   blocks ported from `compose-test.sh` with live ports (8090/8091) and dynamic relay IDs.
4. `ansible/playbooks/e2e-verify.yml` implemented: `systemctl`/`bpftool`/`lsmod`/`ss`/
   `journalctl` checks per relay node and backend service.
5. `relay-sdk/src/bin/relay_sdk_smoke.rs` extended: Group 4 UDP E2E block, group tags
   on all output lines, final JSON summary line.
6. `Makefile` targets `e2e-deployed` and `e2e-teardown` added.
7. This ADR written.

