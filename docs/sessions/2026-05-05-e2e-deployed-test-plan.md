# Session Summary: E2E Deployed Test Flow Plan

**Date:** 2026-05-05<br>
**Duration:** ~3 interactions<br>
**Focus Area:** infra / testing - full workflow E2E after Pulumi provisioning<br>

## Objectives

- [x] Analyse codebase: existing test layers (compose-test, relay_sdk_smoke, Ansible verify)
- [x] Identify gaps between local Docker Compose tests and a live deployed stack
- [x] Produce a concrete, file-level implementation plan for post-provisioning E2E
- [ ] Implement and merge the plan (follow-on work)

## Work Completed

### Codebase Analysis

Reviewed the following artefacts to understand current test coverage and data-flow:

| Artefact | Purpose |
|----------|---------|
| `tests/compose-test.sh` | 10 HTTP assertions against local Compose topology (5 services, fixed IPs 172.28.0.x) |
| `relay-sdk/src/bin/relay_sdk_smoke.rs` | 13 assertions: backend HTTP (groups 1-2) + SDK client/server state (groups 3-4); invoked by `sdk-smoke` Compose profile |
| `relay-backend/tests/` | Unit + integration tests (wire format, optimizer, HTTP handlers) - no live-infra dependency |
| `ansible/playbooks/site.yml` | Full deploy ordering: common -> redis -> relay-backend -> kernel-module -> relay-xdp (serial 1) |
| `ansible/README.md` | Documents per-relay verify steps (systemctl, bpftool, lsmod, journal) but no automated playbook for them |
| `infra/__main__.py` | Pulumi stack: 3x RelayNode + 1x BackendNode; exports `relay_nodes` dict + `backend` |
| `infra/inventory_gen.py` | Parses `pulumi stack output --json` and renders `ansible/inventory/<stack>.yml` |
| `infra/network.py` | SG rules: relay UDP/40000 open to 0.0.0.0/0; backend TCP/8090 public, TCP/8091 from `admin_cidr` only |

**Key gap identified:** No automated test harness runs against a live provisioned stack. All current tests use either hardcoded Compose IPs or pure in-memory simulations.

### Design Decisions Confirmed

| # | Topic | Decision |
|---|-------|---------|
| 1 | Test runner host | Developer laptop within `admin_cidr` (Option A) |
| 2 | Session key injection | Reuse existing `POST /relay_update` on `8090` (production parity, no test-only endpoint) |
| 3 | Failure cleanup policy | Leave stack alive on failure; separate `make e2e-teardown` for cleanup |
| 4 | Fast iteration shortcut | `--reuse-stack` flag skips `pulumi up` when outputs already have valid IPs |
| 5 | UDP/40000 SG | Already open to 0.0.0.0/0 in `infra/network.py` - no SG change needed |

## Plan: Files to Create / Modify

### Step 1 - `tests/e2e-deployed.sh` (new)

Shell script replacing `172.28.0.3` hardcoded addresses with live Pulumi outputs.

Responsibilities:
- Call `python infra/stack_outputs.py --stack ${STACK} --format env` -> exports `BACKEND_HOST`, `BACKEND_PORT=8090`, `ADMIN_BACKEND_PORT=8091`, `RELAY_PUBLIC_IPS`, `RELAY_IDS`
- TCP preflight on `${BACKEND_HOST}:8091` with 3-second timeout; fail fast with: `"Is your laptop IP still in admin_cidr?"` message
- 15-second warmup wait (mirrors `compose-test.sh` relay update cycle wait)
- Port all 10 assertion blocks from `tests/compose-test.sh` using the corrected `8090`/`8091` ports
- Assertion 9 (`/relay_counters/<id>`) loops over `${RELAY_IDS}` instead of hardcoding `relay-a`
- Port-separation 404 checks: `8090 -> /metrics`, `8091 -> /relay_update`
- Exit non-zero on any failure; stack stays alive

### Step 2 - `infra/stack_outputs.py` (new)

Small Python helper (factored from `inventory_gen.py` parsing logic) so both
inventory generation and the E2E script share one Pulumi JSON parser.

```
python infra/stack_outputs.py --stack staging --format env
# outputs:
# export BACKEND_HOST=1.2.3.4
# export BACKEND_PORT=8090
# export ADMIN_BACKEND_PORT=8091
# export RELAY_PUBLIC_IPS="10.x.x.x 10.y.y.y 10.z.z.z"
# export RELAY_IDS="relay-staging-1 relay-staging-2 relay-staging-3"
```

### Step 3 - `relay-sdk/src/bin/relay_sdk_smoke.rs` (modify)

Add Group 4 `udp_route_e2e`, gated by `RELAY_E2E_UDP=1`:

- Spawn `ServerInner` bound on ephemeral UDP port
- Register session via `POST ${BACKEND_HOST}:${BACKEND_PORT}/relay_update` (reuse `relay_sdk::route` helpers already imported by `server_example.rs`)
- 20-second poll on `GET ${ADMIN_BACKEND_PORT}/route_matrix` until body size > N bytes (all 3 relays converged)
- Drive `ClientInner` for N ticks across deployed relays
- Assert `stats.packets_sent_to_server > 0`, `stats.packets_received_from_server > 0`, payload echo equality
- Tag all output lines `[group=4]`; emit final JSON summary line for machine consumption
- Existing 13 assertions unaffected; new group visible only when `RELAY_E2E_UDP=1`

### Step 4 - `ansible/playbooks/e2e-verify.yml` (new)

Ansible playbook, runs on `relay_servers` after `site.yml`:

```yaml
- name: E2E relay node verification
  hosts: relay_servers
  tasks:
    - systemctl is-active relay-xdp
    - bpftool prog list | grep xdp        # BPF program loaded
    - lsmod | grep relay_module            # kernel module present
    - ss -lun 'sport = :40000'             # UDP socket bound
    - journalctl -u relay-xdp --since "5 min ago" --grep ERROR  # fail if errors found
```

No `ignore_errors`. Any failure stops the play before the HTTP/UDP assertions run.

### Step 5 - `Makefile` (modify)

Add two targets:

```makefile
e2e-deployed: STACK ?= staging
e2e-deployed:
    @# --reuse-stack: skip pulumi up if outputs already have valid IPs
    @if [ "$(REUSE_STACK)" != "1" ]; then \
        pulumi up --yes --stack $(STACK) --cwd infra; \
    fi
    python infra/inventory_gen.py --stack $(STACK)
    ansible-playbook -i ansible/inventory/$(STACK).yml \
        ansible/playbooks/site.yml -e relay_version=$(RELAY_VERSION)
    ansible-playbook -i ansible/inventory/$(STACK).yml \
        ansible/playbooks/e2e-verify.yml
    eval $$(python infra/stack_outputs.py --stack $(STACK) --format env) && \
        bash tests/e2e-deployed.sh
    eval $$(python infra/stack_outputs.py --stack $(STACK) --format env) && \
        RELAY_E2E_UDP=1 cargo run -p relay-sdk --bin relay_sdk_smoke

e2e-teardown: STACK ?= staging
e2e-teardown:
    @if [ "$(STACK)" = "production" ]; then \
        echo "ERROR: e2e-teardown refuses to destroy production stack."; exit 1; \
    fi
    pulumi destroy --yes --stack $(STACK) --cwd infra
```

### Step 6 - `docs/decisions/ADR-004-e2e-deployed-test-flow.md` (new)

Architectural Decision Record capturing:
- Scope: staging by default; production opt-in with explicit `STACK=production`
- Runner: developer laptop within `admin_cidr` (cost, simplicity)
- Why `/relay_update` over a test-only inject endpoint (production parity)
- Leave-up-on-failure rationale (forensic state preservation)
- `--reuse-stack` shortcut for fast iteration during development
- Operator runbook: `make e2e-deployed` -> inspect -> `make e2e-teardown`
- Future: nightly CI on GitHub Actions runner with stored AWS + vault creds (optional escalation path)

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Developer laptop as test runner | Covered by existing `admin_cidr` SG rule; zero extra infra cost | ADR-004 |
| Reuse `/relay_update` for session injection | Avoids test-only endpoint; tests same code path as production | ADR-004 |
| Leave stack alive on failure | Preserves relay logs, bpftool state, journalctl for root-cause analysis | ADR-004 |
| `--reuse-stack` shortcut | Skip 5-10 min `pulumi up` on fast iteration runs when infra unchanged | ADR-004 |
| `infra/stack_outputs.py` helper | Single Pulumi JSON parser shared between `inventory_gen.py` and E2E script | N/A |
| UDP/40000 unchanged | Already open to 0.0.0.0/0 in `infra/network.py` - no SG change needed | N/A |
| `route_matrix` convergence poll | Prevents Group 4 UDP test from running before all 3 relays are seen by backend | N/A |

## Tests Added/Modified

| File | Method / Assertion | Type | Status |
|------|--------------------|------|--------|
| `tests/e2e-deployed.sh` | 10+ HTTP assertions against live backend (8090/8091) | Integration | Planned |
| `tests/e2e-deployed.sh` | TCP preflight check on 8091 (admin_cidr gate) | Integration | Planned |
| `ansible/playbooks/e2e-verify.yml` | systemctl / bpftool / lsmod / ss / journalctl checks per relay + backend service + /health liveness | Operational | Done |
| `relay_sdk_smoke` Group 4 | UDP route E2E: ClientInner -> 3 relays -> ServerInner, stats + echo | E2E | Planned |
| `relay_sdk_smoke` Group 4 | `route_matrix` convergence poll before UDP test | E2E | Planned |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| Compose ports (80/81) differ from production SG ports (8090/8091) | Use real ports in e2e-deployed.sh; compose-test.sh unchanged | No |
| relay_ids hardcoded as relay-a/b/c in compose-test.sh | Derive from Pulumi output `relay_nodes` dict keys in e2e-deployed.sh | No |
| UDP path test needs converged route_matrix before running | 20-second poll on `/route_matrix` body size before Group 4 | No |
| relay_sdk_smoke 13-assertion summary grows in Group 4 | Tag `[group=4]` + final JSON line for machine parsing | No |

## Next Steps

1. ~~**High:** Implement `infra/stack_outputs.py` (foundation for all subsequent steps)~~ Done
2. ~~**High:** Implement `tests/e2e-deployed.sh` using stack_outputs.py env output~~ Done
3. ~~**High:** Add `ansible/playbooks/e2e-verify.yml`~~ Done
4. **High:** Add `e2e-deployed` + `e2e-teardown` targets to `Makefile`
5. **Medium:** Extend `relay-sdk/src/bin/relay_sdk_smoke.rs` with Group 4 UDP E2E
6. **Medium:** Write `docs/decisions/ADR-004-e2e-deployed-test-flow.md`
7. **Low:** Evaluate nightly CI escalation path (GitHub Actions runner + stored AWS/vault creds)

## Files Changed

| Status | File |
|--------|------|
| A | `docs/sessions/2026-05-05-e2e-deployed-test-plan.md` |
| A | `tests/e2e-deployed.sh` |
| A | `infra/stack_outputs.py` |
| A | `infra/test_stack_outputs.py` |
| M | `infra/inventory_gen.py` (import from stack_outputs) |
| A | `ansible/playbooks/e2e-verify.yml` |
| A (planned) | `docs/decisions/ADR-004-e2e-deployed-test-flow.md` |
| M (planned) | `Makefile` |
| M (planned) | `relay-sdk/src/bin/relay_sdk_smoke.rs` |

