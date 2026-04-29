# Session Summary: Docker Compose Integration Test Suite

**Date:** 2026-04-05<br>
**Duration:** ~1 hour<br>
**Focus Area:** Operational readiness - multi-process integration testing<br>

## Objectives

- [x] Evaluate Docker's role in CI/CD for this project (eBPF + kernel module constraints)
- [x] Design Docker Compose test topology with `RELAY_NO_BPF=1` userspace-only relays
- [x] Define test fixture data (relay JSON, crypto keypairs)
- [x] Define test assertions covering relay registration, ping, cost matrix, metrics
- [x] Produce implementation plan with file-level detail

## Work Completed

### Analysis: Docker for eBPF Projects

- `relay-backend`: Docker fully viable (pure Rust web service, no kernel deps)
- `relay-xdp`: Docker **deployment** limited (`--privileged --net=host` + host kernel module required), but Docker **CI build** and `RELAY_NO_BPF=1` testing are valuable
- Kernel module (`relay_module.ko`): cannot containerize (must match host kernel)

### Docker Compose Test Design

Designed a 5-service topology on a Docker bridge network with static IPs:

```
relay-test-net (172.28.0.0/16)
  redis       (172.28.0.2)   - Redis 7 for leader election + data storage
  backend     (172.28.0.3)   - relay-backend, HTTP port 80
  relay-a     (172.28.0.10)  - relay-xdp, RELAY_NO_BPF=1, UDP 40000
  relay-b     (172.28.0.11)  - relay-xdp, RELAY_NO_BPF=1, UDP 40000
  relay-c     (172.28.0.12)  - relay-xdp, RELAY_NO_BPF=1, UDP 40000
```

Static IPs required because `platform::parse_address()` expects `ip:port` format - Docker DNS hostnames are not supported.

Each relay container has its own network namespace, so all three can bind UDP port 40000 without conflict.

### Test Coverage Gap Analysis

Identified what compose tests cover that in-process tests do not:

| Gap | Example |
|-----|---------|
| Real HTTP over TCP | `ureq` client (relay) -> TCP -> `axum` server (backend) |
| Real UDP across namespaces | Ping packets through Docker bridge (~0.1ms latency) |
| Real Redis | Leader election race conditions with multiple backend instances |
| Process lifecycle | Signal handling, startup ordering, clean shutdown |
| Env var configuration | Missing/malformed env vars only caught at runtime |

### Implementation Plan

7 deliverables identified:

1. **Test fixture JSON** (`tests/fixtures/test-relays.json`) - 3 relays with X25519 keypairs, distinct datacenter IDs
2. **Key generation script** (`tests/gen-test-keys.sh`) - deterministic test keypairs for relay + backend
3. **`Dockerfile.nobpf`** (`relay-xdp/Dockerfile.nobpf`) - 2-stage build skipping eBPF nightly stage (~3min vs ~15min)
4. **`docker-compose.test.yml`** - 5 services, bridge network, static IPs, health checks
5. **Test runner script** (`tests/compose-test.sh`) - build, wait, assert, teardown
6. **CI job** (`.github/workflows/rust.yml`) - `compose-test` job after Docker image builds
7. **Session doc** (`docs/sessions/2026-04-05-compose-integration-test-plan.md`) - this file

### Test Runner Assertions

| # | Endpoint | Assertion | Validates |
|---|----------|-----------|-----------|
| 1 | `GET /health` | HTTP 200 | Backend alive |
| 2 | `GET /ready` | HTTP 200 | Leader election + delay complete |
| 3 | `GET /active_relays` | Contains `relay-a`, `relay-b`, `relay-c` | Relay -> backend HTTP + crypto |
| 4 | `GET /relays` | 3 "online" rows in CSV | RelayManager state aggregation |
| 5 | `GET /cost_matrix` | Response body length > 0 | Cost pipeline produces output |
| 6 | `GET /costs` | At least one value < 255 | Relay-to-relay UDP ping works |
| 7 | `GET /route_matrix` | Response body length > 0 | Optimizer produces routes |
| 8 | `GET /metrics` | Contains `relay_counter` lines | Prometheus counter propagation |
| 9 | `GET /relay_counters/relay-a` | HTTP 200 | Per-relay counter HTML endpoint |

### Data Flow Under Test

```
relay-a main_thread (1 Hz):
  POST /relay_update (encrypted SalsaBox) -> backend
  <- response: peer list [relay-b, relay-c], magic bytes, ping key

relay-a ping_thread (10 Hz):
  UDP ping -> relay-b:40000, relay-c:40000
  <- UDP pong (RTT measured)
  -> stats via IPC queue to main_thread
  -> next POST /relay_update includes RTT samples

backend update_route_matrix (1 Hz):
  RelayManager.get_costs() -> cost matrix
  optimizer::optimize2() -> route entries (direct + indirect)
  store cost_matrix, route_matrix -> Redis
  load from Redis leader instance -> shared state
```

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Use `RELAY_NO_BPF=1` mode, not full XDP | XDP needs `--privileged --net=host` + kernel module - breaks multi-container topology | [ADR-001](../decisions/ADR-001-compose-nobpf.md) |
| Static IPs instead of Docker DNS | `platform::parse_address()` requires `ip:port` format, no hostname resolution | N/A |
| Separate `Dockerfile.nobpf` | eBPF nightly stage wastes ~12min when `RELAY_NO_BPF=1` never loads `.o` file | N/A |
| Encrypted mode (not plaintext) | Validates full `relay-xdp encrypt -> backend decrypt` path over real HTTP | N/A |
| `INITIAL_DELAY=0` in compose | Default 15s delay unnecessary in test; speeds up test execution | N/A |
| Sleep ~10s before assertions | Relays need ~3-5 update cycles for RTT data; backend needs cost matrix computation | N/A |

## Tests Added/Modified

No code changes in this planning session. Expected deliverables:

| Test Class | Method | Type | Status |
|------------|--------|------|--------|
| `compose-test.sh` | 9 curl assertions | Integration (Docker) | Planned |
| `docker-compose.test.yml` | 5-service topology | Infrastructure | Planned |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| `parse_address()` rejects hostnames | Use static IPs on Docker bridge network | No |
| Full Dockerfile builds eBPF for 15min | Create `Dockerfile.nobpf` (2-stage, ~3min) | No |
| Relay port conflict if `--net=host` | Docker bridge gives each container its own namespace - no conflict on port 40000 | No |

## Next Steps

1. ~~**High:** Generate test X25519 keypairs and create `tests/fixtures/test-relays.json`~~ DONE
2. ~~**High:** Create `relay-xdp/Dockerfile.nobpf` (2-stage, no eBPF)~~ DONE
3. ~~**High:** Create `docker-compose.test.yml` with 5 services + static IPs~~ DONE
4. ~~**High:** Create `tests/compose-test.sh` with 9 assertions~~ DONE
5. ~~**Medium:** Add `compose-test` job to `.github/workflows/rust.yml`~~ DONE
6. **Low:** Consider adding a second backend instance to test Redis leader election failover

## Files Changed

| Status | File |
|--------|------|
| A | `docs/sessions/2026-04-05-compose-integration-test-plan.md` - this session summary |
| A | `tests/fixtures/test-relays.json` - 3 test relays with X25519 public keys |
| A | `tests/gen-test-keys.sh` - documents deterministic test keypair derivation |
| A | `tests/compose-test.sh` - test runner with 9 curl assertions |
| A | `relay-xdp/Dockerfile.nobpf` - 2-stage build (no eBPF nightly) |
| A | `docker-compose.test.yml` - 5-service topology with static IPs |
| M | `relay-backend/Dockerfile` - added curl to runtime for healthcheck |
| M | `.github/workflows/rust.yml` - added compose-test job |

