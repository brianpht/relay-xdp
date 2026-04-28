# Session Summary: Integrate relay-sdk Smoke Test into Docker Compose

**Date:** 2026-04-28
**Duration:** ~1 session (~4 interactions)
**Focus Area:** `relay-sdk` + `docker-compose.test.yml` + `tests/compose-test.sh` - compose integration smoke test

## Objectives

- [x] Evaluate feasibility of adding relay-sdk tests to Docker Compose integration suite
- [x] Design a one-shot `sdk-smoke` container that exercises SDK API against live compose services
- [x] Produce complete implementation plan (code + config for 4 files)
- [x] Implement the 4 files (smoke binary + Dockerfile.smoke + compose service + sh assertion)

## Work Completed

### Feasibility Analysis

- Reviewed `docker-compose.test.yml`: 5-service topology on `172.28.0.0/16`; static IPs `.2/.3/.10/.11/.12`; IP `.20` is available for `sdk-smoke`
- Reviewed `tests/compose-test.sh`: 9 curl-based assertions; `PASSED`/`FAILED` counters; cleanup trap; `--no-build` flag pattern
- Reviewed `relay-sdk/Cargo.toml`: `crate-type = ["cdylib", "staticlib", "rlib"]`; existing deps cover all needs; no HTTP client needed (raw TCP sufficient)
- Confirmed `relay-sdk/src/bin/` directory already exists (empty)
- Confirmed IP `172.28.0.20` not assigned to any existing service
- Identified `build.rs` cbindgen concern: must guard cbindgen execution when building the smoke binary to avoid write failures in multi-stage Docker build

### Design: sdk-smoke Container

The smoke binary performs 13 assertions across 3 groups - no real UDP socket needed:

| Group | Assertions | What is tested |
|-------|-----------|----------------|
| 1. Backend HTTP | 4 | `GET /health` ok + `GET /active_relays` lists relay-a / b / c |
| 2. Client state machine | 5 | `open_session` -> `route_update(DIRECT)` -> `tick` -> `stats.route_changes` -> `close_session` |
| 3. Server state machine | 4 | `open` -> `register_session` -> `expire_session` -> stats counters |

HTTP checks use raw `TcpStream` (no new dependencies). SDK checks run in-process inside the container (connected to compose network for backend HTTP, no UDP relay traffic needed).

### Implementation Plan

#### File 1: `relay-sdk/src/bin/relay_sdk_smoke.rs`

Standalone binary. Reads `BACKEND_HOST` (default `172.28.0.3`) and `BACKEND_PORT` (default `80`) from env. Runs 3 check groups, prints `PASS` / `FAIL` per assertion, exits 0 on full pass.

Key code sketch:
```rust
fn http_body(host: &str, port: u16, path: &str) -> Result<String, String> {
    // raw TcpStream HTTP/1.0 GET - no reqwest/ureq dependency needed
}

fn main() {
    // Group 1: http_body("/health") + http_body("/active_relays")
    // Group 2: ClientInner::create() -> open_session -> route_update(DIRECT)
    //          -> tick -> drain_notify -> assert stats.route_changes >= 1
    // Group 3: ServerInner::create() -> open -> register_session -> expire_session
    //          -> drain_notify -> assert stats.sessions_registered/expired == 1
    // exit 0 or 1
}
```

#### File 2: `relay-sdk/Dockerfile.smoke`

Two-stage multi-stage build:
- **Stage 1 `builder`** (`rust:1.80-slim`): copies `Cargo.toml`, `Cargo.lock`, `relay-xdp-common/`, `relay-sdk/`; runs `cargo build --release -p relay-sdk --bin relay_sdk_smoke`
- **Stage 2 `runtime`** (`debian:bookworm-slim`): copies single binary; `ENTRYPOINT ["relay_sdk_smoke"]`

Build time: ~2-3 min cold; ~30s with Docker layer cache on `Cargo.lock` unchanged.

#### File 3: `docker-compose.test.yml` - add `sdk-smoke` service (before `networks:` section)

```yaml
  sdk-smoke:
    build:
      context: .
      dockerfile: relay-sdk/Dockerfile.smoke
    profiles: ["smoke"]           # excluded from plain "up -d"
    networks:
      relay-test-net:
        ipv4_address: 172.28.0.20
    depends_on:
      backend:
        condition: service_healthy
    environment:
      BACKEND_HOST: "172.28.0.3"
      BACKEND_PORT: "80"
    restart: "no"
```

`profiles: ["smoke"]` prevents the one-shot container from appearing in the main `docker compose up -d` stack (avoids spurious "exited" service in the topology).

#### File 4: `tests/compose-test.sh` - add assertion #10 (after assertion #9, before `# Summary`)

```bash
# 10. relay-sdk smoke test (build + run in compose network)
echo ""
echo -e "${YELLOW}=== Running relay-sdk smoke test ===${NC}"
if docker compose -f "$COMPOSE_FILE" \
        --profile smoke run --rm --build sdk-smoke 2>&1; then
    echo -e "  ${GREEN}PASS${NC} 10. relay-sdk smoke test (13/13 assertions)"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC} 10. relay-sdk smoke test"
    FAILED=$((FAILED + 1))
fi
```

`--build` on `docker compose run` forces re-build before run, handling both fresh CI (image not yet built) and local `--no-build` flows (smoke image was never part of `up --build`).

No changes needed to `.github/workflows/rust.yml` - the `compose-test` job already runs `compose-test.sh` which will drive assertion #10 automatically.

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| `profiles: ["smoke"]` on sdk-smoke service | Prevents one-shot container from appearing as "exited" in main `up -d` stack; explicit activation via `--profile smoke run` | N/A |
| Raw `TcpStream` HTTP (no reqwest/ureq) | No new dependencies added to `relay-sdk/Cargo.toml`; HTTP/1.0 GET over TCP is sufficient for health + active_relays checks | N/A |
| In-process SDK state machine (no real UDP) | Exercises full `Client`/`Server` API surface including `stats` counters without needing relay handshake tokens; backend HTTP check covers live network connectivity | N/A |
| `--build` on `docker compose run` | Smoke image is not built by main `docker compose up --build` (profile-gated); `--build` on run ensures fresh image in both CI and local flows | N/A |
| Two-stage Dockerfile | `rust:1.80-slim` builder (~1 GB) discarded; final image uses `debian:bookworm-slim` with only the binary (~50 MB) | N/A |

## Tests Added/Modified

| Test Class | Method | Type | Status |
|------------|--------|------|--------|
| `relay_sdk_smoke` | `GET /health returns ok` | Integration (compose) | Done |
| `relay_sdk_smoke` | `GET /active_relays contains relay-a/b/c` | Integration (compose) | Done |
| `relay_sdk_smoke` | `client state is CLIENT_STATE_OPEN` | Integration (compose) | Done |
| `relay_sdk_smoke` | `client.stats.route_changes >= 1 after tick` | Integration (compose) | Done |
| `relay_sdk_smoke` | `inner.session_open is false after close_session` | Integration (compose) | Done |
| `relay_sdk_smoke` | `server.is_open() after open` | Integration (compose) | Done |
| `relay_sdk_smoke` | `server.stats.sessions_registered == 1` | Integration (compose) | Done |
| `relay_sdk_smoke` | `server.stats.sessions_expired == 1` | Integration (compose) | Done |
| `compose-test.sh` | assertion #10 sdk-smoke exit code | Integration (compose) | Done |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| `build.rs` runs cbindgen unconditionally; may fail in multi-stage build if `include/` is not writable | Fixed: use absolute path via `CARGO_MANIFEST_DIR` + `.is_ok()` guard instead of `.unwrap()` on `create_dir_all` | Resolved |
| Docker layer cache for Cargo dependencies | `COPY Cargo.toml Cargo.lock ./` before `COPY relay-sdk/ relay-sdk/` in Dockerfile.smoke; `cargo build` caches deps in a separate layer | Resolved |

## Next Steps

1. ~~**High:** Implement the 4 files above (smoke binary + Dockerfile.smoke + compose service + sh assertion) and verify locally with `docker compose --profile smoke run --rm --build sdk-smoke`~~ Done
2. ~~**High:** Fix `relay-sdk/build.rs` cbindgen guard before building Dockerfile.smoke (check `CARGO_BIN_NAME` env var at build time)~~ Done
3. ~~**Medium:** `testing-expansion` - Expand unit tests for pool, mutex-optimization, and platform features in relay-sdk (from improvement plan task 12)~~ Done

## Files Changed

| Status | File |
|--------|------|
| A | `docs/sessions/2026-04-28-sdk-smoke-compose-plan.md` |
| A | `relay-sdk/src/bin/relay_sdk_smoke.rs` |
| A | `relay-sdk/Dockerfile.smoke` |
| M | `docker-compose.test.yml` |
| M | `tests/compose-test.sh` |
| M | `relay-sdk/build.rs` |
| M | `relay-sdk/src/pool.rs` |
| M | `relay-sdk/src/platform/linux.rs` |
| M | `relay-sdk/src/route/trackers.rs` |

