# Session Summary: relay-bench integration with server-backend

**Date:** 2026-05-22<br>
**Duration:** ~1 session (~10 interactions)<br>
**Focus Area:** relay-bench - integrate server-backend matchmaking flow into bench_client and bench_server<br>

## Objectives

- [x] Analyse current relay-bench flow (bench_client, bench_server) and identify direct relay-backend admin calls
- [x] Analyse server-backend API (POST /sessions, POST /sessions/{id}/refresh, POST /servers, webhook /notify_session)
- [x] Design server-backend integration plan for relay-bench (bench_client + bench_server)
- [x] Decide whether to keep relay-bench or replace with a standalone game-client
- [x] Plan infra (Pulumi) changes for server-backend port + bench webhook access
- [x] Plan Ansible role and deploy playbooks for server-backend
- [x] Implement relay-bench changes (completed 2026-05-23)
- [ ] Implement Pulumi infra changes (planned - not yet started)
- [ ] Implement Ansible role + deploy changes (planned - not yet started)

## Work Completed

### Current Flow Analysis

`bench_client` relay mode today:
1. Reads `RELAY_CHAIN` / `RELAY_ADDR` + `BACKEND_ADMIN` env vars (manual relay selection).
2. Calls relay-backend admin `GET /bench_token?relay_chain=...&bench_server_addr=...` directly.
3. Calls bench_server `POST /register_session` directly with session keys + relay address.
4. Builds token array and calls `relay_sdk::Client::route_update`.
5. Background refresh task repeats steps 2-3 every 10 s.

Problems with the current flow:
- Relay chain is configured manually - does not exercise `select_chain()` geo-scoring logic.
- bench_client acts as its own matchmaker, bypassing the real matchmaking path.
- server-backend already implements the full matchmaking flow; bench should use it.

### server-backend API Mapping

Full session lifecycle via server-backend:

| Current bench_client call | Replacement |
|---|---|
| `GET /bench_token` (relay-backend admin) | `POST /sessions` (server-backend) |
| `POST /register_session` (bench_server) | webhook `POST /notify_session` called by server-backend automatically |
| Refresh: `GET /bench_token` + `POST /register_session` | `POST /sessions/{id}/refresh` (server-backend) |
| `RELAY_CHAIN` / `RELAY_ADDR` env vars | `relay_chain` field in `SessionResponse` (auto-selected by Haversine scoring) |

`SessionResponse` fields are a superset of the current `BenchTokenResponse` + relay_chain:
`session_id`, `session_version`, `session_private_key`, `relay_secret_key`, `client_route_token`,
`relay_chain_tokens`, `relay_chain`, `server_udp_addr`, `current_magic`, `ping_key`, `client_public_address`.

### Decision: Keep relay-bench (do not replace with game-client)

Considered replacing relay-bench `bench_client` with a lightweight game-client that only
exercises the matchmaking flow. Rejected because:
- `bench_client` is the only tool that measures end-to-end UDP RTT (p50/p95/p99) + packet loss under load.
- `bench_server` uses `relay-sdk::Server`, the real server SDK - valuable coverage that a simple client cannot replicate.
- The problem is the matchmaking path, not the load testing. Fix the matchmaking, keep the load test.

A lightweight integration-test client (if needed) belongs in `relay-sdk/examples/`, not as a bench_client replacement.

### relay-bench Changes Planned

**bench_server (`relay-bench/src/bin/bench_server.rs`)**:

1. Add `POST /notify_session` handler - receives webhook from server-backend.
   Body matches `WebhookPayload` from `server-backend/src/handlers.rs`:
   `{ session_id, session_version, session_private_key_hex, relay_address, ping_key_hex, current_magic_hex }`.
   Internally routes to the same `install_pinger` + `install_responder` + `ServerInner.register_session` logic
   as the existing `register_session_handler`. Keep `POST /register_session` for direct mode backward compat.

2. Add env var `SERVER_BACKEND_URL` (default: empty/disabled). If set, bench_server calls
   `POST /servers` at startup with `{ udp_addr, lat, lng, callback_url, callback_url }`:
   - `SERVER_LAT` / `SERVER_LNG` env vars (geo coords for chain selection).
   - `SERVER_CALLBACK_URL` = `http://<bench_server_host>:BENCH_HTTP_PORT` (must be reachable by server-backend).
   - Stores returned `server_id` (UUID) in `BenchState` for use by bench_client env.
   - Optionally calls `DELETE /servers/{id}` on graceful shutdown.

**bench_client (`relay-bench/src/bin/bench_client.rs`)**:

3. Add `BenchMode::ServerBackend` variant, activated by `BENCH_MODE=server-backend`.
   New env vars:
   - `SERVER_BACKEND_URL` - base URL of server-backend (e.g. `http://1.2.3.4:8180`)
   - `SERVER_ID` - UUID of the registered game server
   - `CLIENT_LAT`, `CLIENT_LNG` - client geo coordinates for chain selection
   Replaced env vars (`BACKEND_ADMIN`, `RELAY_CHAIN`, `RELAY_ADDR` no longer needed in this mode).

4. Initial session create: `POST /sessions` with `{ server_id, client_lat, client_lng }`.
   Parse `SessionResponse` - relay_chain comes from response (no manual `RELAY_CHAIN` needed).
   Do NOT call `POST /register_session` on bench_server - server-backend already called the webhook.

5. Route refresh (every `ROUTE_REFRESH_INTERVAL_SECS = 10`): call `POST /sessions/{session_id}/refresh`
   with `{ client_lat, client_lng }`. Parse `SessionResponse` - server-backend called webhook into
   bench_server automatically. Replace `do_refresh()` with `do_refresh_via_server_backend()`.
   Store `session_id` from initial create to use in refresh URL.

6. All relay-mode `BenchMode::Relay` paths unchanged - backward compat preserved.

**relay-bench/Cargo.toml**:

7. Add `reqwest = { version = "1", features = ["json", "blocking"] }` for server-backend HTTP calls
   in `BenchMode::ServerBackend`. Keep existing raw TCP HTTP helpers for direct mode and legacy relay mode.

### Infra (Pulumi) Changes Planned

**`infra/network.py`**:

8. Add ingress rule TCP 8180 to `sg_backend` from `0.0.0.0/0` - server-backend public matchmaking port,
   same model as TCP 8090 for relay-backend. Game clients reach this from anywhere.

9. Update ingress on `sg_bench` TCP 18080: add a second rule from `vpc_cidr` in addition to
   the existing `admin_cidr` rule. Required because server-backend (backend node, private IP in
   `BACKEND_CIDR = 10.10.0.0/16`) calls `POST /notify_session` webhook into bench_server after
   `POST /sessions`. Both bench_node and backend_node are co-located in `backend_net` (same VPC),
   so the webhook travels over the private network using bench_node's private IP as `SERVER_CALLBACK_URL`.

**`infra/__main__.py`**:

10. Add `pulumi.export("server_backend_url", backend.public_ip.apply(lambda ip: f"http://{ip}:8180"))`.
    Consumed by `stack_outputs.py` and the bench deploy workflow so bench_client knows `SERVER_BACKEND_URL`.

### Ansible Changes Planned

**New role `ansible/roles/server-backend/`**:

11. `tasks/main.yml` - mirrors `relay-backend` role: download binary from `artifact_base_url`,
    deploy `server-backend.env`, deploy and enable systemd unit, flush_handlers, healthcheck
    `GET http://127.0.0.1:{{ server_backend_http_port }}/health`.

12. `templates/server-backend.service.j2` - systemd unit.
    `After=network.target relay-backend.service` (relay-backend must be ready before server-backend
    starts polling `/route_matrix`). Security hardening identical to relay-backend.service.j2.

13. `templates/server-backend.env.j2`:
    ```
    HTTP_PORT={{ server_backend_http_port }}
    RELAY_BACKEND_ADMIN_URL=http://127.0.0.1:{{ backend_admin_http_port }}
    POLL_INTERVAL_MS={{ server_backend_poll_interval_ms | default(1000) }}
    WEBHOOK_TIMEOUT_MS={{ server_backend_webhook_timeout_ms | default(3000) }}
    ```

14. `handlers/main.yml` - reload systemd + restart server-backend.

**`ansible/playbooks/site.yml`**:

15. Add play `server-backend - backend servers` after the relay-backend play.
    `hosts: backend_servers`, roles: `[server-backend]`.

**`ansible/playbooks/group_vars/all.yml`**:

16. Add `server_backend_http_port: 8180`.

**`ansible/playbooks/bench-deploy.yml`**:

17. Add env vars to bench-server systemd unit inline template:
    - `SERVER_BACKEND_URL=http://{{ hostvars[inventory_hostname].private_ip | default('') }}:{{ server_backend_http_port }}`
      (uses backend node private IP - same VPC).
      Alternatively: env var set to the `server_backend_url` stack output value passed via `-e`.
    - `SERVER_LAT={{ bench_server_lat }}` / `SERVER_LNG={{ bench_server_lng }}`
      (add defaults in group_vars/staging: coords for us-east-1, e.g. lat=39.0 lng=-77.5).
    - `SERVER_CALLBACK_URL=http://{{ hostvars[inventory_hostname].ansible_host }}:{{ bench_http_port }}`
      (bench_node public EIP - server-backend is on backend_node, different instance, needs EIP even in same VPC
      unless internal DNS is set up; use EIP for simplicity).

**New playbook `ansible/playbooks/bench-server-backend-deploy.yml`**:

18. Mirrors `bench-backend-deploy.yml`: copy `target/release/server-backend`, restart `server-backend`
    systemd service, verify healthcheck `GET /health`. Used for rapid iteration without full `site.yml`.

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Keep relay-bench, do not replace with game-client | bench_client is the only RTT/loss measurement tool; bench_server exercises relay-sdk::Server. The problem is the matchmaking path, not the load testing. | N/A |
| Add `BenchMode::ServerBackend` as opt-in, keep `BenchMode::Relay` | Backward compat - existing relay+RELAY_CHAIN setups and CI docker-compose tests continue to work unchanged. | N/A |
| Co-locate server-backend on existing backend EC2 instance | server-backend is lightweight (HTTP + in-memory HashMap). No new instance or EIP needed for staging. Separate instance is a future option if load increases. | N/A |
| bench_server `SERVER_CALLBACK_URL` uses EIP, not private IP | server-backend is on backend_node; bench_server is on bench_node. Different instances - even in same VPC, using EIP avoids needing internal DNS and keeps the callback_url setup explicit. sg_bench TCP 18080 must also allow from vpc_cidr. | N/A |
| `After=relay-backend.service` in server-backend systemd unit | server-backend polls `/route_matrix` immediately after start. If relay-backend is not yet up, the first poll fails and server-backend logs a warning. Dependency ensures correct startup order. | N/A |

## Tests Added/Modified


| File | Test | Type | Status |
|------|------|------|--------|
| `relay-bench/src/bin/bench_client.rs` | `BenchMode::ServerBackend` parse + env read | Unit | Planned |
| `relay-bench/src/bin/bench_server.rs` | `POST /notify_session` handler (valid + invalid body) | Unit | Planned |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| `sg_bench` TCP 18080 only allows `admin_cidr` - server-backend on backend node cannot call webhook | Add second ingress rule from `vpc_cidr` to `sg_bench` TCP 18080 (both are in `backend_net` VPC) | No |
| bench_server needs a stable `SERVER_CALLBACK_URL` for server-backend webhook | Use bench_node EIP (exported from Pulumi); inject via Ansible `-e server_backend_url=...` at bench-deploy time | No |
| `insert_edit_into_file` produced duplicate `BenchState` struct in bench_server.rs | Rewrote file completely via shell; all duplicates removed | No |

## Implementation Notes (2026-05-23)

### bench_server.rs - key decisions

- `server_public_addr: Option<String>` stored in `BenchState` at startup from `SERVER_PUBLIC_ADDR` env var.
  `notify_session_handler` uses this as the `server_public_address` argument to `install_pinger` /
  `install_responder`. If not set, session is registered (SDK crypto works) but pinger/responder are
  skipped with a log warning - relay will not whitelist bench_server.
- `POST /servers` registration is best-effort: failure logs a warning but does not abort startup.
  bench_server remains reachable for direct/relay mode even if server-backend is down.
- Graceful shutdown uses `axum::serve(...).with_graceful_shutdown(...)` + `ctrl_c()` signal.
  Network thread shutdown is signaled via the existing `AtomicBool` inside the same closure.
- reqwest version `0.12` selected to match `server-backend/Cargo.toml`.

### bench_client.rs - key decisions

- `BenchMode::ServerBackend` flow is structurally identical to `BenchMode::Relay` after session creation:
  same `setup_relay_route`, same pinger, same network thread. Only session lifecycle differs.
- `create_session_via_sb` and `do_refresh_via_sb` use `reqwest::blocking` called via `spawn_blocking`
  to match the existing `do_refresh` pattern (blocking I/O off the async runtime).
- `do_refresh_via_sb` validates `relay_chain_tokens` is non-empty (server-backend always fills it;
  the legacy `wire_route_token` fallback from relay mode does not apply here).
- Both `refresh_cfg` (relay mode) and `sb_refresh_cfg` (server-backend mode) can be `Some` only in
  their respective modes - the two tasks are never spawned simultaneously.

## Next Steps

1. ~~**High:** Implement `bench_server` changes - add `POST /notify_session` handler + `POST /servers` self-registration at startup~~ **Done 2026-05-23**
2. ~~**High:** Implement `bench_client` changes - add `BenchMode::ServerBackend` with `do_refresh_via_server_backend()`~~ **Done 2026-05-23**
3. ~~**High:** Update `relay-bench/Cargo.toml` - add `reqwest` dep~~ **Done 2026-05-23**
4. ~~**High:** Run CI checks: `cargo fmt --all` -> `cargo clippy --workspace --lib --bins -- -D warnings` -> `cargo test --workspace`~~ **Done 2026-05-23 - all pass, zero warnings**
5. **High:** Implement Pulumi infra changes - TCP 8180 on `sg_backend`, TCP 18080 from `vpc_cidr` on `sg_bench`, export `server_backend_url`
6. **High:** Implement Ansible role `server-backend` (tasks, templates, handlers)
7. **High:** Update `site.yml` + `group_vars/all.yml` + `bench-deploy.yml`
8. **Medium:** Add `bench-server-backend-deploy.yml` playbook
9. **Low:** Update `README.md` bench section with new `BENCH_MODE=server-backend` usage example

## Files Changed

| Status | File |
|--------|------|
| Done | `relay-bench/src/bin/bench_client.rs` |
| Done | `relay-bench/src/bin/bench_server.rs` |
| Done | `relay-bench/Cargo.toml` |
| Planned | `infra/network.py` |
| Planned | `infra/__main__.py` |
| Planned | `ansible/roles/server-backend/tasks/main.yml` |
| Planned | `ansible/roles/server-backend/templates/server-backend.service.j2` |
| Planned | `ansible/roles/server-backend/templates/server-backend.env.j2` |
| Planned | `ansible/roles/server-backend/handlers/main.yml` |
| Planned | `ansible/playbooks/site.yml` |
| Planned | `ansible/playbooks/group_vars/all.yml` |
| Planned | `ansible/playbooks/bench-deploy.yml` |
| Planned | `ansible/playbooks/bench-server-backend-deploy.yml` (new) |

