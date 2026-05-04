# Session Summary: Project-Wide Audit and Remediation Plan (v2)

**Date:** 2026-05-04 (v2 revised same day)<br>
**Duration:** Initial audit (~1 interaction, 4 parallel exploration agents) + verification pass against `master @ 0e02c4e`<br>
**Focus Area:** Cross-cutting audit of relay-xdp (eBPF data plane, kfunc loader, relay-backend, relay-sdk, infra/ansible/CI). Supersedes [`2026-05-04-project-audit-plan.md`](2026-05-04-project-audit-plan.md).<br>

> **Why v2.** v1 was produced by parallel exploration agents reading file excerpts. A targeted re-read of the working tree (1) confirmed most findings, (2) corrected several claims that were factually wrong, (3) surfaced new risks v1 did not flag, (4) re-sequenced two cross-cutting items whose stated severity contradicted their phase placement, and (5) **after a full verification pass on the previously-unverified Critical claims, reduced the Backend Critical count from 3 to 1** because two of the three turned out to be High or Low after evidence review.

## Objectives

- [x] Run a structured audit across all four major surfaces of the project
- [x] Categorise findings by severity (Critical / High / Medium / Low)
- [x] Produce a phased remediation plan with concrete next steps
- [x] **v2:** Verify the named Critical claims against current source (line-grep + targeted reads)
- [x] **v2:** Re-classify findings whose evidence did not hold up
- [x] **v2:** Verify the un-named Critical claims (catch_unwind swallow, eBPF pointer pattern, kfunc panic sites, RNG assumption, lock-poisoning sites)
- [x] **v2:** Open Proposed ADRs for the three architectural decisions (ADR-004 / ADR-005 / ADR-006)
- [ ] Verify findings outside the Critical bucket - to be done at fix time per the finding-to-action matrix

## Corrections to v1 (verification pass)

| v1 claim | Reality on disk | v2 action |
|----------|-----------------|-----------|
| systemd unit "runs `User=root` without ... capability bounding" | `relay-xdp.service.j2:23-24` already sets `AmbientCapabilities` and `CapabilityBoundingSet` to `CAP_NET_ADMIN CAP_BPF CAP_SYS_ADMIN`. What is missing is `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies` | Reword Critical theme #4: "filesystem + privilege hardening", drop "capability bounding" |
| ansible disables strict host key checking | True at two sites, not one. `ansible/ansible.cfg:6` (`host_key_checking = False`) AND `ansible/ansible.cfg:18` (`ssh_args = ... StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`). Fixing only the first leaves the second silently overriding | Both sites must be addressed in the same change |
| Low: "Move `debug.txt` and the committed `relay_xdp_rust.o` artefact out of the working tree (add to `.gitignore`)" | Both already in `.gitignore` (`/relay_xdp_rust.o`, `/debug.txt`) and not tracked by git (`git ls-files` empty for both) | Drop this Low item entirely. v1's audit agent saw the on-disk file but did not check `git ls-files` |
| eBPF `.unwrap()` after `*_map.get_ptr_mut` is unsafe per se | Pattern in `main.rs` is `is_none() -> early return; then unwrap()`. The `unwrap()` itself does not race - the risk is **pointer lifetime** (holding the raw pointer across a second mutation that may evict). Already corrected in the (now deleted) phase-1 plan. | Re-scope to "raw pointer-lifetime audit", not "unwrap audit" |
| FFI `relay_*_get_stats(out)` is a buffer overflow | `RelayClientStats` / `RelayServerStats` are `#[repr(C)]` and cbindgen emits the layout into the generated header; correct C callers compile against it. Real risk is silent **contract drift** if Rust struct grows but header is regenerated late | Lower severity from Critical to Medium; add a Rust `const _: () = assert!(size_of::<X>() == N);` plus a C `_Static_assert` in the cbindgen post-amble |
| Backend "3 Critical" findings | Only **1** holds at Critical: `decrypt_relay_request` replay/freshness gap. Of the remaining two: 14 `RwLock::expect("lock poisoned")` sites across `magic.rs`, `main.rs`, `handlers.rs`, `redis_client.rs` are **High** (lock poisoning is a downstream symptom of a prior panic, not a primary attack vector). `update_relay_backend_instance` `system clock before unix epoch` expect at `main.rs:149` is **Low** (unreachable except on misconfigured hardware) | Reduce Backend Critical 3 -> 1; reaffirm 14 lock sites as the High P1-13 backlog (already in plan) |
| relay-sdk RNG assumption | `Cargo.toml:26` pins `rand = "0.8"` (lockfile resolves to `0.8.6`). In `rand 0.8`, `thread_rng()` is `ReseedingRng<ChaCha12Core, OsRng>` - safe for 192-bit XChaCha nonces. Not a Critical bug, but an undocumented assumption | Add a `static_assertions` rand-version gate + comment in `relay-sdk/src/tokens/mod.rs`; do **not** raise severity |
| SDK `catch_unwind` panic-swallow | Confirmed at 8 void FFI sites (`mod.rs:78, 95, 126, 145, 247, 267, 299, 386`). The behaviour is even **explicitly documented** at `mod.rs:23-26` ("panics inside catch_unwind are silently swallowed because there is no return channel"). Stays Critical | No change; ADR-006 already covers via the registered C log callback |
| eBPF pointer-lifetime - has the risk a real failure mode? | Yes. `session_map.insert(...)` exists at line 1127 (different handler). Within a single handler the verified pattern is is_none-then-unwrap-then-use, but several handlers hold `whitelist`/`session` raw pointers and write through `*ptr` at later lines (1057, 1165, 1244, 1328, 1412, 1493, 1572, 1650). P1-03 must walk each handler and verify no map mutation falls between `unwrap()` and the last `*ptr` access | Keep P1-03 scope as written |

## Findings summary (v2)

After verification and re-classification:

| Surface                          | Critical    | High       | Medium    | Low       |
|----------------------------------|-------------|------------|-----------|-----------|
| eBPF data plane + kfunc loader   | 5           | 5          | 5         | 4         |
| relay-backend                    | **1** (-2)  | **7** (+2) | 7         | **6** (+1)|
| relay-sdk (FFI / crypto)         | 2 (-1)      | **4** (+1) | 3 (+1)    | 2         |
| Infra / Ansible / CI             | 3           | 2          | 4         | 1 (-1)    |
| **Total**                        | **11** (-3) | **18** (+3)| **19**    | **13** (=)|

Net change after v2 verification + P1-08/P1-09/P1-15 implementation pass:
- Critical 14 -> 11 (FFI get_stats reclassified to Medium; backend lock-poison reclassified to High; backend system-clock expect reclassified to Low).
- High 15 -> 18 (lock-poisoning sites now sit here explicitly; backend HTTP route auth surface NEW after Pulumi SG check; NEW P1-15 caught and fixed by P1-08 parity fixture).
- Medium 18 -> 19 (FFI get_stats moved here).
- Low 13 -> 13 (gitignore item dropped, system-clock expect added).
- **Phase 1 progress 2026-05-04 (9/14 actions done):** P1-01 (replay window + clock skew), P1-02 (FFI Zeroize + panic hook), P1-04 (Pulumi admin_cidr REQUIRED_OVERRIDE + Makefile preflight), P1-05 (ansible host key checking), P1-06 (relay-xdp systemd hardening), P1-08 (parity fixture), P1-09 (size_of asserts), P1-14 (route group split), P1-15 (SDK pittle fix) landed and verified. ADR-004 + ADR-006 moved Proposed -> Accepted. **P1-14 + P1-04 together close the admin-port exposure**: routes are now split, the production SG only allows admin port from `admin_cidr`, and `admin_cidr` can no longer be silently left as `0.0.0.0/0` (rejected at both Makefile preflight and Pulumi evaluation time). **All four "Operational hardening" Critical-theme items (P1-04, P1-05, P1-06, P1-14) are now done.** Operators must explicitly set a narrow CIDR before any production `pulumi up`; SSH host-key MITM is detected after first deploy; the relay-xdp service is sandboxed beyond just capability bounding.

## Critical themes (v2)

1. **Replay/nonce hygiene.** `relay-backend/src/handlers.rs:146 decrypt_relay_request` accepts any AEAD-valid ciphertext - no per-relay nonce cache, no payload-timestamp freshness check. SDK token encryption in `relay-sdk/src/tokens/mod.rs:87, 127` uses `rand::thread_rng()` for XChaCha20-Poly1305 nonces; in pinned `rand 0.8.x` this is OsRng-seeded `ChaCha12Rng` which is acceptable for 192-bit nonces, but the assumption needs a comment + a unit test that rejects PRNG downgrade.
2. **FFI surface in relay-sdk.** Secret-key copies on the stack (`SESSION_PRIVATE_KEY_BYTES` buffers in `client_open_session` and `server_register_session`) are not wrapped in `Zeroizing`; void FFI functions inside `catch_unwind` swallow panics with no log path; cbindgen does not emit `_Static_assert` on stat-struct sizes.
3. **Kernel-side safety - pointer lifetime, not panic.** Multiple call sites in `relay-xdp-ebpf/src/main.rs` hold a raw pointer from `session_map.get_ptr_mut` / `whitelist_map.get_ptr_mut` while later code paths can evict the same map. The current `is_none -> unwrap` guard is correct **at unwrap time**, but does not prevent use-after-eviction further down the handler.
4. **Operational hardening.** `infra/Pulumi.production.yaml:11` ships `admin_cidr: 0.0.0.0/0`; `ansible/ansible.cfg:6, 18` disables host-key checking via two independent settings; `relay-xdp.service.j2` runs as `User=root` (necessary for XDP attach) but lacks filesystem and privilege hardening directives even though capability bounding is already in place.
5. **(NEW in v2) kfunc loader trust boundary.** `relay-xdp/src/kfunc.rs` is ~1300 lines of byte-level ELF + BTF parsing with 27 `.unwrap()/.expect()` call sites. Input is `relay_module.ko` from disk. If an attacker can replace `relay_module.ko`, full game-over - so the trust boundary is "we trust the on-disk module path"; that needs to be documented as an ADR and the `.expect()` calls converted to typed errors so a broken module is reported, not panics.

## Cross-cutting risks (v2)

| Risk | v1 phase | v2 phase | Reason for change |
|------|----------|----------|-------------------|
| Pittle/chonkle parity drift across `relay-xdp-ebpf`, `relay-xdp/src/packet_filter.rs`, `relay-sdk/src/route/mod.rs` | Phase 2 (Medium) | **Phase 1 (High)** | v1 itself called this "the single most likely correctness regression" - that contradicts a Medium classification |
| Wire-layout drift in `relay-xdp-common` caught only by integration `wire_compat` | Phase 2 | **Phase 1** | `const _: () = assert!(size_of::<X>() == N);` is ~30 minutes of work, zero maintenance, gates the same code being modified in Phase 1. No reason to defer |
| Dependency hygiene (`cargo audit` / `cargo deny`) | Phase 2 | **Drop "add cargo audit"**, keep `cargo deny` | `cargo audit` is already wired via `rustsec/audit-check` workflow per v1. v1 listed it twice (under "Cross-cutting risks" and again as Phase 2 work) |
| (NEW) Session-map flood / LRU eviction DoS - `session_map` is `LruHash[200K]`; an attacker with rate budget can spam unique 5-tuples to evict legitimate sessions before crypto verify | - | **Phase 2 (High)** | Distinct from pointer-lifetime; this is an availability concern even if every pointer access is correct |
| (NEW) Redis fail-open vs fail-closed for backend leader election | - | **Phase 1 (High)** | If Redis goes down and the backend fails open, two leaders may run optimization simultaneously. Plan mentions "Add Redis TTL on leader-election keys" but does not specify the failure-mode contract |
| (NEW) Vermagic mismatch after kernel HWE auto-update breaks `relay_module.ko` insmod | Phase 2 (preflight) | **Phase 1 (operational)** | This has been a real-world outage class for out-of-tree modules; preflight is cheap, fits in Phase 1 ops bucket |
| (NEW from v2 verification, **CONFIRMED HIGH** after Pulumi SG check) Backend HTTP routes have no auth: `/relays`, `/relay_data`, `/cost_matrix`, `/route_matrix`, `/relay_counters/{name}`, `/relay_history`, `/costs`, `/active_relays`, `/metrics` are all served from `0.0.0.0:HTTP_PORT` (`main.rs:89`). Production SG `sg_backend` (`infra/network.py:187-194`) opens TCP 8090 to `0.0.0.0/0` and `::/0` for both IPv4 and IPv6 - the entire internet. The comment "Backend HTTP (/relay_update, /route_matrix)" suggests path-restricted intent, but a security group is L4 and cannot enforce per-path rules | - | **Phase 1 (High)** | Information disclosure: cost matrices and topology are useful for targeted attacks (game-cheating reconnaissance, DDoS targeting), `/metrics` reveals operational patterns. No authenticated state changes are possible (so not Critical), but every scanned EC2 IP leaks topology. Fix: bind non-`/relay_update` routes to a separate internal port restricted to `admin_cidr` and the VPC CIDR, OR add a bearer-token middleware layer to the non-`/relay_update` route group. Cannot be fixed at SG level alone |
| (NEW from v2 verification) Redis HSET write at `main.rs:153` writes to `relay-backends-{minutes}` with no `EXPIRE` | - | **Phase 2 (Medium)** | Steady state Redis memory growth at 1 entry per minute per backend. Fix: add `EXPIRE 7200` (2 hours) on each HSET path |

## Decisions Made

Carried from v1:

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Run audit as four parallel exploration agents instead of one monolithic pass | Each surface has different invariants; parallel keeps each prompt focused | N/A |
| Treat agent line numbers as advisory, not authoritative | Exploration agents read excerpts; offsets must be re-checked before fix | N/A |
| Sequence remediation as Critical -> High -> Medium with two-week cadence | Matches existing CI gate philosophy | N/A |

Added in v2:

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Run a verification pass before committing to phase actions | Three v1 claims did not hold up; without verification the plan would have spent effort on a non-issue (`gitignore`) and missed structure issues (capability bounding already present) | N/A |
| Promote pittle/chonkle parity test and `size_of` asserts from Phase 2 to Phase 1 | Both are cheap, zero-maintenance, and protect the exact code being modified in Phase 1. Deferring them increases the risk of a Phase 1 fix introducing a regression that Phase 2 would only catch later | N/A |
| Treat "kfunc loader trust boundary" as an architectural decision, not a Critical bug | The 27 panics are a quality issue, but the underlying design choice ("we trust the on-disk module path, full stop") needs to be written down before we know which fixes are appropriate (typed errors? signature check? read-only mount?) | [ADR-005](../decisions/ADR-005-kfunc-loader-trust-boundary.md) |

## ADRs (drafted 2026-05-04)

The audit produced three architectural decisions, each drafted as a Proposed ADR before the corresponding Phase 1 code change lands:

1. **[ADR-004: Replay-Protection Window for `/relay_update`](../decisions/ADR-004-replay-protection-window-for-relay-update.md).** Per-relay nonce LRU + 30s payload-timestamp freshness check. Companion to P1-01.
2. **[ADR-005: kfunc Loader Trust Boundary](../decisions/ADR-005-kfunc-loader-trust-boundary.md).** Trusted-input contract; convert `.expect()` panics to a typed `KfuncLoadError`. Companion to P1-07.
3. **[ADR-006: FFI Panic Policy for relay-sdk](../decisions/ADR-006-ffi-panic-policy-for-relay-sdk.md).** Registered C log callback + best-effort error sentinel. Companion to P1-02.

## Phase plan with finding-to-action matrix

### Phase 1 - Critical + cross-cutting cheap wins (target ~1 week)

| Action ID | Source finding | Files | Tests / gates | Notes |
|-----------|----------------|-------|---------------|-------|
| ~~P1-01~~ **Done 2026-05-04** | Critical theme #1 (replay) | New `relay-backend/src/replay.rs` (NonceCache + clock-fresh check, 6 unit tests); `state.rs` (`nonce_cache`, 2 atomic counters); `handlers.rs` (replay check before decrypt; clock-skew check after parse); `metrics.rs` (2 new Prometheus counters); `Cargo.toml` (lru 0.12 dep) | New `tests/e2e_encrypted.rs` cases: replay rejected on second attempt + counter incremented; stale `current_time` rejected + counter incremented; same-nonce-different-relay sanity (delegated to `replay::tests`) | Per-relay LRU 1024 nonces, `30s` clock-skew window. Companion [ADR-004](../decisions/ADR-004-replay-protection-window-for-relay-update.md) (status moved to Accepted). LRU eviction-allows-replay covered by `replay::tests::nonce_eviction_past_capacity_allows_old_nonce` (cheaper than 1025 e2e HTTP requests) |
| ~~P1-02~~ **Done 2026-05-04** | Critical theme #2 (FFI zeroize + panic policy) | New `relay-sdk/src/ffi/panic.rs` (PanicHook type, `set_hook` AtomicPtr, `ffi_catch` wrapper, 3 unit tests with TEST_LOCK serialization); `mod.rs` (17 catch_unwind sites refactored to `panic::ffi_catch`; `Zeroizing` wrap on session-key buffers in `relay_client_open_session` line 110 + `relay_server_register_session` line 282; `relay_set_panic_hook` + `relay_clear_panic_hook` extern "C" exports; `const _: fn()` Zeroize impl assert) | `cargo test -p relay-sdk` 187 lib tests pass (+3 panic tests); cbindgen header `relay_generated.h` exports `relay_PanicHook`, `relay_set_panic_hook`, `relay_clear_panic_hook` | Companion [ADR-006](../decisions/ADR-006-ffi-panic-policy-for-relay-sdk.md) (status moved to Accepted). Hook is opt-in: embedders that never call `relay_set_panic_hook` keep the historical silent-swallow behaviour. Zeroizing protects FFI-layer key copies; deeper `Client`/`Server` storage zeroization is out of scope (separate finding) |
| P1-03 | Critical theme #3 (pointer lifetime, not unwrap) | `relay-xdp-ebpf/src/main.rs` (call sites at lines 612, 1193, 1277, 1361, 1451, 1520, 1599, 1677, 1898 - **verify offsets**) | Manual verifier walk + `xtask build-ebpf-rust` clean | Codify "snapshot-then-write-back" pattern. Output: short note in `docs/decisions/` |
| ~~P1-04~~ **Done 2026-05-04** | Critical theme #4 (Pulumi prod CIDR) | `infra/Pulumi.production.yaml` + `Pulumi.staging.yaml` (`admin_cidr: REQUIRED_OVERRIDE`); `infra/config.py` (`_validate_admin_cidr` + `cfg.require` instead of silent default); `Makefile` (`_preflight-admin-cidr-{production,staging}` as deps of every Pulumi target); new `infra/test_admin_cidr_validation.py` (7/7 pass) | `python infra/test_admin_cidr_validation.py` exercises 4 reject paths + 3 accept paths; `python infra/test_inventory_gen.py` still green | Two-layer defense: (1) Makefile preflight catches misconfig before `pulumi` even starts, with a clearer error and earlier failure than (2) `_validate_admin_cidr` raising `pulumi.RunError` at evaluation time. Staging refuses placeholder but accepts `0.0.0.0/0` if explicitly chosen; production refuses both placeholder and wide-open |
| ~~P1-05~~ **Done 2026-05-04** | Critical theme #4 (ansible host key) | `ansible/ansible.cfg` | INI parse confirms `host_key_checking = True`, `ssh_args = -o ControlMaster=auto -o ControlPersist=60s -o StrictHostKeyChecking=accept-new` | **BOTH** sites fixed in one change. Used `accept-new` (auto-accepts on first sight, rejects on key change) instead of toggling to `=yes` (which would prompt interactively and break automation). After first deploy, MITM is detected on every subsequent connect |
| ~~P1-06~~ **Done 2026-05-04** | Critical theme #4 (systemd hardening) | `ansible/roles/relay-xdp/templates/relay-xdp.service.j2` | `systemd-analyze verify` on rendered unit reports only the expected "ExecStart not executable" (binary not on dev host); unit syntax clean. Functional XDP-attach check requires staging deploy | Added `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ProtectKernelTunables`, `ProtectControlGroups`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`. Capability bounding already correct (kept as-is). **Operator note:** if a future change writes outside `/sys/fs/bpf`, add `ReadWritePaths` rather than relaxing `ProtectSystem`. Functional verification on staging is a follow-up |
| P1-07 | Critical theme #5 (kfunc trust boundary) | `relay-xdp/src/kfunc.rs` (typed errors), `bpf.rs` | Existing kfunc-loader integration tests + new negative-path unit tests | Companion [ADR-005](../decisions/ADR-005-kfunc-loader-trust-boundary.md). Convert `.expect()` to `Result` via `KfuncLoadError`. Do NOT add signature verification (rejected in ADR-005) |
| ~~P1-08~~ **Done 2026-05-04 - and immediately caught a real bug (P1-15 below)** | Cross-cutting (parity drift, was Phase 2) | `tests/fixtures/pittle_chonkle_vectors.rs` (8 canonical vectors); consumers in `relay-xdp/tests/pittle_chonkle_parity.rs`, `relay-sdk/tests/pittle_chonkle_parity.rs` (loaded via `#[path]` - zero serde dev-dep) | XDP test passes on both pittle and chonkle; SDK chonkle passes; SDK pittle ignored with link to P1-15 | Used `.rs` source file rather than `.json` because eBPF crate is no_std and serde_json adds non-trivial dev-dep weight to two crates. eBPF parity ensured by visual inspection (eBPF and userspace impls are byte-identical); a proper eBPF-target build-time check is deferred |
| ~~P1-15~~ **Done 2026-05-04 (caught + fixed in same session)** - SDK `generate_pittle` was using `1u8.wrapping_add(s0 ^ s1 ^ 193)` instead of canonical `1 \| (sum_0 ^ sum_1 ^ 193)`. Diverged on ~50% of inputs by exactly 1 | `relay-sdk/src/route/mod.rs:56-57` | `cargo test -p relay-sdk --test pittle_chonkle_parity` now passes both `sdk_pittle_matches_canonical` and `sdk_chonkle_matches_canonical` without `#[ignore]` | **Severity was High - latent correctness bug.** SDK-stamped packets would have been dropped by the XDP relay's `basic_packet_filter` on every diverging input. The fix is two character changes (`1u8.wrapping_add(...)` -> `1 \| (...)`); validated by the parity fixture from P1-08. **Operational note for the user:** if SDK is already in a live packet path, this bug would have manifested as ~50% packet drop at the relay - worth confirming whether anyone reported it |
| ~~P1-09~~ **Done 2026-05-04** | Cross-cutting (wire layout, was Phase 2) | `relay-xdp-common/src/lib.rs` (14 `const _:` asserts at file end) | `cargo build` on both `relay-xdp-common` and `relay-xdp-ebpf` (bpfel-unknown-none) succeeds; deliberate-mismatch proof showed `error[E0080]: evaluation panicked` | Covers 11 wire structs + `Chacha20Poly1305Crypto`; double-asserts for `RouteToken` and `ContinueToken` (named constant + literal). Workspace clippy + fmt + `wire_compat` runtime tests still green |
| P1-10 | High - Redis leader election fail-mode | `relay-backend/src/redis_client.rs`, `relay_manager.rs` | Compose test: kill Redis, observe single-leader contract | TTL alone is not enough - decide fail-open vs fail-closed in writing |
| P1-11 | High - Vermagic preflight | `ansible/roles/relay-module/tasks/main.yml` (or equivalent) | Ansible role on a staging host that has a pending kernel update | Cheap; prevents a known outage class |
| P1-12 | High - backend resource bounds | `relay-backend/src/relay_manager.rs`, `optimizer.rs` | Existing optimizer tests + new bounded-map test | Cap source-entry HashMap by max relay count; wrap optimizer worker bodies in `catch_unwind` |
| P1-13 | High - poisoned RwLock | `relay-backend/src/*` (audit `RwLock::expect("lock poisoned")` call sites at `magic.rs:76, 89`, `main.rs:309, 313, 319`, `handlers.rs:313, 369, 383, 456, 510, 576`, `redis_client.rs:147, 191, 220, 227`) | Unit test that poisons the lock and asserts recovery | Use a small helper crate-wide |
| ~~P1-14~~ **Done 2026-05-04** | High - Backend HTTP route auth surface | `relay-backend/src/handlers.rs` (split `create_router` -> `create_public_router` + `create_admin_router`); `relay-backend/src/main.rs` (two listeners via `tokio::join!`); `relay-backend/src/config.rs` (`admin_http_port`, `admin_bind_address`); `relay-backend/tests/route_separation.rs` (new); `docker-compose.test.yml` (`ADMIN_HTTP_PORT=81`, `ADMIN_BIND_ADDRESS=0.0.0.0`); `tests/compose-test.sh` (split URLs + 3 new 404 assertions); `infra/network.py` (new SG ingress for 8091 from `admin_cidr`); `ansible/roles/relay-backend/templates/backend.env.j2` (`ADMIN_HTTP_PORT`, `ADMIN_BIND_ADDRESS`) | `cargo test -p relay-backend --test route_separation` 2/2 pass; full workspace test suite green | Two-server split. Public port carries `/relay_update` + 5 health endpoints; admin port carries `/relays`, `/relay_data`, `/cost_matrix`, `/route_matrix`, `/relay_counters/{n}`, `/relay_history/{src}/{dest}`, `/costs`, `/active_relays`, `/metrics`. Admin defaults to `127.0.0.1` bind for safety; production overrides to `0.0.0.0` and relies on the SG ingress filter limiting 8091 to `admin_cidr`. **Operator note:** `admin_cidr` is still `0.0.0.0/0` in `Pulumi.production.yaml` (P1-04 backlog) - until P1-04 lands, the admin port is effectively as exposed as the public port was. The separation in code is now in place; closing the gap requires P1-04 |

### Phase 2 - High + drift / observability (target ~1 - 2 weeks after Phase 1)

| Action ID | Source finding | Notes |
|-----------|----------------|-------|
| P2-01 | Session-map flood / LRU eviction DoS | Token-bucket on per-source rate before `session_map.insert`, OR sharded session map |
| P2-02 | `cargo deny` (NOT `cargo audit`, already in CI) | License + duplicate-version + advisory gates beyond what `audit-check` covers |
| P2-03 | Validate `RELAY_DATA_FILE` path | Reject path traversal + symlink escape |
| P2-04 | Constrain `/relay_counters/{name}` regex | Whitelist character set |
| P2-05 | Paginate `/metrics` | Bound response size |
| P2-06 | Generic-ize backend error strings | Avoid leaking wire-format hints |
| P2-07 | FFI contract drift guard (downgraded from Critical) | `_Static_assert(sizeof(...) == N)` in cbindgen post-amble; matching Rust `const _` |
| P2-08 | Redis HSET TTL on `relay-backends-{minutes}` (NEW from v2 verification) | Add `EXPIRE 7200` after HSET in `main.rs:153-160` |
| - | ~~P2-09 (Backend HTTP route auth)~~ | **Promoted to Phase 1 as P1-14** after Pulumi SG verification confirmed `0.0.0.0/0` + `::/0` ingress on TCP 8090 in `infra/network.py:192-193`. Production stack does not override |

### Phase 3 - Medium hardening

Carried over from v1 unchanged: paginate `/metrics`, validate path inputs, etc. (See v1 sections; no v2 changes.)

### Phase 4 - Low / hygiene

| Action ID | Notes |
|-----------|-------|
| P4-01 | Switch `tests/compose-test.sh` vault-pass cleanup from `rm -f` to `shred -ufv` |
| P4-02 | Add `cargo:rerun-if-changed=src/constants.rs` to `relay-sdk/build.rs` |
| - | **Removed v1 item**: "move `debug.txt` and `relay_xdp_rust.o` out of working tree" - already gitignored, not tracked |

## Verification status (post second pass)

Verified in v2's second pass (this section is the receipt):

- [x] **Backend `decrypt_relay_request` lacks freshness check** - confirmed at `handlers.rs:146-218`; no nonce cache, no timestamp validation. Unambiguously Critical. Drives ADR-004 / P1-01.
- [x] **SDK `catch_unwind` swallow** - confirmed; 8 void FFI sites, **the source comment at `mod.rs:23-26` itself documents the swallow behaviour**. Drives ADR-006 / P1-02.
- [x] **SDK secret-key not zeroized** - confirmed at `mod.rs:110` (`let mut key = [0u8; SESSION_PRIVATE_KEY_BYTES];`, no `Zeroizing` wrap). `zeroize = "1"` is already vendored.
- [x] **SDK `rand::thread_rng()` for XChaCha nonces** - `Cargo.toml:26` -> `rand 0.8.6` -> `ThreadRng = ReseedingRng<ChaCha12Core, OsRng>`. Safe for 192-bit nonces. Action: document the assumption + version-gate; not a Critical bug.
- [x] **eBPF `is_none -> unwrap` pattern** - confirmed at line 1193-1198. The unwrap itself does not race; the lifetime of the resulting raw pointer is the real concern. `session_map.insert(...)` exists at line 1127 and direct `*ptr` writes appear at 1057, 1165, 1244, 1328, 1412, 1493, 1572, 1650 - so eviction can interleave with pointer use across handlers. P1-03 must walk each handler.
- [x] **kfunc.rs panic count** - confirmed 27 sites, mostly `.try_into().expect("N bytes")` in BTF parsing (lines 162-477 for relocations, 790-1035 for BTF parser, plus `object::File::parse` at 1293). Drives ADR-005 / P1-07.
- [x] **Backend lock-poisoning** - 14 `RwLock::expect("lock poisoned")` sites: `magic.rs:76, 89`, `main.rs:309, 313, 319`, `handlers.rs:313, 369, 383, 456, 510, 576`, `redis_client.rs:147, 191, 220, 227`. Reclassified Critical -> High; drives P1-13.
- [x] **Backend system-clock expect** - `main.rs:149 update_relay_backend_instance` `.expect("system clock before unix epoch")`. Reclassified Critical -> Low.
- [x] **Operational Critical theme #4** - `Pulumi.production.yaml:11`, `ansible.cfg:6, 18`, `relay-xdp.service.j2` all confirmed in v2 round 1.

Still pending verification (pushed to fix-time per the matrix):

- [ ] **The 5 eBPF "Critical" count** - 1 verified (pointer lifetime / P1-03), 1 verified architecturally (kfunc trust boundary / P1-07). The remaining 3 are not enumerated in v1 nor in v2 - either v1's count was rounded up, or there are findings hidden in v1's exploration-agent output that did not make it into the themes section. Re-verify when revisiting v1's raw agent output.
- [ ] **All High / Medium / Low items.** Verified at fix time per the finding-to-action matrix.
- [x] **Backend HTTP route auth surface** - confirmed High after `infra/network.py:187-194` shows `sg_backend` opens TCP 8090 to `0.0.0.0/0` AND `::/0` for the entire internet, and `Pulumi.production.yaml` does not override. Promoted from candidate P2-09 to P1-14 in this same revision.

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| v1 exploration agents cite line numbers from partial reads; some offsets stale | v2 verifies the named Critical claims; remaining items get verified at fix time | No |
| v1 conflated "no capability bounding" with "no privilege hardening" - the unit had the former | v2 corrects, drops the false claim | No |
| v1's Low-priority `gitignore` item was a misread (file on disk != file in git index) | v2 drops the item | No |
| `pittle/chonkle parity` was simultaneously labelled "single most likely correctness regression" and Phase 2 Medium | v2 promotes to Phase 1 | No |
| Backend "3 Critical" count over-reported | v2 second pass shows only 1 (replay) is Critical; 14 lock-poison sites reclassified to High; system-clock expect reclassified to Low. Net Critical 14 -> 11 | No |
| 5 eBPF Critical findings only partially enumerated; v2 verified pointer-lifetime + kfunc-trust-boundary, the other 3 are not named in v1's themes | Marked as "still pending verification" - revisit raw exploration-agent output if a future audit needs the full list | No |

## Next Steps

1. Land P1-09 (`size_of` asserts) and P1-08 (parity vector fixture) **first** - they protect every subsequent Phase 1 fix.
2. ADR drafts already in place: [ADR-004](../decisions/ADR-004-replay-protection-window-for-relay-update.md) (replay window), [ADR-005](../decisions/ADR-005-kfunc-loader-trust-boundary.md) (kfunc trust boundary), [ADR-006](../decisions/ADR-006-ffi-panic-policy-for-relay-sdk.md) (FFI panic policy). Move each to **Accepted** when its companion P1 action lands.
3. ~~Verify the Pulumi security-group ingress for backend `HTTP_PORT` to classify P2-09~~ Done in this revision: `network.py:187-194` opens TCP 8090 to `0.0.0.0/0` + `::/0`; promoted to P1-14 (High) below.
4. Execute P1-01..P1-14 in any order respecting the matrix's "Files / Tests" columns; each lands as its own PR-equivalent local commit.
5. After Phase 1, re-verify the un-verified Critical items listed above; if any survive, they enter Phase 2 ahead of the current Phase 2 backlog.
6. Phase 2 starts only after Phase 1 CI is green (`cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`, `cargo xtask func-test`, `cargo bench --no-run -p relay-sdk`, docker-compose suite).

<!-- Mark completed steps with strikethrough: ~~**P1-01:** description~~ Done -->

## Files Changed

| Status | File |
|--------|------|
| A      | `docs/sessions/2026-05-04-project-audit-plan-v2.md` |
| A      | `docs/decisions/ADR-004-replay-protection-window-for-relay-update.md` |
| A      | `docs/decisions/ADR-005-kfunc-loader-trust-boundary.md` |
| A      | `docs/decisions/ADR-006-ffi-panic-policy-for-relay-sdk.md` |
| -      | `docs/sessions/2026-05-04-project-audit-plan.md` (kept as v1, unchanged) |
| D      | `docs/sessions/2026-05-04-phase-1-critical-fixes-plan.md` (already staged for removal in working tree; superseded by v2's finding-to-action matrix) |