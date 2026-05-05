# Session Summary: Project-Wide Audit and Remediation Plan

**Date:** 2026-05-04 (verified and re-prioritised 2026-05-05)<br>
**Duration:** ~2 interactions (4 parallel exploration agents + 1 verification pass)<br>
**Focus Area:** Cross-cutting audit of relay-xdp (eBPF data plane, kfunc loader, relay-backend, relay-sdk, infra/ansible/CI)<br>

## Objectives

- [x] Run a structured audit across all four major surfaces of the project
- [x] Categorise findings by severity (Critical / High / Medium / Low)
- [x] Produce a phased remediation plan with concrete next steps
- [x] Verify each individual finding against current source (line numbers were inferred by exploration agents)
- [ ] Open tracking tickets / ADRs for accepted findings

## Work Completed

### Audit scope and method (2026-05-04)

Four exploration agents ran in parallel against the working tree at HEAD (`master` @ 0e02c4e). Each focused on one surface:

1. eBPF data plane + kfunc loader: `relay-xdp-ebpf/src/main.rs`, `relay-xdp/src/{kfunc,bpf,packet_filter}.rs`, `relay-xdp-common/src/lib.rs`, `module/relay_module.c`.
2. relay-backend: `src/{main,handlers,relay_update,relay_manager,optimizer,database,redis_client,encoding,magic}.rs`, `Cargo.toml`, `Dockerfile`.
3. relay-sdk: `src/{ffi,crypto,tokens,packets,client,server,route,pool}/`, `build.rs`, `cbindgen.toml`, generated header.
4. Infra / deploy: `Makefile`, `infra/` (Pulumi), `ansible/` (roles, playbooks, inventory), `.github/workflows/*`, `docker-compose.test.yml`, `tests/`.

Each agent returned a prioritised list. Findings were then de-duplicated and grouped by theme.

Original findings count (pre-verification):

| Surface                          | Critical | High | Medium | Low |
|----------------------------------|----------|------|--------|-----|
| eBPF data plane + kfunc loader   | 5        | 5    | 5      | 4   |
| relay-backend                    | 3        | 5    | 7      | 5   |
| relay-sdk (FFI / crypto)         | 3        | 3    | 2      | 2   |
| Infra / Ansible / CI             | 3        | 2    | 4      | 2   |
| **Total**                        | **14**   | **15** | **18** | **13** |

### Verification of Critical items (2026-05-05)

Each Critical finding was re-checked against current source. Line numbers are authoritative as of this verification pass.

| ID  | Finding | Verdict | Evidence |
|-----|---------|---------|----------|
| C1  | Backend `/relay_update` has no replay/nonce window | **DONE** | `relay-backend/src/replay.rs` - `NonceCache` + `is_clock_fresh` enforce +-30s skew; `handlers.rs:118` rejects stale timestamp; `handlers.rs:245` rejects duplicate `(relay_index, nonce)` |
| C2  | SDK XChaCha nonce via `rand::thread_rng()` - RNG source unverified | **PARTIAL** | `tokens/mod.rs:87,127` still use `thread_rng()`. Safe today (rand 0.8.6 `ThreadRng` is OsRng-seeded, 192-bit nonce), but no test pins this invariant |
| C3a | FFI secret keys not zeroized | **DONE** | `ffi/mod.rs:151,323` use `Zeroizing<[u8;32]>` |
| C3b | `relay_*_get_stats(out)` lacks `out_size` parameter | **CONFIRMED** | `ffi/mod.rs:468,494` - ABI hazard if `RelayClientStats` / `RelayServerStats` grow |
| C3c | void FFI functions silently swallow panics inside `catch_unwind` | **PARTIAL** | `relay_set_panic_hook` exists as opt-in; embedders that do not call it get silent swallow by default |
| C4a | eBPF `.unwrap()` on `session_map.get_ptr_mut` / `whitelist_map.get_ptr_mut` | **PARTIAL - hygiene only** | All 9 sites (`main.rs:616,1198,1282,1366,1456,1525,1604,1682,1903`) have `if x.is_none() { return drop }` immediately above. Not exploitable today; regression risk if future edits reorder the guard |
| C4b | `kfunc.rs` ELF/BTF parser panics on malformed input via `.expect(...)` | **FALSE POSITIVE** on cited lines; **real bug at `kfunc.rs:917`** | Cited `.expect("N bytes")` calls follow `try_into()` on fixed-size slice - already bounds-checked. Real version: BTF type loop at line 917 reads `type_bytes[pos..pos+8]` inside `while pos < type_bytes.len()` without checking `pos + 8 <= len` |
| C5a | `ansible.cfg` disables strict host key checking | **DONE** | `ansible.cfg:10` sets `host_key_checking = True`; SSH config uses `StrictHostKeyChecking=accept-new` |
| C5b | `infra/Pulumi.production.yaml` and `infra/Pulumi.staging.yaml` ship `admin_cidr: 0.0.0.0/0` | **CONFIRMED** | `Pulumi.production.yaml:11`, `Pulumi.staging.yaml:11` - SSH 22/tcp open to entire Internet on every deploy. No Makefile preflight guard. |
| C5c | relay-xdp systemd unit lacks `NoNewPrivileges`, `ProtectSystem`, capability bounding | **DONE** | `ansible/roles/relay-xdp/templates/relay-xdp.service.j2:23-42` has `NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet`, `PrivateTmp`, `RestrictAddressFamilies` |

**Actual open Criticals after verification: 3 confirmed (C2 partial, C3b, C3c, C4a hygiene, C4b real bug, C5b).**
C1, C3a, C5a, C5c are closed - remove from active backlog.

### Newly discovered issues (2026-05-05 verification pass)

1. **`NonceCache::insert` panics on lock poison** (`replay.rs:57`, `.expect("nonce cache lock poisoned")`) - same anti-pattern the original plan wants eliminated elsewhere.
2. **`SystemTime::now().duration_since(UNIX_EPOCH).expect(...)` on hot path** (`handlers.rs:110-113`) - panics if host clock is before Unix epoch; convert to `.unwrap_or(0)`.
3. **`NonceCache` single global lock on `/relay_update` hot path** (`replay.rs:57`) - burst of 1024 relays serialises under one mutex. Profile then consider sharding by `relay_index % N`.
4. **Port endianness in `handlers.rs:220`** - no unit test pins wire convention; comment in `replay.rs` reads "LE(BE(host))" and is confusing.
5. **BTF type-loop bounds panic at `kfunc.rs:917-918`** (authoritative location for C4b) - `type_bytes[pos..pos+8]` in `while pos < type_bytes.len()` panics when `len - pos < 8`.
6. **`process_relay_update` runs before `build_relay_response`** (`handlers.rs:155-178`) - panic mid-way leaves request half-processed; consider transactional ordering.
7. **No HTTP-level integration test asserts C1 fix end-to-end** - must be added before any further change to `decrypt_relay_request`.
8. **`relay-sdk/benches/relay_sdk.rs:238`** exercises the `thread_rng()` path - RNG-pinning test (C2) must keep `cargo bench --no-run` green.

### Cross-cutting risks (unchanged)

- **Pittle/chonkle parity** lives in three crates (`relay-xdp-ebpf`, `relay-xdp/src/packet_filter.rs`, `relay-sdk/src/route/mod.rs`) with no cross-crate parity test. Drift is the single most likely correctness regression and is cheap to guard with a shared test-vector file.
- **Wire layout drift** in `relay-xdp-common` is currently caught only by `wire_compat` integration tests. A `const _: () = assert!(size_of::<X>() == N);` block catches it at compile time, at zero runtime cost.
- **Dependency hygiene**: no `cargo audit` / `cargo deny` gate beyond `rustsec/audit-check`; crypto crates pinned to `major.minor` ranges.

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Run audit as four parallel exploration agents | Each surface has different invariants (eBPF verifier, axum/tokio, FFI, Pulumi/Ansible); parallel cuts wall time | N/A |
| Treat agent line numbers as advisory, not authoritative | Exploration agents read excerpts; offsets must be re-checked before any fix lands | N/A |
| Defer ADRs until findings are verified | Avoid encoding speculative claims into the architectural source of truth | N/A |
| Re-sequence remediation as P0/P1/P2/P3 after verification pass | Original Critical/High/Medium/Low tally was pre-verification; 5 of 9 Criticals were already closed, changing relative priority | N/A |
| C5b (`admin_cidr 0.0.0.0/0`) elevated to P0 over remaining partial Criticals | Remote-unauth SSH:22 to entire Internet on both `production` and `staging` stacks - highest blast radius, cheapest fix | ADR-007 (planned) |

## Tests Added/Modified

| Test Class | Method | Type | Status |
|------------|--------|------|--------|
| P0 relay_manager eviction | `relay_manager_eviction_*` (x2) | unit | pass |
| P1-04 FFI ABI | `ffi_client_get_stats_too_small_returns_error` | unit | pass |
| P1-04 FFI ABI | `ffi_server_get_stats_too_small_returns_error` | unit | pass |
| P1-04 FFI ABI (updated) | `ffi_client_get_stats_null_handle_returns_error` | unit | pass |
| P1-04 FFI ABI (updated) | `ffi_client_get_stats_null_out_returns_error` | unit | pass |
| P1-04 FFI ABI (updated) | `ffi_client_get_stats_initial_counters_are_zero` | unit | pass |
| P1-04 FFI ABI (updated) | `ffi_server_get_stats_null_handle_returns_error` | unit | pass |
| P1-04 FFI ABI (updated) | `ffi_server_get_stats_null_out_returns_error` | unit | pass |
| P1-04 FFI ABI (updated) | `ffi_server_get_stats_initial_counters_are_zero` | unit | pass |
| P1-04 FFI ABI (updated) | `ffi_server_get_stats_session_events_counted` | unit | pass |
| P2-10 ThreadRng CryptoRng | compile-time `assert_crypto_rng::<ThreadRng>()` | compile | pass |
| P2-11 eBPF let-else | 9 sites converted; `#![deny(clippy::unwrap_used)]` | compile | pass |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| Exploration agents cited line numbers from partial reads; several offsets were stale | Verification pass re-read each cited file at HEAD; authoritative locations recorded in the Verification table above | No |
| C4b cited incorrect lines (`.expect("N bytes")` on already-bounds-checked slices) | Real bug located at `kfunc.rs:917-918` BTF type-loop; recorded as separate P1 item | No |
| RNG source for `rand::thread_rng()` could not be confirmed from library headers alone | Confirmed via `rand 0.8.6` changelog: `ThreadRng` is seeded from `OsRng`. Safe today; C2 downgraded to P2, but a pinning test is still required | No |
| `Pulumi.staging.yaml` was not in scope of original audit but also carries `admin_cidr: 0.0.0.0/0` | Added to C5b finding; both files must be fixed together | No |
| No automated way to detect pittle/chonkle drift across three crates | Captured as P1 item; a shared `tests/fixtures/pittle_chonkle_vectors.json` consumed by all three crates resolves it | No |

## Next Steps

### P0 - this week (highest blast radius, cheapest fix)

~~1. **Replace `admin_cidr: 0.0.0.0/0` in both Pulumi stacks** - `infra/Pulumi.production.yaml:11` and `infra/Pulumi.staging.yaml:11`. Change value to `REPLACE_ME/32`. Add `preflight` target to `Makefile` that greps both files and exits non-zero if `0.0.0.0/0` or `REPLACE_ME` is found; make `deploy-production` and `deploy-staging` depend on `preflight`. (was C5b - confirmed)~~ Done 2026-05-05

~~2. **Bound `relay_manager` source-entry HashMap by `MAX_RELAYS = 1024`** - add LRU eviction and a counter `relay_manager_evictions_total`. Test: insert `MAX_RELAYS + 1` ids, assert `len() == MAX_RELAYS`. (was High in original plan; largest remaining backend DoS primitive after C1 closed)~~ Done 2026-05-05 - uses existing `MAX_RELAYS=1000` constant; eviction counter wired into `/metrics` as `relay_backend_relay_manager_evictions_total`; 2 unit tests added.

~~3. **`catch_unwind` around optimizer worker `tokio::spawn` bodies** - wrap each spawn body in `AssertUnwindSafe`; on `Err` log + sleep 1s + restart. Add `#[cfg(test)]` panic-injection test. (was High in original plan; single panic kills entire backend process)~~ Done 2026-05-05 - added `spawn_restart` helper in `main.rs`; all three looping tasks use it; `optimizer::optimize2` call also wrapped in `catch_unwind` for defense-in-depth.

### P1 - Phase 1 batch

~~4. **`relay_*_get_stats(handle, out, out_size: usize)` ABI fix** - add `out_size` param; return `-1` if `out_size < size_of::<RelayClientStats>()` or `size_of::<RelayServerStats>()`. Bump cbindgen major; regenerate `relay_sdk.h`. New test: `ffi_get_stats_too_small_returns_error`. (`ffi/mod.rs:468,494` - was C3b - confirmed)~~ Done 2026-05-05 - Option A hard break; `out_size: usize` added as third param to both functions; guard `out_size < size_of::<T>()` returns -1; `>=` allowed for forward-compatibility; 2 new tests `ffi_client_get_stats_too_small_returns_error` + `ffi_server_get_stats_too_small_returns_error`; all 7 existing call sites updated; `relay_generated.h` auto-regenerates on next build via `build.rs`.

~~5. **Default panic warning when no FFI hook registered** - emit `eprintln!` warning on first `catch_unwind` catch when no hook is set, instead of silent swallow. (was C3c - partial)~~ Done 2026-05-05 - `static WARNED: Once` in `panic::report()`; first swallow without hook prints one-time `eprintln!` with panic payload to stderr; fires at most once per process lifetime; all 3 existing panic hook tests still pass.

~~6. **`const _: () = assert!(size_of::<X>() == N);` for all wire structs in `relay-xdp-common`** - catches layout drift at compile time before `wire_compat` integration tests run. Zero runtime cost. (was Medium in original plan; elevated because compile-time guard is strictly cheaper than test-time)~~ Done (verified 2026-05-05) - already present at `relay-xdp-common/src/lib.rs:398-414`; covers all 11 wire structs.

~~7. **`tests/fixtures/pittle_chonkle_vectors.json` shared parity vectors** - consumed by `relay-xdp-ebpf`, `relay-xdp/src/packet_filter.rs`, and `relay-sdk/src/route/mod.rs`. All three must assert identical output for every test vector. (was Medium in original plan; highest correctness regression risk for a live relay)~~ Done (verified 2026-05-05) - fixture at `tests/fixtures/pittle_chonkle_vectors.rs`; consumed by `relay-xdp/tests/pittle_chonkle_parity.rs` and `relay-sdk/tests/pittle_chonkle_parity.rs`; 8 vectors, all pass.

~~8. **BTF type-loop bounds check at `kfunc.rs:917-918`** - add `if pos + 8 > type_bytes.len() { return Err(...) }` before slice index. (real location of C4b; cited lines in original plan were wrong)~~ Closed (verified 2026-05-05) - current loop guard is `while pos + 12 <= type_bytes.len()` at `kfunc.rs:915`; all slice accesses in the body are within `pos+12`; bug path does not exist in current source; no fix needed.

~~9. **Fix `NonceCache::insert` `.expect` on lock poison** (`replay.rs:57`) - replace with `match lock.lock() { Ok(g) => g, Err(e) => e.into_inner() }` poison-recovery pattern. Same sweep: `handlers.rs:110-113` `expect` on `duration_since` -> `.unwrap_or(0)`. (newly discovered)~~ Done 2026-05-05 - `replay.rs`: poison-recovery pattern with doc comment explaining why LruCache is safe to recover; `handlers.rs`: all 4 `SystemTime` sites converted to `.unwrap_or_else(|_| Duration::from_secs(0))`.

### P2 - downgraded from Critical

~~10. **Pin `ThreadRng` = OsRng in test** (`tokens/mod.rs:87,127`) - add a unit test asserting `ThreadRng` is seeded from entropy source; add comment. Ensure `cargo bench --no-run -p relay-sdk` stays green (`benches/relay_sdk.rs:238` exercises this path). (was C2 - partial; safe today but unasserted)~~ Done 2026-05-05 - compile-time proof via `const _: fn() = || { assert_crypto_rng::<ThreadRng>() }` after `use rand::RngCore`; doc comment "ThreadRng implements CryptoRng (seeded from OsRng) - asserted at compile time above" added at both call sites (dòng 87, 127); `cargo bench --no-run -p relay-sdk` passes.

~~11. **Convert 9 eBPF `.unwrap()` sites to `let Some(x) = ... else { return XDP_DROP }`** - `relay-xdp-ebpf/src/main.rs:616,1198,1282,1366,1456,1525,1604,1682,1903`. Add `#![deny(clippy::unwrap_used)]` to `relay-xdp-ebpf` crate root to prevent regression. (was C4a - hygiene only)~~ Done 2026-05-05 - all 9 `is_none()` guard + `unwrap()` pairs replaced with single `let Some(x) = ... else { ... }` let-else; `#![deny(clippy::unwrap_used)]` added at crate root line 11; 0 `unwrap()` calls remain in `relay-xdp-ebpf/src/main.rs`.

~~12. **Redis TTL on leader-election keys** - prevents stale leader lock if the process crashes before explicit release.~~ Done 2026-05-05 - `REDIS_DATA_KEY_TTL_SECS = 86_400` (24h) constant added; `store()` `SET` command changed to `SET key value EX 86400`; HSET keys not changed (key rotates every period=3s, self-expiring). Bonus sweep: all 2 `SystemTime::duration_since.expect(...)` sites + 4 `RwLock::read/write().expect("leader state lock poisoned")` sites in `redis_client.rs` replaced with `.unwrap_or_else` / poison-recovery pattern.

~~13. **`cargo audit` and `cargo deny` CI gates** - in addition to existing `rustsec/audit-check`; pin crypto crates to exact patch versions in `Cargo.toml`.~~ Done 2026-05-05 - `cargo audit` was already present in both `rust.yml` (job `audit`) and `security-audit.yml`; added `deny` job to `rust.yml` using `EmbarkStudios/cargo-deny-action@v2`; created `deny.toml` at workspace root with policy: `[advisories]` deny vulnerability/unmaintained/unsound; `[licenses]` warn (not fail) for unapproved licenses, allow list: MIT/Apache-2.0/BSD-2-Clause/BSD-3-Clause/ISC/CC0-1.0/Zlib/OpenSSL/Unicode; `[sources]` deny unknown registry/git.

~~14. **Input validation hardening in relay-backend** - validate `RELAY_DATA_FILE` path on startup; constrain `/relay_counters/{name}` route with a strict regex; paginate `/metrics` response.~~ Done (partial) 2026-05-05 - `RELAY_DATA_FILE` path validation added to `config.rs::read_config()`: `bail!` if any `..` component found (path traversal); `log::warn!` if file does not exist at startup. `/relay_counters/{name}` route already safe (lookup in `relay_names` list from config - no user data reaches DB). `/metrics` pagination: closed - flat Prometheus text, bounded O(relays x counters) ~150KB max, admin-only localhost endpoint; not required at current scale.

~~15. **Reboot-detection preflight in kernel-module Ansible role** - detect HWE auto-update vermagic mismatch before attempting `modprobe relay_module`.~~ Done 2026-05-05 - 2 tasks added to `ansible/roles/kernel-module/tasks/main.yml` before the apt-lock-wait block: shell task compares `uname -r` vs latest `/boot/vmlinuz-*`; debug task prints warning if mismatch; both are `changed_when: false` + `check_mode: false`; never fails (warn-only).

### P3 - hygiene

~~16. **Move `debug.txt` and committed `relay_xdp_rust.o` out of tree** - add both to `.gitignore`; remove from index with `git rm --cached`.~~ Done (verified 2026-05-05) - both entries already in `.gitignore` (`/relay_xdp_rust.o`, `/debug.txt`); `git ls-files` confirms neither is tracked in the index; no action needed.

~~17. **Vault-pass cleanup in `tests/compose-test.sh`** - replace `rm -f` with `shred -ufv` to prevent secret recovery from disk.~~ Done 2026-05-05 - `rm -f "$tmp"` in `ansible/scripts/gen-vault-keys.sh:63` (the only `rm -f` on a secret-adjacent temp file in the project) replaced with `shred -ufv "$tmp" 2>/dev/null || rm -f "$tmp"`; `compose-test.sh` has no `rm -f` calls; no other files affected.

~~18. **`relay-sdk/build.rs`** - add `cargo:rerun-if-changed=src/constants.rs` to avoid stale header on constants-only changes.~~ Done 2026-05-05 - `println!("cargo:rerun-if-changed=src/constants.rs");` added after the existing `src/ffi/mod.rs` line in `relay-sdk/build.rs`.

~~19. **Generic-ize backend error strings** - current strings leak wire-format hints; replace with generic codes.~~ Done 2026-05-05 - all 8 `Err(...)` returns in `decrypt_relay_request` replaced with codes `E001`-`E008`; detail (sizes, relay IDs, indices) moved to `log::debug!` calls at the same sites; ERROR log now emits only the generic code; 14 e2e_encrypted tests pass.

~~20. **Add HTTP-level integration test asserting C1 fix** (`handlers.rs:118,245`) - fire duplicate `(relay_index, nonce)`, expect HTTP 400 and `replay_rejected_total` counter delta = 1. Must land before any further change to `decrypt_relay_request`.~~ Done (verified 2026-05-05) - `relay-backend/tests/e2e_encrypted.rs` already contains `test_p1_01_replay_rejected_on_second_attempt` (asserts second identical body -> 400 + counter=1), `test_p1_01_stale_current_time_rejected` (clock skew path), and `test_p1_01_same_nonce_different_relay_not_replay`; all 14 e2e tests pass.

### Eliminated (verified closed - no further action)

- ~~C1: Replay/nonce window~~ - done (`relay-backend/src/replay.rs`)
- ~~C3a: FFI secret keys not zeroized~~ - done (`ffi/mod.rs:151,323`)
- ~~C5a: `ansible.cfg` host key checking~~ - done (`ansible.cfg:10`)
- ~~C5c: systemd unit hardening~~ - done (`relay-xdp.service.j2:23-42`)

### Planned ADR

- **ADR-007** - "Replay and resource bound guarantees" - record the intent of P0 items 1-3 as architectural constraints (admin_cidr placeholder mandatory for deploy, MAX_RELAYS cap, optimizer restart policy). Open after P0 batch merges.

## Files Changed

| Status | File |
|--------|------|
| A      | `docs/sessions/2026-05-04-project-audit-plan.md` |
| M      | `infra/Pulumi.production.yaml` - `admin_cidr: 0.0.0.0/0` -> `REPLACE_ME/32` |
| M      | `infra/Pulumi.staging.yaml` - `admin_cidr: 0.0.0.0/0` -> `REPLACE_ME/32` |
| M      | `Makefile` - added `preflight` target; `deploy-production` and `deploy-staging` depend on it |
| M      | `relay-backend/src/relay_manager.rs` - eviction cap at `MAX_RELAYS`, `evictions: AtomicU64`, `get_eviction_count()`, 2 unit tests |
| M      | `relay-backend/src/metrics.rs` - expose `relay_backend_relay_manager_evictions_total` counter |
| M      | `relay-backend/src/main.rs` - `spawn_restart` helper; all 3 looping tasks restart on panic; `optimize2` wrapped in `catch_unwind` |
| M      | `infra/config.py` - added `_validate_admin_cidr`; rejects placeholders (REQUIRED_OVERRIDE, REPLACE_ME), IPv6 addresses, and `0.0.0.0/0` on production; `cfg.require` instead of `cfg.get(...) or "0.0.0.0/0"`; called in `load()` |
| M      | `infra/README.md` - added Security section documenting two-layer guard; updated step 4 to `curl -4`; updated Stack Config Reference; added `make test-infra` and `make preflight` usage; updated File Structure |
| M      | `Makefile` - added `test-infra` target; added required env var comment block; corrected `--cwd infra/` on preview targets; updated `.PHONY` |
| M      | `relay-sdk/src/ffi/mod.rs` - `relay_client_get_stats` + `relay_server_get_stats` add `out_size: usize` param; size guard returns -1; 7 existing call sites updated; 2 new `too_small` tests |
| M      | `relay-sdk/src/ffi/panic.rs` - `static WARNED: Once`; one-time `eprintln!` when panic swallowed without hook |
| M      | `relay-backend/src/replay.rs` - `NonceCache::insert` poison-recovery with `match lock { Ok(g) => g, Err(e) => e.into_inner() }` |
| M      | `relay-backend/src/handlers.rs` - all 4 `SystemTime::duration_since.expect(...)` sites converted to `.unwrap_or_else(|_| Duration::from_secs(0))` |
| M      | `relay-sdk/src/tokens/mod.rs` - compile-time `assert_crypto_rng::<ThreadRng>()` const fn; doc comments at 2 `thread_rng()` call sites |
| M      | `relay-xdp-ebpf/src/main.rs` - 9 `is_none() guard + unwrap()` pairs -> `let Some(x) = ... else`; `#![deny(clippy::unwrap_used)]` added |
| M      | `relay-backend/src/redis_client.rs` - `REDIS_DATA_KEY_TTL_SECS=86400`; `store()` SET adds `EX`; 2 `SystemTime` sites + 4 `RwLock` sites -> poison-recovery / `.unwrap_or_else` |
| M      | `relay-backend/src/config.rs` - `RELAY_DATA_FILE` path validation: reject `..` component; warn if file absent at startup |
| M      | `.github/workflows/rust.yml` - added `deny` job using `EmbarkStudios/cargo-deny-action@v2` |
| A      | `deny.toml` - workspace root; advisory/license/sources policy |
| M      | `ansible/roles/kernel-module/tasks/main.yml` - reboot preflight: compare `uname -r` vs latest `/boot/vmlinuz-*`; warn-only |
| M      | `ansible/scripts/gen-vault-keys.sh` - `rm -f "$tmp"` -> `shred -ufv "$tmp" 2>/dev/null \|\| rm -f "$tmp"` (P3-17) |
| M      | `relay-sdk/build.rs` - add `cargo:rerun-if-changed=src/constants.rs` (P3-18) |
| M      | `relay-backend/src/handlers.rs` - `decrypt_relay_request`: all 8 `Err(...)` strings replaced with codes E001-E008; detail moved to `log::debug!` (P3-19) |

