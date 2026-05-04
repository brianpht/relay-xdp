# Session Summary: Project-Wide Audit and Remediation Plan

**Date:** 2026-05-04<br>
**Duration:** ~1 interaction (4 parallel exploration agents)<br>
**Focus Area:** Cross-cutting audit of relay-xdp (eBPF data plane, kfunc loader, relay-backend, relay-sdk, infra/ansible/CI)<br>

## Objectives

- [x] Run a structured audit across all four major surfaces of the project
- [x] Categorise findings by severity (Critical / High / Medium / Low)
- [x] Produce a phased remediation plan with concrete next steps
- [ ] Verify each individual finding against current source (line numbers were inferred by exploration agents)
- [ ] Open tracking tickets / ADRs for accepted findings

## Work Completed

### Audit scope and method

Four exploration agents ran in parallel against the working tree at HEAD (`master` @ 0e02c4e). Each focused on one surface:

1. eBPF data plane + kfunc loader: `relay-xdp-ebpf/src/main.rs`, `relay-xdp/src/{kfunc,bpf,packet_filter}.rs`, `relay-xdp-common/src/lib.rs`, `module/relay_module.c`.
2. relay-backend: `src/{main,handlers,relay_update,relay_manager,optimizer,database,redis_client,encoding,magic}.rs`, `Cargo.toml`, `Dockerfile`.
3. relay-sdk: `src/{ffi,crypto,tokens,packets,client,server,route,pool}/`, `build.rs`, `cbindgen.toml`, generated header.
4. Infra / deploy: `Makefile`, `infra/` (Pulumi), `ansible/` (roles, playbooks, inventory), `.github/workflows/*`, `docker-compose.test.yml`, `tests/`.

Each agent returned a prioritised list. Findings were then de-duplicated and grouped by theme.

### Findings summary

| Surface                          | Critical | High | Medium | Low |
|----------------------------------|----------|------|--------|-----|
| eBPF data plane + kfunc loader   | 5        | 5    | 5      | 4   |
| relay-backend                    | 3        | 5    | 7      | 5   |
| relay-sdk (FFI / crypto)         | 3        | 3    | 2      | 2   |
| Infra / Ansible / CI             | 3        | 2    | 4      | 2   |
| **Total**                        | **14**   | **15** | **18** | **13** |

### Critical themes (verification required before fix)

1. **Replay/nonce hygiene.** Backend `/relay_update` decryption has no timestamp/nonce window; SDK token encryption uses `rand::thread_rng()` for XChaCha20-Poly1305 nonces - chosen RNG source needs explicit verification (likely OsRng-backed and safe due to 192-bit nonce, but should be made explicit and asserted in tests).
2. **FFI surface in relay-sdk.** Secret-key copies are not zeroized; `relay_*_get_stats(out)` lacks an `out_size` argument; void FFI functions silently swallow panics inside `catch_unwind`.
3. **Kernel-side safety.** Multiple `.unwrap()` on `session_map.get_ptr_mut` / `whitelist_map.get_ptr_mut` results; LRU eviction races between lookup and write are plausible. ELF/BTF parser in `kfunc.rs` panics on malformed input via `.expect(...)`.
4. **Operational hardening.** `ansible.cfg` disables strict host key checking; `infra/Pulumi.production.yaml` ships `admin_cidr=0.0.0.0/0` for SSH:22; relay-xdp systemd unit runs `User=root` without `NoNewPrivileges`, `ProtectSystem`, or capability bounding.

### Cross-cutting risks

- **Pittle/chonkle parity** lives in three crates with no cross-crate parity test - drift is the single most likely correctness regression and is cheap to guard with a shared test vector file.
- **Wire layout drift** in `relay-xdp-common` is currently caught only by `wire_compat` integration tests - a `const _: () = assert!(size_of::<X>() == N);` block would catch it at compile time, much cheaper.
- **Dependency hygiene**: no `cargo audit` / `cargo deny` gate beyond the existing `rustsec/audit-check` workflow; crypto crates pinned to `major.minor` ranges.

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Run audit as four parallel exploration agents instead of one monolithic pass | Each surface has different invariants (eBPF verifier, axum/tokio, FFI, Pulumi/Ansible); parallel keeps each prompt focused and cuts wall time | N/A |
| Treat agent line numbers as advisory, not authoritative | Exploration agents read excerpts; they can name files reliably but offsets must be re-checked before a fix lands | N/A |
| Defer ADRs until findings are verified | Avoid encoding speculative claims into the architectural source of truth | N/A |
| Sequence remediation as Critical -> High -> Medium with two-week cadence | Matches existing CI gate philosophy (zero warnings, zero failing tests on master) | N/A |

## Tests Added/Modified

None. This session was audit-only - no source or tests were modified.

| Test Class | Method | Type | Status |
|------------|--------|------|--------|
| -          | -      | -    | -      |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| Exploration agents cite line numbers from partial reads; some offsets may be stale | Marked findings as "verify before fix"; require git-blame + targeted re-read during remediation | No |
| Several findings depend on RNG / crypto-library internals that were not opened during audit (e.g., whether `rand::thread_rng()` is OsRng-backed in the SDK's pinned `rand` version) | Capture as explicit verification tasks in Phase 1 | No |
| No automated way to detect drift between eBPF / userspace / SDK pittle/chonkle implementations today | Phase 2 introduces a shared test-vector JSON file consumed by all three crates | No |

## Next Steps

1. **High:** Verify and fix the Critical set (Phase 1, target ~1 week)
   - Add timestamp/nonce window in `relay-backend/src/handlers.rs::decrypt_relay_request`
   - Zeroize secret-key buffers in `relay-sdk/src/ffi/mod.rs` (use the already-vendored `zeroize` crate)
   - Change `relay_client_get_stats` / `relay_server_get_stats` to take `(out, out_size)` and validate
   - Audit every `.unwrap()` in `relay-xdp-ebpf/src/main.rs` against the LRU eviction model
   - Replace `admin_cidr: "0.0.0.0/0"` default in `infra/Pulumi.production.yaml`; add a Makefile preflight check
   - Harden `ansible/roles/relay-xdp/templates/relay-xdp.service.j2` with `NoNewPrivileges`, `ProtectSystem=strict`, capability bounding
2. **High:** Concurrency and resource bounds in backend (Phase 1, in parallel)
   - Replace `RwLock::expect("lock poisoned")` call sites with poison-recovering helpers
   - Bound `relay_manager` source-entry HashMap by max relay count
   - Wrap optimizer worker bodies in `catch_unwind` so a single panic does not kill the process
   - Add Redis TTL on leader-election keys
3. **Medium:** Drift and observability (Phase 2, ~1-2 weeks after Phase 1)
   - Introduce `tests/fixtures/pittle_chonkle_vectors.json`; have the eBPF, relay-xdp, and relay-sdk filter implementations all assert against it
   - Add `const _: () = assert!(size_of::<X>() == N);` for every wire struct in `relay-xdp-common`
   - Add `cargo audit` and `cargo deny` to CI; pin crypto crates to exact patch versions
   - Validate `RELAY_DATA_FILE` path; constrain `/relay_counters/{name}` regex; paginate `/metrics`
   - Add reboot-detection preflight to the kernel-module Ansible role to catch HWE auto-update vermagic mismatches
4. **Low:** Hygiene
   - Move `debug.txt` and the committed `relay_xdp_rust.o` artefact out of the working tree (add to `.gitignore`)
   - Switch `tests/compose-test.sh` vault-pass cleanup from `rm -f` to `shred -ufv`
   - Add `cargo:rerun-if-changed=src/constants.rs` to `relay-sdk/build.rs`
   - Generic-ize backend error strings to avoid leaking wire-format hints

<!-- Mark completed steps with strikethrough: ~~**High:** description~~ Done -->

## Files Changed

| Status | File |
|--------|------|
| A      | `docs/sessions/2026-05-04-project-audit-plan.md` |