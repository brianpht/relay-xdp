# Session Summary: Phase 1 Critical Fixes - Implementation Plan

**Date:** 2026-05-04<br>
**Duration:** Planning session (no code changes yet)<br>
**Focus Area:** Implementation plan for the Phase 1 / Critical bucket of the 2026-05-04 audit<br>

> Companion to [`2026-05-04-project-audit-plan.md`](2026-05-04-project-audit-plan.md). This file converts the "Next Steps - High (Phase 1)" bullets into concrete, verified work items.

## Objectives

- [ ] Add timestamp/nonce replay protection to `relay-backend` `decrypt_relay_request`
- [ ] Zeroize FFI session key buffers in `relay-sdk` (use already-vendored `zeroize` crate)
- [ ] Audit LRU pointer lifetime (not `.unwrap()` itself) in `relay-xdp-ebpf` packet handlers
- [ ] Replace `admin_cidr: 0.0.0.0/0` default in `infra/Pulumi.production.yaml`; add Makefile preflight
- [ ] Harden `relay-xdp.service.j2` with `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`
- [ ] Tighten `relay_*_get_stats` FFI contract (lower priority - documentation + cbindgen `static_assert`)

## Verified Findings (audit corrections)

Reading the actual source corrected three items the audit agents flagged:

| Original claim | Reality | Action |
|----------------|---------|--------|
| eBPF `.unwrap()` after `get_ptr_mut` is unsafe | Pattern is `is_none() -> return; unwrap()` synchronously; no LRU race window between the two | Re-scope to "pointer-lifetime audit" - check that no handler holds the raw pointer across a second map operation that could trigger eviction |
| `relay_*_get_stats(out: *mut T)` is a buffer overflow | `RelayClientStats` / `RelayServerStats` are `#[repr(C)]` and cbindgen emits the layout into `relay_generated.h`; correct C callers compile against the header. Risk is contract drift, not memory corruption | Lower to Medium; add `static_assert(sizeof(...) == N)` in header and a Rust `const _` size check |
| `systemd` unit has no capability bounding | Unit already has `AmbientCapabilities` and `CapabilityBoundingSet` for `CAP_NET_ADMIN CAP_BPF CAP_SYS_ADMIN` | Re-scope to "filesystem + privilege hardening" only |

The other Critical items (replay protection, FFI zeroize, prod SSH CIDR, service unit fs-hardening) reproduced exactly as described.

## Work Planned

### 1. Backend replay protection (`relay-backend/src/handlers.rs:146`)

Current `decrypt_relay_request` calls `SalsaBox::decrypt_in_place_detached` and accepts any valid AEAD ciphertext. crypto_box guarantees integrity but not freshness; an attacker who captures one valid request can replay it indefinitely.

Approach:

- Cache `(relay_index, nonce_bytes)` for `2 * RELAY_UPDATE_PERIOD_SEC` (default `2s -> 4s` window). Use a `parking_lot::Mutex<HashMap<u64, lru::LruCache<[u8; 24], ()>>>` keyed by relay index. LRU cap per relay = 1024 entries.
- Reject when `(relay_index, nonce)` already seen.
- Add a freshness check inside the decrypted payload: `RelayUpdateRequest` already carries `current_time` (see `relay_update.rs`). Reject when `|req.current_time - state.now| > 30s`.
- Increment two new counters: `relay_update_replay_rejected`, `relay_update_clock_skew_rejected`.

Files:

- `relay-backend/src/handlers.rs` (decrypt path, counters)
- `relay-backend/src/state.rs` (add `nonce_cache: Arc<Mutex<...>>` to `AppState`)
- `relay-backend/src/relay_update.rs` (add clock-skew check after parse)
- `relay-backend/src/metrics.rs` (export the two new counters)

Tests (in `relay-backend/tests/e2e_encrypted.rs`):

- Replay same encrypted payload twice -> second is rejected
- Stale `current_time` (now - 60s) -> rejected
- Cache eviction past window -> replay accepted again (documents window behavior)

### 2. SDK FFI key zeroization (`relay-sdk/src/ffi/mod.rs`)

Two call sites copy a 32-byte secret into a stack buffer that the compiler may not memset on drop:

- `relay_client_open_session` line 110: `let mut key = [0u8; SESSION_PRIVATE_KEY_BYTES];`
- `relay_server_register_session` (~line 282 per audit): same pattern

`zeroize = "1"` with feature `derive` is already in `relay-sdk/Cargo.toml:27`.

Approach:

- Replace `let mut key = [0u8; SESSION_PRIVATE_KEY_BYTES]` with `let mut key = zeroize::Zeroizing::new([0u8; SESSION_PRIVATE_KEY_BYTES]);`.
- The `Zeroizing` newtype derefs to `[u8; 32]` for the `copy_from_slice` and call into `open_session`. Drop-on-scope-exit memsets.
- Audit `client::ClientInner::open_session` and `server::ServerInner::register_session` for whether they retain the key in a struct field; if so, store as `Zeroizing<[u8; 32]>` there too.

Tests:

- Unit test in `relay-sdk/src/ffi/mod.rs` test module that calls the function and asserts no obvious in-stack key residue is visible (best-effort - this is hard to guarantee in Rust, the real protection is the `drop_in_place` Zeroize provides).
- Compile-time check: `static_assertions::assert_impl_all!(Zeroizing<[u8; 32]>: Zeroize)` already covered by the crate's own tests.

### 3. eBPF pointer-lifetime audit (`relay-xdp-ebpf/src/main.rs`)

Confirmed call sites where a raw pointer from `session_map.get_ptr_mut`/`whitelist_map.get_ptr_mut` is held:

- `session_map.get_ptr_mut`: lines 1193, 1277, 1361, 1451, 1520, 1599, 1677
- `whitelist_map.get_ptr` / `get_ptr_mut`: lines 612, 1898

For each: trace from `unwrap()` to last `(*ptr)` access. Verify no intermediate operation can trigger LRU eviction:

- Any second `*_map.insert()` on the same map.
- Any kfunc call that the verifier may treat as a sequence point.
- Any code path that yields back to the verifier-tracked stack frame in a way that invalidates the pointer.

If found, copy the value to a stack `let snapshot = *ptr;` immediately after `unwrap()`, mutate `snapshot`, then write back via `*ptr = snapshot` only at the end. This pattern is already used in some handlers - codify it as the standard.

Deliverable: short note in `docs/decisions/` (or extend an existing ADR) with the rule "do not hold a raw map pointer across another mutation of the same map" plus a checklist comment in each handler.

No automated test (verifier is the test). Manual review + `cargo run -p xtask -- build-ebpf-rust` must succeed unchanged.

### 4. Pulumi production CIDR + Makefile preflight

Files:

- `infra/Pulumi.production.yaml`: change `admin_cidr: 0.0.0.0/0` to a placeholder that fails fast: `admin_cidr: REQUIRED_OVERRIDE`. Pulumi config validation in `infra/config.py` currently parses `admin_cidr`; extend it to reject the placeholder string with a clear error.
- `Makefile`: insert preflight before `pulumi up --stack production --yes`:
  ```
  @python infra/inventory_gen.py --stack production --check-admin-cidr || \
      (echo "ERROR: production admin_cidr is 0.0.0.0/0 or REQUIRED_OVERRIDE - refusing to deploy" && exit 1)
  ```
  Or implement the check as a small script in `infra/preflight.py`.
- `infra/Pulumi.staging.yaml`: keep `0.0.0.0/0` (intentional for CI/staging), but document why in a comment.

Tests:

- `infra/test_inventory_gen.py`: add a case asserting the preflight rejects `0.0.0.0/0` and the placeholder string for production.

### 5. systemd unit fs-hardening (`ansible/roles/relay-xdp/templates/relay-xdp.service.j2`)

Current unit has capability bounding but the process can still write anywhere root can. Add:

```
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=false   # we DO load relay_module.ko via a separate unit, but leave this false for safety; relay-xdp itself does not load modules
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
RestrictRealtime=true
ReadWritePaths={{ relay_data_dir }} /sys/fs/bpf
```

Notes:

- `ProtectSystem=strict` makes `/usr` `/boot` `/etc` read-only. relay-xdp only writes to `{{ relay_data_dir }}` (logs/state) and `/sys/fs/bpf` (pin path). Both are listed in `ReadWritePaths`.
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX` would be ideal but XDP attach via `AF_NETLINK` and BPF syscall via `AF_UNIX`-equivalent need verification before enabling - defer.
- The kernel-module loader (`relay-module.service`) is a separate unit and can keep its current privileges.

Tests:

- Deploy to staging first; verify `systemctl status relay-xdp` is `active (running)` and counters tick on an end-to-end packet flow via `tests/compose-test.sh`-equivalent staging sanity checks.

### 6. Stats-FFI contract tightening (downgraded to Medium)

- Add to `relay-sdk/src/ffi/mod.rs`:
  ```rust
  const _: () = assert!(core::mem::size_of::<RelayClientStats>() == 64);
  const _: () = assert!(core::mem::size_of::<RelayServerStats>() == 64);
  ```
  (Use real sizes from the structs.)
- Update `cbindgen.toml` `after_includes` to emit `_Static_assert(sizeof(relay_client_stats_t) == 64, ...);` so C callers fail at compile time on drift.
- Document in the FFI doc comment that callers MUST `#include "relay_generated.h"` and pass `&(relay_client_stats_t){0}` rather than ad-hoc buffers.

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Use `lru::LruCache` per relay for nonce cache instead of a single global cache | Bounded per relay; avoids one chatty/compromised relay evicting everyone else's nonces | N/A (operational) |
| Use `Zeroizing` newtype rather than `drop_in_place` + manual memset | Idiomatic, panic-safe, already a workspace dep | N/A |
| Re-scope eBPF audit from "remove unwrap" to "pointer-lifetime rule" | The unwrap pattern is correct - the real risk is holding pointers across map mutations | Capture as a short ADR if pattern hardens into a rule |
| Keep `0.0.0.0/0` for staging, fail-closed for production | Staging is exercised by CI runners with rotating IPs | N/A |
| Defer `RestrictAddressFamilies` | XDP/BPF socket family requirements need empirical verification on the target kernel | Revisit in Phase 2 |

## Tests Planned

| Test | Module | Type | Purpose |
|------|--------|------|---------|
| `replay_rejected_within_window` | `relay-backend/tests/e2e_encrypted.rs` | Integration | Replay attack rejected, counter incremented |
| `clock_skew_rejected` | `relay-backend/tests/e2e_encrypted.rs` | Integration | Stale `current_time` rejected |
| `nonce_cache_eviction_replay_accepted` | `relay-backend/tests/e2e_encrypted.rs` | Integration | Documents window behavior |
| `ffi_session_key_zeroized_on_scope_exit` | `relay-sdk` (best-effort) | Unit | Smoke test that `Zeroizing` is applied |
| `pulumi_preflight_rejects_default_cidr` | `infra/test_inventory_gen.py` | Unit | Prod deploy fails fast |
| `relay_xdp_service_starts_with_hardening` | manual + staging | E2E | Service still starts after fs-hardening |

## Issues / Risks

| Issue | Mitigation | Blocking |
|-------|------------|----------|
| Nonce cache memory growth if attackers spoof many `relay_id` values pre-decrypt | Look up `relay_index` BEFORE caching; only cache for known relays | No |
| `ProtectSystem=strict` may hide a path relay-xdp currently writes that is undocumented | Stage first; collect failures via journalctl; expand `ReadWritePaths` as needed | No |
| Pinning the prod CIDR placeholder can break operators following old runbook | Update `infra/README.md` and Makefile error to point at the new variable | No |
| eBPF pointer-lifetime "audit" produces no diff if everything is already correct | Capture the rule + checklist as documentation regardless | No |

## Sequencing

Two parallel tracks over ~1 week:

```
Day 1-2:  (Backend) replay + clock skew + tests
          (Infra)   Pulumi placeholder + Makefile preflight + test
Day 2-3:  (SDK)     Zeroize FFI keys + tests
          (Ops)     systemd hardening on staging + sanity check
Day 4:    (eBPF)    pointer-lifetime audit + ADR draft + verifier rebuild
Day 5:    Cross-cutting review, merge to master, deploy staging
```

## Next Steps (after this plan is approved)

1. **High:** Open one branch per work item (`fix/backend-replay`, `fix/sdk-ffi-zeroize`, `chore/infra-prod-cidr-preflight`, `chore/relay-xdp-systemd-hardening`, `audit/ebpf-ptr-lifetime`).
2. **High:** Land Backend replay and Infra preflight first - smallest blast radius, biggest immediate-risk reduction.
3. **Medium:** Stage and soak the systemd hardening on staging for at least 24 hours before production rollout.
4. **Medium:** After Phase 1 ships, write Phase 2 plan covering: pittle/chonkle parity tests, `const _` size assertions in `relay-xdp-common`, optimizer-thread `catch_unwind`, Redis TTL.

## Files Changed

| Status | File |
|--------|------|
| A      | `docs/sessions/2026-05-04-phase-1-critical-fixes-plan.md` |