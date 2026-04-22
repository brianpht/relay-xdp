# Session Summary: relay-sdk Code Review and Consistency Audit

**Date:** 2026-04-22
**Duration:** ~1 session (~20 interactions)
**Focus Area:** `relay-sdk` - code review, wire compatibility, consistency with `relay-xdp-common` and the relay-xdp system

## Objectives

- [x] Review entire `relay-sdk` codebase
- [x] Verify consistency with `relay-xdp-common` (constants, struct layouts, wire format)
- [x] Identify logic, security, and correctness issues
- [x] Fix identified issues (deferred - next session)
- [x] Write `tests/wire_compat.rs` (deferred)
- [x] Implement `mod ffi` (deferred)

## Work Completed

### Review: `relay-sdk`

- Read all key modules: `src/constants.rs`, `src/route/mod.rs`, `src/packets/mod.rs`, `src/tokens/mod.rs`, `src/client/mod.rs`, `src/server/mod.rs`, `src/address/mod.rs`
- Cross-referenced against `relay-xdp-common/src/lib.rs` (structs, constants, byte order conventions)
- Identified 6 issues, classified by priority

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Document issues without fixing in this session | Bugs require further confirmation before patching (especially the BE u32 byte order convention) | N/A |
| Prioritize byte order bug and unverified route confirm fixes | Both affect wire correctness and security in production paths | N/A |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| **Bug [CRITICAL] Wrong byte order in `route/mod.rs` `begin_next_route()`**: `rt.next_address.to_be_bytes()` produces the wrong octets for a BE u32 field. IP 10.0.0.1 (stored as `0x0100000A`) produces `[0x01, 0x00, 0x00, 0x0A]` instead of `[0x0A, 0x00, 0x00, 0x01]`. Fix: use `u32::from_be(rt.next_address).to_be_bytes()`. Lines 337, 342 in `src/route/mod.rs`. | **Fixed** - changed both `pending_route_next_address` octets and `to_address` in `begin_next_route()` to use `u32::from_be(rt.next_address).to_be_bytes()`. Regression test added in `confirm_pending_route_transitions_to_active`. | Yes - wrong destination IP when forwarding packets through relay |
| **Bug [SECURITY] `ROUTE_RESPONSE` confirmed without header verification**: `client/mod.rs` line 227 calls `confirm_pending_route()` immediately upon receiving packet type 2, without verifying the relay header HMAC (SHA-256). Any packet with `type=2` will transition the client to `ActiveRoute`. | **Fixed** - `process_incoming()` now decodes `RouteResponsePacket`, fetches `get_pending_route_private_key()`, and calls `read_header()` before `confirm_pending_route()`. Same fix applied to `CONTINUE_RESPONSE` using `get_current_route_private_key()`. Two security tests added: spoofed HMAC drops packet, valid HMAC confirms route. | Yes - security vulnerability |
| **Bug [PANIC] Missing bounds check in `continue_next_route()`**: `src/route/mod.rs` line 378 slices `tokens[57..num_tokens*57]` but only validates `tokens.len() >= 57`. If `tokens.len() < num_tokens*57` the slice will panic. Same issue in `begin_next_route()` line 340 with `tokens[111..num_tokens*111]`. | **Fixed** - both `begin_next_route()` and `continue_next_route()` now validate `tokens.len() >= num_tokens * ENCRYPTED_*_BYTES` before slicing; call `set_fallback_to_direct()` on failure. | Yes - panic in production |
| **Code smell: Duplicate constants** in `route/mod.rs` lines 20-24: 5 packet type constants re-declared that already exist in `constants.rs` | **Fixed** - removed the 5 re-declared constants; replaced `use crate::constants::*` with explicit imports of all used constants from `crate::constants`. | No |
| **Missing `tests/wire_compat.rs`**: File is listed in ARCHITECTURE.md but does not exist. No byte-for-byte comparison against relay-xdp golden vectors. | **Fixed** - `tests/wire_compat.rs` created with 14 tests covering: constant compatibility vs relay-xdp-common, packet size constants, ROUTE_RESPONSE/CONTINUE_RESPONSE/CLIENT_TO_SERVER/SERVER_TO_CLIENT/SESSION_PING/RELAY_PONG/SERVER_PONG/RELAY_PING/CLIENT_PONG golden bytes and roundtrips, pittle/chonkle determinism, and header HMAC cross-check vs relay-xdp-common HeaderData. | No (tech debt) |
| **`mod ffi` not yet implemented**: `src/lib.rs` line 39 still has `// pub mod ffi;` commented out. C ABI exports are not ready. | **Fixed** - `src/ffi/mod.rs` implemented with all 10 `#[no_mangle] extern "C"` functions per ARCHITECTURE.md spec: `relay_client_create/destroy/open_session/close_session/send_packet/recv_packet` and `relay_server_create/destroy/register_session/expire_session/send_packet/recv_packet`. Every entry point uses `catch_unwind`. Null pointer checks on all inputs. 13 smoke tests added covering create/destroy, null-safety, open/close, send/recv. | No (planned) |

## Tests Added/Modified

| Test Class | Method | Type | Status |
|------------|--------|------|--------|
| `route::tests` | `confirm_pending_route_transitions_to_active` | regression | Added assertion for correct `Address::V4` octets `[10,0,0,1]` and port `12345` after `confirm_pending_route` |
| `client::security_tests` | `route_response_spoofed_hmac_does_not_confirm_route` | security | Spoofed ROUTE_RESPONSE with all-zero HMAC must NOT confirm pending route |
| `client::security_tests` | `route_response_valid_hmac_confirms_route` | security | Valid ROUTE_RESPONSE with correct HMAC must confirm pending route |

## Next Steps

1. ~~**High:** Fix byte order bug in `src/route/mod.rs` `begin_next_route()` (lines 337, 342) - confirm the BE u32 convention used in relay-xdp userspace, then change `rt.next_address.to_be_bytes()` to `u32::from_be(rt.next_address).to_be_bytes()`. Add a regression test verifying `Address::V4` octets after `confirm_pending_route`.~~ **Done.**
2. ~~**High:** Fix `ClientInner::process_incoming()` (`src/client/mod.rs` line 227): add `RouteResponsePacket::decode()` + `read_header()` verification before calling `confirm_pending_route()`. If header verification fails, drop the packet without confirming the route.~~ **Done.**
3. ~~**High:** Fix potential panic in `continue_next_route()` and `begin_next_route()`: validate `tokens.len() >= num_tokens * ENCRYPTED_*_BYTES` before slicing; call `set_fallback_to_direct()` if validation fails.~~ **Done.**
4. ~~**Medium:** Remove duplicate packet type constants in `src/route/mod.rs` lines 20-24; replace with explicit `use crate::constants::{PACKET_TYPE_ROUTE_REQUEST, PACKET_TYPE_ROUTE_RESPONSE, PACKET_TYPE_CLIENT_TO_SERVER, PACKET_TYPE_SERVER_TO_CLIENT, PACKET_TYPE_CONTINUE_REQUEST};`.~~ **Done.**
5. ~~**Medium:** Create `tests/wire_compat.rs` with golden byte vectors for at least: `CLIENT_TO_SERVER`, `SERVER_TO_CLIENT`, `ROUTE_RESPONSE`, `CONTINUE_RESPONSE`. Compare against relay-xdp golden data.~~ **Done.**
6. ~~**Low:** Implement `mod ffi` per the ARCHITECTURE.md spec - `relay_client_t` / `relay_server_t` C ABI exports with `catch_unwind` on every entry point.~~ **Done.**

## Files Changed

| Status | File |
|--------|------|
| Modified | `relay-sdk/src/route/mod.rs` - fixed BE u32 byte order bug in `begin_next_route()`, fixed bounds checks in `begin_next_route()` and `continue_next_route()`, added `get_pending_route_private_key()` and `get_current_route_private_key()` methods, added regression assertion in `confirm_pending_route_transitions_to_active` test, removed 5 duplicate packet type constants and replaced `use crate::constants::*` with explicit named imports |
| Modified | `relay-sdk/src/client/mod.rs` - added HMAC verification via `read_header()` before `confirm_pending_route()` for `ROUTE_RESPONSE`, and before `confirm_continue_route()` for `CONTINUE_RESPONSE`; added `setup_pending_route` test helper and two security tests |
| Modified | `relay-sdk/src/lib.rs` - uncommented `pub mod ffi` |
| Added | `relay-sdk/src/ffi/mod.rs` - 12 `#[no_mangle] extern "C"` functions for `relay_client_t` and `relay_server_t`; all entry points use `catch_unwind` and null-check every pointer; 13 smoke tests |
| Added | `relay-sdk/tests/wire_compat.rs` - 14 tests: constant compatibility vs relay-xdp-common, packet size constants, golden byte / roundtrip tests for ROUTE_RESPONSE, CONTINUE_RESPONSE, CLIENT_TO_SERVER, SERVER_TO_CLIENT, SESSION_PING, RELAY_PONG, SERVER_PONG, RELAY_PING, CLIENT_PONG, pittle/chonkle determinism, header HMAC cross-check vs relay-xdp-common HeaderData |
