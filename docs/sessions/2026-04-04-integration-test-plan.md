# Session Summary: Integration Test Plan for relay-xdp <-> relay-backend

**Date:** 2026-04-04  
**Duration:** ~1 hour (~6 interactions)  
**Focus Area:** Cross-crate integration testing between relay-xdp and relay-backend

## Objectives

- [x] Analyze codebase to understand relay-xdp <-> relay-backend interaction points
- [x] Identify gaps in existing test coverage
- [x] Design comprehensive integration test plan covering wire format, HTTP handler, response parsing, and full pipeline
- [x] Implement the integration tests

## Work Completed

### Codebase Analysis

- Reviewed the full communication flow: relay-xdp sends HTTP POST `/relay_update` every 1s, relay-backend parses request and feeds into `RelayManager`, returns binary response that relay-xdp parses to update BPF state and relay ping set.
- Identified the **critical address encoding mismatch** between the two crates:
  - relay-xdp `Writer::write_address_ipv4()` writes `write_uint32(addr.to_be())` - stores BE address as LE bytes (reversed octets)
  - relay-backend `SimpleWriter::write_address()` writes raw IP octets directly
  - Response path is compatible: `SimpleWriter` raw octets = network order, relay-xdp `Reader::read_uint32()` reads as LE then `u32::from_be()` produces correct host-order value
- Documented in `ARCHITECTURE.md` section "Wire Format: Address Encoding Mismatch"

### Existing Test Coverage Audit

| Test File | Crate | Count | What It Tests | Gap |
|-----------|-------|-------|---------------|-----|
| `relay-backend/tests/integration_xdp.rs` | relay-backend | 30 | Wire format, optimizer, relay manager, cost matrix, route matrix | Manually builds bytes - does NOT use relay-xdp's real `Writer` |
| `relay-backend/tests/helpers/mod.rs` | relay-backend | - | Helper functions wrapping relay-backend modules | Only uses relay-backend's own types |
| `relay-xdp/tests/func_parity.rs` | relay-xdp | 8 (`#[ignore]`) | Config, update response parsing, crypto, mock HTTP backend | Uses relay-xdp's `Writer` to build mock responses - does NOT use relay-backend's `RelayUpdateResponse::write()` |
| `relay-xdp/tests/wire_compat.rs` | relay-xdp | 15 | Struct sizes, field offsets, constants, crypto roundtrips | Tests layout only, not cross-crate encoding compatibility |

**Key gap**: Neither test suite uses the **real encoder from the other crate**. If one side changes wire format, the other's tests still pass.

### Integration Test Plan Design

Designed 5 new test files with ~35 total tests across 5 categories:

1. **Cross-crate wire format** (`relay-backend/tests/cross_crate_wire.rs`, ~10 tests)
   - relay-xdp Writer builds request -> relay-backend SimpleReader parses
   - relay-backend SimpleWriter builds response -> relay-xdp Reader parses
   - Byte-level address encoding compatibility assertions

2. **HTTP handler integration** (`relay-backend/tests/http_handler_integration.rs`, ~6 tests)
   - Real axum Router with populated `RelayData`
   - `tower::ServiceExt::oneshot()` for in-process HTTP testing
   - Valid request, unknown relay, size validation, multi-relay cost computation

3. **Backend response integration** (`relay-xdp/tests/backend_response_integration.rs`, ~5 tests)
   - `RelayUpdateResponse::write()` real output -> `MainThread::parse_update_response()` real parsing
   - Relay set delta computation across successive responses
   - Error cases: wrong public key, zero relays

4. **Full pipeline** (`relay-backend/tests/pipeline_integration.rs`, ~3 tests)
   - relay-xdp Writer builds 4 relay updates -> relay-backend parses -> RelayManager -> costs -> optimizer -> route matrix roundtrip
   - Indirect route discovery verification
   - Shutting-down relay exclusion

5. **Encrypted request** (`relay-backend/tests/e2e_encrypted.rs`, ~11 tests)
   - End-to-end NaCl crypto_box encryption/decryption using real keypairs
   - relay-xdp Writer builds request, encrypts with SalsaBox (relay_sk + backend_pk)
   - relay-backend handler decrypts with (relay_pk + backend_sk), parses, returns RelayUpdateResponse
   - Response parsed with relay-xdp Reader to verify cross-crate compatibility
   - Negative cases: wrong key, tampered MAC, tampered ciphertext, tampered nonce, truncated body, unknown relay
   - Plaintext fallback when no crypto keys configured (legacy gateway proxy mode)
   - Multiple sequential encrypted requests from same relay

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Add cross-crate dev-dependencies (relay-xdp in relay-backend and vice versa) | Required to use real encoders from both sides in tests; both are workspace members so no circular dependency issue | N/A |
| Keep existing `func_parity.rs` tests alongside new tests | func_parity tests crypto (NaCl encrypt/decrypt) and full HTTP cycle with encryption - not covered by new tests | N/A |
| Use `tower::ServiceExt::oneshot()` for HTTP handler tests | Avoids TCP socket overhead, tests handler logic directly without network layer | N/A |
| Place cross-crate wire tests in relay-backend | relay-backend already has 30 integration tests in `integration_xdp.rs` with helpers infrastructure; natural extension | N/A |
| New tests are NOT `#[ignore]` (unlike func_parity) | These should run in normal `cargo test` - no special env vars or root required | N/A |

## Tests Added/Modified

All 35 integration tests implemented and passing.

### Planned Test Summary

| Test File | Tests | Type | Status |
|-----------|-------|------|--------|
| `relay-backend/tests/cross_crate_wire.rs` | 10 | Integration (cross-crate wire format) | Done |
| `relay-backend/tests/http_handler_integration.rs` | 6 | Integration (HTTP handler) | Done |
| `relay-xdp/tests/backend_response_integration.rs` | 5 | Integration (response parsing) | Done |
| `relay-backend/tests/pipeline_integration.rs` | 3 | Integration (full data pipeline) | Done |
| `relay-backend/tests/e2e_encrypted.rs` | 11 | Integration (NaCl crypto_box encrypt/decrypt) | Done |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| Address encoding mismatch between crates | Documented in ARCHITECTURE.md; response path is compatible. Request path now supports both direct mode (relay-backend decrypts NaCl box) and legacy gateway proxy mode. Tests verify byte-level compatibility. | No |
| `/relay_update` handler returns empty 200 (no response body) | **Resolved**: handler now builds and returns a full `RelayUpdateResponse` body in both direct and legacy modes. Added `MagicRotator` for magic bytes and ping key rotation. | No |
| `func_parity.rs` tests use `#[ignore]` and modify env vars | New tests will NOT use env vars or `#[ignore]` - they directly construct Config structs and pass them in. func_parity tests remain separate for crypto testing. | No |

## Next Steps

1. ~~**High:** Implement `relay-backend/tests/cross_crate_wire.rs`~~ Done (10 tests)
2. ~~**High:** Implement `relay-backend/tests/http_handler_integration.rs`~~ Done (6 tests)
3. ~~**Medium:** Implement `relay-xdp/tests/backend_response_integration.rs`~~ Done (5 tests)
4. ~~**Medium:** Implement `relay-backend/tests/pipeline_integration.rs`~~ Done (3 tests)
5. ~~**Low:** Consider extending `/relay_update` handler to return `RelayUpdateResponse` body (currently returns empty 200) for direct relay-xdp -> relay-backend communication without gateway proxy~~ Done

## Files Changed

| Status | File |
|--------|------|
| M | `relay-backend/Cargo.toml` (added relay-xdp, relay-xdp-common, tower, http-body-util, crypto_box, getrandom to dev-dependencies) |
| M | `relay-xdp/Cargo.toml` (added relay-backend to dev-dependencies) |
| A | `relay-backend/tests/cross_crate_wire.rs` (10 tests) |
| A | `relay-backend/tests/http_handler_integration.rs` (6 tests) |
| A | `relay-backend/tests/pipeline_integration.rs` (3 tests) |
| A | `relay-backend/tests/e2e_encrypted.rs` (11 tests) |
| A | `relay-xdp/tests/backend_response_integration.rs` (5 tests) |

## Reference

- Wire format details: [`relay-backend/ARCHITECTURE.md` - Interaction with relay-xdp](../relay-backend/ARCHITECTURE.md#interaction-with-relay-xdp)
- Request format: [`relay-backend/ARCHITECTURE.md` - RelayUpdateRequest](../relay-backend/ARCHITECTURE.md#51-relayupdaterequest---sent-by-relay-xdp)
- Response format: [`relay-backend/ARCHITECTURE.md` - RelayUpdateResponse](../relay-backend/ARCHITECTURE.md#52-relayupdateresponse---returned-by-relay-backend)
- Address encoding mismatch: [`relay-backend/ARCHITECTURE.md` - Wire Format](../relay-backend/ARCHITECTURE.md#wire-format-address-encoding-mismatch)
