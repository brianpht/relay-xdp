# Session Summary: RelayData Loader Plan

**Date:** 2026-04-04  
**Duration:** ~30 min (~4 interactions)  
**Focus Area:** relay-backend RelayData loader design

## Objectives

- [x] Analyze Go original's RelayData loading mechanism (Load -> Transform -> Watch)
- [x] Design RelayData JSON loader plan for relay-backend

## Work Completed

### Go Original Analysis

Analyzed the Go original's 3-phase relay data loading:

1. **Load phase** (`Service.LoadDatabase()`):
   - Reads `DATABASE_PATH` env var (default `database.bin`)
   - Format: gzip + Go gob encoding (Go-specific, NOT portable to Rust)
   - Calls `Fixup()` to rebuild derived maps, `Validate()` for consistency
   - `GenerateRelaySecretKeys()` derives per-relay shared secrets from relay PK + backend SK

2. **Transform phase** (`generateRelayData()`):
   - Converts raw database into denormalized, read-optimized `RelayData` struct
   - **Critical**: sorts relays by name (line 683) for consistent ordering across all instances
   - Builds parallel arrays: ids, addresses, names, latitudes, longitudes, datacenter_ids, prices
   - Computes `RelayIdToIndex` reverse map, `DestRelays` (relay is dest for >= 1 live buyer)
   - Stores `DatabaseBinFile` (raw binary) for passthrough to other instances via RouteMatrix

3. **Watch phase** (`watchDatabase()`):
   - Background goroutine polling every `DATABASE_SYNC_INTERVAL` (default 1 min)
   - Supports Google Cloud Storage (`DATABASE_URL`) or local disk
   - Atomic swap via `databaseMutex.Lock()`
   - **Bug found**: lines 800/806 and 840/846 validate/transform the OLD database instead of new one

### RelayData Loader Plan (JSON format)

Key design decisions for Rust implementation:

| Aspect | Go original | Rust plan | Rationale |
|--------|-------------|-----------|-----------|
| Format | gzip + Go gob | JSON | Go gob is Go-specific; JSON is human-readable, serde_json already a dep |
| Secret keys | `GenerateRelaySecretKeys()` per relay | Not needed | relay-xdp derives its own via `derive_secret_key()`; backend only needs PK for decrypt |
| Sort order | Sort by relay name | Same | Required for consistent ordering across instances |
| Hot reload | `watchDatabase()` goroutine | Phase 2 | MVP: load at startup only |
| Validate | `database.Validate()` | Basic checks | No duplicate address/name, address parseable |
| DatabaseBinFile | Raw binary passthrough | Empty vec | Not using Go gob; server_backend doesn't need it |
| DestRelays | Computed from live buyers | JSON field | No buyer system in Rust yet |

JSON schema:

```json
{
  "relays": [
    {
      "name": "relay-dallas",
      "address": "10.0.0.1:40000",
      "latitude": 32.78,
      "longitude": -96.80,
      "datacenter_id": 1,
      "price": 0,
      "dest": true,
      "public_key": "base64encoded32bytes=="
    }
  ]
}
```

Implementation steps:

1. ~~`RelayData::load_json(path)` in `database.rs` - parse, sort by name, build vecs, compute ids~~ **Done**
2. ~~`relay_data_file: Option<String>` in `config.rs` from env var `RELAY_DATA_FILE`~~ **Done**
3. ~~Wire into `main.rs` line 39-40: load if path set, else `empty()`~~ **Done**
4. ~~Unit tests: valid load, sort order, duplicate detection, invalid address, public keys, empty array~~ **Done (13 tests)**
5. ~~Integration test: JSON fixture -> AppState -> encrypted request -> 200 OK~~ **Done (6 tests)**
6. ~~Update docs: ARCHITECTURE.md config table, startup flow, shared state~~ **Done**

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Use JSON format instead of Go gob binary | Go gob is Go-specific, not portable. JSON is human-readable, testable, serde_json already a dependency. Data is small (hundreds of relays). | N/A |
| Sort relays by name after loading | Matches Go original behavior. Ensures consistent relay ordering across all instances (deterministic relay_id_to_index mapping). | N/A |
| Skip hot reload for MVP | Adds complexity (`Arc<RwLock<Arc<RelayData>>>` or `arc-swap`). Load-at-startup sufficient for initial deployment. Add later. | N/A |
| Skip relay secret keys in relay-backend | Go generates per-relay shared secrets for route/continue tokens. In Rust, relay-xdp derives its own via `derive_secret_key()`. relay-backend only needs public keys for NaCl box decrypt. `test_token` is `[0u8; 111]` (relay-xdp skips it). | N/A |
| Keep `DatabaseBinFile` empty | Opaque passthrough in RouteMatrix for Go relay_backend instances. Rust doesn't use Go gob. Field passes through as empty bytes - safe because server_backend doesn't depend on it for routing. | N/A |

## Tests Added/Modified

13 unit tests in `relay-backend/src/database.rs`:

| Test | Verifies |
|------|----------|
| `test_load_valid_json` | Full parse, sort order, all fields, relay_id_to_index, default public keys |
| `test_load_sort_order` | Relays sorted alphabetically by name |
| `test_load_duplicate_name_rejected` | Duplicate relay name returns error |
| `test_load_duplicate_address_rejected` | Duplicate relay address returns error |
| `test_load_invalid_address_rejected` | Unparseable address returns error |
| `test_load_empty_relays` | Empty array produces empty RelayData |
| `test_load_public_keys` | Base64 public keys decoded correctly, missing key defaults to zeros |
| `test_load_invalid_public_key_length` | Non-32-byte key rejected |
| `test_load_invalid_public_key_base64` | Invalid base64 rejected |
| `test_relay_ids_computed_from_address` | relay_id matches FNV-1a of address string |
| `test_load_invalid_json` | Malformed JSON returns error |
| `test_load_json_file` | File I/O round-trip (write temp file, load, verify) |
| `test_load_json_file_not_found` | Missing file returns error |

6 integration tests in `relay-backend/tests/json_loader_integration.rs`:

| Test | Verifies |
|------|----------|
| `test_json_loaded_relay_encrypted_request_returns_ok` | JSON fixture -> from_json -> AppState -> encrypted POST -> 200 OK |
| `test_json_loaded_relay_encrypted_request_updates_relay_manager` | Encrypted update registers relay as active with correct session count |
| `test_json_loaded_relay_response_echoes_correct_public_key` | Response echoes correct per-relay public key from JSON for two different relays |
| `test_json_loaded_two_relays_see_each_other_as_peers` | Second relay's response lists first as active peer with correct address/id |
| `test_json_loaded_relay_wrong_key_returns_bad_request` | Wrong relay secret key fails decryption -> 400 |
| `test_json_file_load_then_encrypted_request` | load_json() from temp file -> encrypted POST -> 200 OK + valid response |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| Go gob format not portable to Rust | Use JSON instead. Small data set (hundreds of relays) makes JSON parsing overhead negligible. | No |
| Go `watchDatabase()` has bug on lines 800/806, 840/846 | Validates/transforms old database instead of new. Noted for reference - Rust implementation will avoid this. | No |

## Next Steps

1. ~~**High:** Implement `RelayData::load_json()` in `relay-backend/src/database.rs`~~ **Done**
2. ~~**High:** Add `RELAY_DATA_FILE` env var to `config.rs` and wire into `main.rs`~~ **Done**
3. ~~**High:** Unit tests for JSON loader (valid, sort, duplicates, errors, public keys)~~ **Done (13 tests)**
4. ~~**Medium:** Integration test - load JSON fixture -> encrypted request -> verify response~~ **Done (6 tests)**
5. ~~**Medium:** Update docs (ARCHITECTURE.md config table, startup flow, shared state)~~ **Done**
6. **Low:** Hot reload support (Phase 2 - `arc-swap` or `RwLock` + file watcher)
7. **Low:** GCS/HTTP URL support for `RELAY_DATA_FILE` (Phase 2)

## Files Changed

| File | Change |
|------|--------|
| `relay-backend/src/database.rs` | Added `from_json()`, `load_json()`, JSON schema types, validation, 13 unit tests, `#[derive(Debug)]` |
| `relay-backend/src/config.rs` | Added `relay_data_file: Option<String>` field, reads `RELAY_DATA_FILE` env var |
| `relay-backend/src/main.rs` | Wired `RelayData::load_json()` / `empty()` based on config |
| `relay-backend/tests/http_handler_integration.rs` | Added `relay_data_file: None` to test Config |
| `relay-backend/tests/e2e_encrypted.rs` | Added `relay_data_file: None` to two test Config structs |
| `relay-backend/ARCHITECTURE.md` | Updated config table, module desc, startup flow, shared state comment |
| `relay-backend/tests/json_loader_integration.rs` | **New** - 6 integration tests: JSON fixture -> AppState -> encrypted request -> verify |

## Reference

- Go original: `Service.LoadDatabase()` -> `db.LoadDatabase()` -> `Fixup()` -> `Validate()` -> `generateRelayData()`
- Rust implementation: `relay-backend/src/database.rs` - `RelayData::load_json()` / `from_json()` / `empty()`
- relay-xdp secret key derivation: `relay-xdp/src/config.rs` `derive_secret_key()` (X25519 + BLAKE2B-512)
- Previous session: [`2026-04-04-integration-test-plan.md`](2026-04-04-integration-test-plan.md)
