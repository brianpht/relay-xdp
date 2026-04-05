//! Relay database loader.
//! Port of the relay data loading from `modules/common/service.go`.
//!
//! Loads relay configuration from a JSON file instead of Go's gzip+gob binary.
//! JSON schema:
//! ```json
//! {
//!   "relays": [
//!     {
//!       "name": "relay-dallas",
//!       "address": "10.0.0.1:40000",
//!       "latitude": 32.78,
//!       "longitude": -96.80,
//!       "datacenter_id": 1,
//!       "price": 0,
//!       "dest": true,
//!       "public_key": "base64encoded32bytes=="
//!     }
//!   ]
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::net::SocketAddrV4;
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::Deserialize;

use crate::relay_update::relay_id;

/// JSON schema for the relay data file.
#[derive(Deserialize)]
struct RelayDataJson {
    relays: Vec<RelayEntryJson>,
}

/// A single relay entry in the JSON file.
#[derive(Deserialize)]
struct RelayEntryJson {
    name: String,
    address: String,
    #[serde(default)]
    latitude: f32,
    #[serde(default)]
    longitude: f32,
    #[serde(default)]
    datacenter_id: u64,
    #[serde(default)]
    price: u8,
    #[serde(default)]
    dest: bool,
    /// Base64-encoded 32-byte X25519 public key (optional).
    #[serde(default)]
    public_key: Option<String>,
}

/// Relay data loaded from environment / database bin file.
/// This is the relay configuration data needed by the backend.
#[derive(Debug)]
pub struct RelayData {
    pub num_relays: usize,
    pub relay_ids: Vec<u64>,
    pub relay_addresses: Vec<SocketAddrV4>,
    pub relay_names: Vec<String>,
    pub relay_latitudes: Vec<f32>,
    pub relay_longitudes: Vec<f32>,
    pub relay_datacenter_ids: Vec<u64>,
    pub relay_price: Vec<u8>,
    pub relay_id_to_index: HashMap<u64, usize>,
    pub dest_relays: Vec<bool>,
    pub database_bin_file: Vec<u8>,
    /// Per-relay public keys (32 bytes each). Used to decrypt relay-xdp update
    /// requests and echo back in responses for relay self-verification.
    pub relay_public_keys: Vec<[u8; 32]>,
}

impl RelayData {
    /// Create an empty relay data structure.
    pub fn empty() -> Self {
        RelayData {
            num_relays: 0,
            relay_ids: vec![],
            relay_addresses: vec![],
            relay_names: vec![],
            relay_latitudes: vec![],
            relay_longitudes: vec![],
            relay_datacenter_ids: vec![],
            relay_price: vec![],
            relay_id_to_index: HashMap::new(),
            dest_relays: vec![],
            database_bin_file: vec![],
            relay_public_keys: vec![],
        }
    }

    /// Load relay data from a JSON file.
    ///
    /// Relays are sorted by name after loading (matches Go original behavior)
    /// to ensure consistent ordering across all backend instances.
    pub fn load_json<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("could not read relay data file: {}", path.display()))?;
        Self::from_json(&data)
    }

    /// Parse relay data from a JSON string.
    ///
    /// Relays are sorted by name after parsing to ensure deterministic ordering.
    pub fn from_json(json: &str) -> Result<Self> {
        let parsed: RelayDataJson =
            serde_json::from_str(json).context("could not parse relay data JSON")?;

        let mut entries = parsed.relays;

        // Sort by name for consistent ordering across instances (matches Go original).
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        // Validate: no duplicate names
        let mut seen_names = HashSet::new();
        for entry in &entries {
            if !seen_names.insert(&entry.name) {
                bail!("duplicate relay name: {}", entry.name);
            }
        }

        // Validate: no duplicate addresses
        let mut seen_addresses = HashSet::new();
        for entry in &entries {
            if !seen_addresses.insert(&entry.address) {
                bail!("duplicate relay address: {}", entry.address);
            }
        }

        let num_relays = entries.len();
        let mut relay_ids = Vec::with_capacity(num_relays);
        let mut relay_addresses = Vec::with_capacity(num_relays);
        let mut relay_names = Vec::with_capacity(num_relays);
        let mut relay_latitudes = Vec::with_capacity(num_relays);
        let mut relay_longitudes = Vec::with_capacity(num_relays);
        let mut relay_datacenter_ids = Vec::with_capacity(num_relays);
        let mut relay_price = Vec::with_capacity(num_relays);
        let mut relay_id_to_index = HashMap::with_capacity(num_relays);
        let mut dest_relays = Vec::with_capacity(num_relays);
        let mut relay_public_keys = Vec::with_capacity(num_relays);

        for (i, entry) in entries.iter().enumerate() {
            let addr: SocketAddrV4 = entry.address.parse().with_context(|| {
                format!(
                    "invalid address for relay '{}': {}",
                    entry.name, entry.address
                )
            })?;

            let rid = relay_id(&entry.address);

            let pk = match &entry.public_key {
                Some(b64) => {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(b64)
                        .with_context(|| {
                            format!("invalid base64 public_key for relay '{}'", entry.name)
                        })?;
                    if bytes.len() != 32 {
                        bail!(
                            "public_key for relay '{}' must be 32 bytes, got {}",
                            entry.name,
                            bytes.len()
                        );
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                None => [0u8; 32],
            };

            relay_ids.push(rid);
            relay_addresses.push(addr);
            relay_names.push(entry.name.clone());
            relay_latitudes.push(entry.latitude);
            relay_longitudes.push(entry.longitude);
            relay_datacenter_ids.push(entry.datacenter_id);
            relay_price.push(entry.price);
            relay_id_to_index.insert(rid, i);
            dest_relays.push(entry.dest);
            relay_public_keys.push(pk);
        }

        log::info!("loaded {} relays from JSON (sorted by name)", num_relays);
        for (i, name) in relay_names.iter().enumerate() {
            log::debug!(
                "  relay[{}]: {} -> {} (id={:016x})",
                i,
                name,
                relay_addresses[i],
                relay_ids[i]
            );
        }

        Ok(RelayData {
            num_relays,
            relay_ids,
            relay_addresses,
            relay_names,
            relay_latitudes,
            relay_longitudes,
            relay_datacenter_ids,
            relay_price,
            relay_id_to_index,
            dest_relays,
            database_bin_file: vec![],
            relay_public_keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_valid_json() {
        let json = r#"{
            "relays": [
                {
                    "name": "relay-dallas",
                    "address": "10.0.0.1:40000",
                    "latitude": 32.78,
                    "longitude": -96.80,
                    "datacenter_id": 1,
                    "price": 0,
                    "dest": true
                },
                {
                    "name": "relay-amsterdam",
                    "address": "10.0.0.2:40000",
                    "latitude": 52.37,
                    "longitude": 4.90,
                    "datacenter_id": 2,
                    "price": 5,
                    "dest": false
                }
            ]
        }"#;

        let rd = RelayData::from_json(json).unwrap();
        assert_eq!(rd.num_relays, 2);

        // Sorted by name: amsterdam < dallas
        assert_eq!(rd.relay_names[0], "relay-amsterdam");
        assert_eq!(rd.relay_names[1], "relay-dallas");

        // Addresses follow sort order
        assert_eq!(rd.relay_addresses[0].to_string(), "10.0.0.2:40000");
        assert_eq!(rd.relay_addresses[1].to_string(), "10.0.0.1:40000");

        // Verify fields
        assert!((rd.relay_latitudes[0] - 52.37).abs() < 0.01);
        assert!((rd.relay_longitudes[0] - 4.90).abs() < 0.01);
        assert_eq!(rd.relay_datacenter_ids[0], 2);
        assert_eq!(rd.relay_price[0], 5);
        assert!(!rd.dest_relays[0]);

        assert!((rd.relay_latitudes[1] - 32.78).abs() < 0.01);
        assert_eq!(rd.relay_datacenter_ids[1], 1);
        assert_eq!(rd.relay_price[1], 0);
        assert!(rd.dest_relays[1]);

        // relay_id_to_index lookup
        let rid0 = rd.relay_ids[0];
        assert_eq!(rd.relay_id_to_index[&rid0], 0);
        let rid1 = rd.relay_ids[1];
        assert_eq!(rd.relay_id_to_index[&rid1], 1);

        // database_bin_file always empty for JSON
        assert!(rd.database_bin_file.is_empty());

        // public keys default to zeros when not specified
        assert_eq!(rd.relay_public_keys[0], [0u8; 32]);
    }

    #[test]
    fn test_load_sort_order() {
        let json = r#"{
            "relays": [
                { "name": "relay-z", "address": "10.0.0.3:40000" },
                { "name": "relay-a", "address": "10.0.0.1:40000" },
                { "name": "relay-m", "address": "10.0.0.2:40000" }
            ]
        }"#;

        let rd = RelayData::from_json(json).unwrap();
        assert_eq!(rd.relay_names, vec!["relay-a", "relay-m", "relay-z"]);
    }

    #[test]
    fn test_load_duplicate_name_rejected() {
        let json = r#"{
            "relays": [
                { "name": "relay-dallas", "address": "10.0.0.1:40000" },
                { "name": "relay-dallas", "address": "10.0.0.2:40000" }
            ]
        }"#;

        let err = RelayData::from_json(json).unwrap_err();
        assert!(err.to_string().contains("duplicate relay name"));
    }

    #[test]
    fn test_load_duplicate_address_rejected() {
        let json = r#"{
            "relays": [
                { "name": "relay-a", "address": "10.0.0.1:40000" },
                { "name": "relay-b", "address": "10.0.0.1:40000" }
            ]
        }"#;

        let err = RelayData::from_json(json).unwrap_err();
        assert!(err.to_string().contains("duplicate relay address"));
    }

    #[test]
    fn test_load_invalid_address_rejected() {
        let json = r#"{
            "relays": [
                { "name": "relay-bad", "address": "not-an-address" }
            ]
        }"#;

        let err = RelayData::from_json(json).unwrap_err();
        assert!(err.to_string().contains("invalid address"));
    }

    #[test]
    fn test_load_empty_relays() {
        let json = r#"{ "relays": [] }"#;

        let rd = RelayData::from_json(json).unwrap();
        assert_eq!(rd.num_relays, 0);
        assert!(rd.relay_ids.is_empty());
    }

    #[test]
    fn test_load_public_keys() {
        // 32 zero bytes, base64 encoded
        let zero_key_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        // 32 0xFF bytes, base64 encoded
        let ff_key_b64 = base64::engine::general_purpose::STANDARD.encode([0xFFu8; 32]);

        let json = format!(
            r#"{{
                "relays": [
                    {{
                        "name": "relay-a",
                        "address": "10.0.0.1:40000",
                        "public_key": "{}"
                    }},
                    {{
                        "name": "relay-b",
                        "address": "10.0.0.2:40000",
                        "public_key": "{}"
                    }},
                    {{
                        "name": "relay-c",
                        "address": "10.0.0.3:40000"
                    }}
                ]
            }}"#,
            zero_key_b64, ff_key_b64
        );

        let rd = RelayData::from_json(&json).unwrap();
        assert_eq!(rd.relay_public_keys[0], [0u8; 32]);
        assert_eq!(rd.relay_public_keys[1], [0xFFu8; 32]);
        assert_eq!(rd.relay_public_keys[2], [0u8; 32]); // default
    }

    #[test]
    fn test_load_invalid_public_key_length() {
        let short_key_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let json = format!(
            r#"{{
                "relays": [
                    {{
                        "name": "relay-a",
                        "address": "10.0.0.1:40000",
                        "public_key": "{}"
                    }}
                ]
            }}"#,
            short_key_b64
        );

        let err = RelayData::from_json(&json).unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn test_load_invalid_public_key_base64() {
        let json = r#"{
            "relays": [
                {
                    "name": "relay-a",
                    "address": "10.0.0.1:40000",
                    "public_key": "not-valid-base64!!!"
                }
            ]
        }"#;

        let err = RelayData::from_json(&json).unwrap_err();
        assert!(err.to_string().contains("invalid base64"));
    }

    #[test]
    fn test_relay_ids_computed_from_address() {
        let json = r#"{
            "relays": [
                { "name": "relay-a", "address": "10.0.0.1:40000" }
            ]
        }"#;

        let rd = RelayData::from_json(json).unwrap();
        let expected_id = relay_id("10.0.0.1:40000");
        assert_eq!(rd.relay_ids[0], expected_id);
    }

    #[test]
    fn test_load_invalid_json() {
        let json = "{ invalid json }";
        let err = RelayData::from_json(json).unwrap_err();
        assert!(err.to_string().contains("could not parse relay data JSON"));
    }

    #[test]
    fn test_load_json_file() {
        let dir = std::env::temp_dir().join("relay_data_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_relays.json");

        let json = r#"{
            "relays": [
                { "name": "relay-test", "address": "10.0.0.99:40000", "dest": true }
            ]
        }"#;
        std::fs::write(&path, json).unwrap();

        let rd = RelayData::load_json(&path).unwrap();
        assert_eq!(rd.num_relays, 1);
        assert_eq!(rd.relay_names[0], "relay-test");
        assert!(rd.dest_relays[0]);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_json_file_not_found() {
        let err = RelayData::load_json("/nonexistent/path/relays.json").unwrap_err();
        assert!(err.to_string().contains("could not read relay data file"));
    }
}
