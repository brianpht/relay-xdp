//! Configuration - read from environment variables.
//! Port of `relay_config.c`.

use anyhow::{bail, Context, Result};
use base64::Engine;
use relay_xdp_common::*;

use crate::platform;

#[derive(Debug)]
pub struct Config {
    /// Used in logging and tests; will be needed for Prometheus labels.
    #[allow(dead_code)]
    pub relay_name: String,
    pub relay_port: u16,
    /// Host byte order
    pub relay_public_address: u32,
    /// Host byte order
    pub relay_internal_address: u32,
    pub relay_public_key: [u8; RELAY_PUBLIC_KEY_BYTES],
    pub relay_private_key: [u8; RELAY_PRIVATE_KEY_BYTES],
    pub relay_backend_public_key: [u8; RELAY_BACKEND_PUBLIC_KEY_BYTES],
    pub relay_secret_key: [u8; RELAY_SECRET_KEY_BYTES],
    pub gateway_ethernet_address: [u8; RELAY_ETHERNET_ADDRESS_BYTES],
    pub use_gateway_ethernet_address: bool,
    pub relay_backend_url: String,
    pub dedicated: bool,
}

fn get_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} not set"))
}

fn decode_base64_key<const N: usize>(value: &str) -> Result<[u8; N]> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .context("base64 decode failed")?;
    if decoded.len() != N {
        bail!("expected {N} bytes, got {}", decoded.len());
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

/// Derive secret key using crypto_kx_client_session_keys equivalent.
///
/// Delegates to relay_sdk::crypto::derive_relay_session_key which is the
/// canonical shared implementation used by both relay-xdp and relay-backend.
///
/// Parameters (relay side):
///   - public_key: relay's own X25519 public key
///   - private_key: relay's own X25519 private key
///   - server_public_key: backend's X25519 public key
///
/// Returns rx = BLAKE2b-512(X25519(relay_sk, backend_pk) || relay_pk || backend_pk)[..32]
fn derive_secret_key(
    public_key: &[u8; 32],
    private_key: &[u8; 32],
    server_public_key: &[u8; 32],
) -> Result<[u8; 32]> {
    // relay side: my_sk=relay_private_key, their_pk=backend_pk,
    //             relay_pk=relay_public_key, backend_pk=backend_public_key
    Ok(relay_sdk::crypto::derive_relay_session_key(
        private_key,
        server_public_key,
        public_key,
        server_public_key,
    ))
}

pub fn read_config() -> Result<Config> {
    let relay_name = get_env("RELAY_NAME")?;
    log::info!("Relay name is '{relay_name}'");

    let public_addr_str = get_env("RELAY_PUBLIC_ADDRESS")?;
    let (relay_public_address, relay_port) = platform::parse_address(&public_addr_str)?;
    log::info!("Relay port is {relay_port}");
    log::info!(
        "Relay public address is {}",
        platform::format_address(relay_public_address, relay_port)
    );

    let relay_internal_address = match std::env::var("RELAY_INTERNAL_ADDRESS") {
        Ok(s) if !s.is_empty() => {
            let (addr, _) = platform::parse_address(&s)?;
            log::info!(
                "Relay internal address is {}",
                platform::format_address(addr, relay_port)
            );
            addr
        }
        _ => relay_public_address,
    };

    let relay_public_key_str = get_env("RELAY_PUBLIC_KEY")?;
    let relay_public_key: [u8; RELAY_PUBLIC_KEY_BYTES] =
        decode_base64_key(&relay_public_key_str).context("invalid relay public key")?;
    log::info!("Relay public key is {relay_public_key_str}");

    let relay_private_key_str = get_env("RELAY_PRIVATE_KEY")?;
    let relay_private_key: [u8; RELAY_PRIVATE_KEY_BYTES] =
        decode_base64_key(&relay_private_key_str).context("invalid relay private key")?;
    log::info!(
        "Relay private key is {}...",
        &relay_private_key_str[..relay_private_key_str.len().min(4)]
    );

    let relay_backend_public_key_str = get_env("RELAY_BACKEND_PUBLIC_KEY")?;
    let relay_backend_public_key: [u8; RELAY_BACKEND_PUBLIC_KEY_BYTES] =
        decode_base64_key(&relay_backend_public_key_str)
            .context("invalid relay backend public key")?;
    log::info!("Relay backend public key is {relay_backend_public_key_str}");

    let relay_secret_key = derive_secret_key(
        &relay_public_key,
        &relay_private_key,
        &relay_backend_public_key,
    )?;

    let relay_backend_url = get_env("RELAY_BACKEND_URL")?;
    log::info!("Relay backend url is {relay_backend_url}");

    let (use_gateway_ethernet_address, gateway_ethernet_address) =
        match std::env::var("RELAY_GATEWAY_ETHERNET_ADDRESS") {
            Ok(s) if !s.is_empty() => {
                log::info!("Relay gateway ethernet address is '{s}'");
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() != RELAY_ETHERNET_ADDRESS_BYTES {
                    bail!("invalid RELAY_GATEWAY_ETHERNET_ADDRESS");
                }
                let mut addr = [0u8; RELAY_ETHERNET_ADDRESS_BYTES];
                for (i, part) in parts.iter().enumerate() {
                    addr[i] =
                        u8::from_str_radix(part, 16).context("invalid hex in ethernet address")?;
                }
                log::info!(
                    "Parsed to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    addr[0],
                    addr[1],
                    addr[2],
                    addr[3],
                    addr[4],
                    addr[5]
                );
                (true, addr)
            }
            _ => (false, [0u8; RELAY_ETHERNET_ADDRESS_BYTES]),
        };

    let dedicated = std::env::var("RELAY_DEDICATED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if dedicated {
        log::info!("Relay dedicated mode is ENABLED");
    }

    Ok(Config {
        relay_name,
        relay_port,
        relay_public_address,
        relay_internal_address,
        relay_public_key,
        relay_private_key,
        relay_backend_public_key,
        relay_secret_key,
        gateway_ethernet_address,
        use_gateway_ethernet_address,
        relay_backend_url,
        dedicated,
    })
}
