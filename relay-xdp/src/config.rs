//! Configuration - read from environment variables.
//! Port of `relay_config.c`.

use anyhow::{bail, Context, Result};
use base64::Engine;
use relay_xdp_common::*;

use crate::platform;

#[allow(dead_code)]
#[derive(Debug)]
pub struct Config {
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
/// This computes the client-side session key from a key exchange:
/// 1. Compute shared secret: q = X25519(client_sk, server_pk)
/// 2. Compute rx || tx = BLAKE2B-512(q || client_pk || server_pk)
/// 3. Return rx (first 32 bytes) as the relay secret key
fn derive_secret_key(
    public_key: &[u8; 32],
    private_key: &[u8; 32],
    server_public_key: &[u8; 32],
) -> Result<[u8; 32]> {
    use blake2::digest::{Update, VariableOutput};
    use x25519_dalek::{PublicKey, StaticSecret};

    // Perform X25519 key exchange
    let client_sk = StaticSecret::from(*private_key);
    let server_pk = PublicKey::from(*server_public_key);
    let shared_secret = client_sk.diffie_hellman(&server_pk);

    // BLAKE2B-512(q || client_pk || server_pk)
    let mut hasher = blake2::Blake2bVar::new(64).expect("valid output size");
    hasher.update(shared_secret.as_bytes());
    hasher.update(public_key);
    hasher.update(server_public_key);

    let mut output = [0u8; 64];
    hasher.finalize_variable(&mut output).expect("valid output size");

    // rx = first 32 bytes
    let mut rx = [0u8; 32];
    rx.copy_from_slice(&output[..32]);
    Ok(rx)
}

pub fn read_config() -> Result<Config> {
    let relay_name = get_env("RELAY_NAME")?;
    println!("Relay name is '{relay_name}'");

    let public_addr_str = get_env("RELAY_PUBLIC_ADDRESS")?;
    let (relay_public_address, relay_port) = platform::parse_address(&public_addr_str)?;
    println!("Relay port is {relay_port}");
    println!(
        "Relay public address is {}",
        platform::format_address(relay_public_address, relay_port)
    );

    let relay_internal_address = match std::env::var("RELAY_INTERNAL_ADDRESS") {
        Ok(s) if !s.is_empty() => {
            let (addr, _) = platform::parse_address(&s)?;
            println!(
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
    println!("Relay public key is {relay_public_key_str}");

    let relay_private_key_str = get_env("RELAY_PRIVATE_KEY")?;
    let relay_private_key: [u8; RELAY_PRIVATE_KEY_BYTES] =
        decode_base64_key(&relay_private_key_str).context("invalid relay private key")?;
    println!(
        "Relay private key is {}...",
        &relay_private_key_str[..relay_private_key_str.len().min(4)]
    );

    let relay_backend_public_key_str = get_env("RELAY_BACKEND_PUBLIC_KEY")?;
    let relay_backend_public_key: [u8; RELAY_BACKEND_PUBLIC_KEY_BYTES] =
        decode_base64_key(&relay_backend_public_key_str)
            .context("invalid relay backend public key")?;
    println!("Relay backend public key is {relay_backend_public_key_str}");

    let relay_secret_key =
        derive_secret_key(&relay_public_key, &relay_private_key, &relay_backend_public_key)?;

    let relay_backend_url = get_env("RELAY_BACKEND_URL")?;
    println!("Relay backend url is {relay_backend_url}");

    let (use_gateway_ethernet_address, gateway_ethernet_address) =
        match std::env::var("RELAY_GATEWAY_ETHERNET_ADDRESS") {
            Ok(s) if !s.is_empty() => {
                println!("Relay gateway ethernet address is '{s}'");
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() != RELAY_ETHERNET_ADDRESS_BYTES {
                    bail!("invalid RELAY_GATEWAY_ETHERNET_ADDRESS");
                }
                let mut addr = [0u8; RELAY_ETHERNET_ADDRESS_BYTES];
                for (i, part) in parts.iter().enumerate() {
                    addr[i] = u8::from_str_radix(part, 16)
                        .context("invalid hex in ethernet address")?;
                }
                println!(
                    "Parsed to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
                );
                (true, addr)
            }
            _ => (false, [0u8; RELAY_ETHERNET_ADDRESS_BYTES]),
        };

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
    })
}

