// mod crypto - relay-sdk cryptographic primitives.
//
// Only two primitives are needed by relay-xdp wire format:
//   - SHA-256: header verification (HeaderData struct from relay-xdp-common)
//   - XChaCha20-Poly1305: token encryption (RouteToken, ContinueToken)
//
// Key derivation (X25519 + BLAKE2b-512) is shared between relay-xdp and
// relay-backend via `derive_relay_session_key`. Both sides compute the same
// 32-byte key using X25519 symmetry:
//   relay:   q = X25519(relay_sk,   backend_pk)
//   backend: q = X25519(backend_sk, relay_pk)
//   both:    key = BLAKE2b-512(q || relay_pk || backend_pk)[..32]

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

// ── Constants ────────────────────────────────────────────────────────────────

/// XChaCha20-Poly1305 nonce size in bytes (matches relay-xdp-common XCHACHA20POLY1305_NONCE_SIZE).
pub const XCHACHA_NONCE_BYTES: usize = 24;

/// XChaCha20-Poly1305 key size in bytes (matches relay-xdp-common CHACHA20POLY1305_KEY_SIZE).
pub const XCHACHA_KEY_BYTES: usize = 32;

/// Poly1305 authentication tag appended to ciphertext.
pub const XCHACHA_TAG_BYTES: usize = 16;

/// SHA-256 output size.
pub const SHA256_BYTES: usize = 32;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("decryption failed (bad key, nonce, or ciphertext)")]
    DecryptFailed,
    #[error("ciphertext too short: need at least {XCHACHA_TAG_BYTES} tag bytes")]
    CiphertextTooShort,
}

// ── Per-relay symmetric key derivation ───────────────────────────────────────

/// Derive the per-relay XChaCha20-Poly1305 key shared between a relay and
/// the backend.
///
/// Both sides compute the same 32-byte key by exploiting X25519 symmetry:
///
/// - **Relay side:** `q = X25519(relay_sk, backend_pk)`
/// - **Backend side:** `q = X25519(backend_sk, relay_pk)`
/// - **Both:** `key = BLAKE2b-512(q || relay_pk || backend_pk)[..32]`
///
/// This key is used by the relay's eBPF kfunc
/// `bpf_relay_xchacha20poly1305_decrypt` to decrypt `RouteToken`s on the wire,
/// and by the backend's `/bench_token` handler to encrypt them before sending.
///
/// # Parameters
/// - `my_secret_key`: the caller's X25519 secret key (relay_sk or backend_sk)
/// - `their_public_key`: the counterpart's X25519 public key (backend_pk or relay_pk)
/// - `relay_public_key`: the relay's X25519 public key (same on both sides)
/// - `backend_public_key`: the backend's X25519 public key (same on both sides)
pub fn derive_relay_session_key(
    my_secret_key: &[u8; 32],
    their_public_key: &[u8; 32],
    relay_public_key: &[u8; 32],
    backend_public_key: &[u8; 32],
) -> [u8; 32] {
    use blake2::digest::{Update, VariableOutput};
    use x25519_dalek::{PublicKey, StaticSecret};

    let sk = StaticSecret::from(*my_secret_key);
    let pk = PublicKey::from(*their_public_key);
    let q = sk.diffie_hellman(&pk);

    let mut hasher = blake2::Blake2bVar::new(64).expect("valid output size");
    hasher.update(q.as_bytes());
    hasher.update(relay_public_key);
    hasher.update(backend_public_key);
    let mut out = [0u8; 64];
    hasher
        .finalize_variable(&mut out)
        .expect("valid output size");
    let mut rx = [0u8; 32];
    rx.copy_from_slice(&out[..32]);
    rx
}

// ── SHA-256 ──────────────────────────────────────────────────────────────────

/// Compute SHA-256 over `data`. Used for relay packet header verification.
///
/// In relay-xdp the header HMAC is: SHA-256(HeaderData)[..8]
pub fn hash_sha256(data: &[u8]) -> [u8; SHA256_BYTES] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

// ── XChaCha20-Poly1305 ───────────────────────────────────────────────────────

/// Encrypt `plaintext` with XChaCha20-Poly1305.
///
/// Returns `ciphertext || tag` (plaintext.len() + XCHACHA_TAG_BYTES bytes).
/// `nonce` must be exactly XCHACHA_NONCE_BYTES (24) bytes.
/// `key`   must be exactly XCHACHA_KEY_BYTES (32) bytes.
/// `aad`   is optional additional authenticated data (pass `&[]` if unused).
pub fn xchacha_encrypt(
    plaintext: &[u8],
    nonce: &[u8; XCHACHA_NONCE_BYTES],
    key: &[u8; XCHACHA_KEY_BYTES],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encrypt should not fail with valid key/nonce")
}

/// Decrypt `ciphertext` (ciphertext || tag) with XChaCha20-Poly1305.
///
/// Returns plaintext on success.
/// `nonce` must be exactly XCHACHA_NONCE_BYTES (24) bytes.
/// `key`   must be exactly XCHACHA_KEY_BYTES (32) bytes.
/// `aad`   must match what was passed to `xchacha_encrypt`.
pub fn xchacha_decrypt(
    ciphertext: &[u8],
    nonce: &[u8; XCHACHA_NONCE_BYTES],
    key: &[u8; XCHACHA_KEY_BYTES],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < XCHACHA_TAG_BYTES {
        return Err(CryptoError::CiphertextTooShort);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_relay_session_key_symmetric() {
        // Both sides must compute the identical key via X25519 symmetry.
        let relay_sk = [0x11u8; 32];
        let backend_sk = [0x22u8; 32];

        let relay_pk = {
            use x25519_dalek::{PublicKey, StaticSecret};
            let sk = StaticSecret::from(relay_sk);
            PublicKey::from(&sk).to_bytes()
        };
        let backend_pk = {
            use x25519_dalek::{PublicKey, StaticSecret};
            let sk = StaticSecret::from(backend_sk);
            PublicKey::from(&sk).to_bytes()
        };

        // Relay side: my_sk = relay_sk, their_pk = backend_pk
        let key_relay = derive_relay_session_key(&relay_sk, &backend_pk, &relay_pk, &backend_pk);
        // Backend side: my_sk = backend_sk, their_pk = relay_pk
        let key_backend = derive_relay_session_key(&backend_sk, &relay_pk, &relay_pk, &backend_pk);

        assert_eq!(
            key_relay, key_backend,
            "relay-side and backend-side keys must be identical (X25519 symmetry)"
        );
    }

    #[test]
    fn derive_relay_session_key_differs_per_relay() {
        // Different relay key pairs must produce different session keys even
        // with the same backend key pair.
        let relay_sk_a = [0x11u8; 32];
        let relay_sk_b = [0x33u8; 32];
        let backend_sk = [0x22u8; 32];

        let relay_pk_a = {
            use x25519_dalek::{PublicKey, StaticSecret};
            PublicKey::from(&StaticSecret::from(relay_sk_a)).to_bytes()
        };
        let relay_pk_b = {
            use x25519_dalek::{PublicKey, StaticSecret};
            PublicKey::from(&StaticSecret::from(relay_sk_b)).to_bytes()
        };
        let backend_pk = {
            use x25519_dalek::{PublicKey, StaticSecret};
            PublicKey::from(&StaticSecret::from(backend_sk)).to_bytes()
        };

        let key_a = derive_relay_session_key(&backend_sk, &relay_pk_a, &relay_pk_a, &backend_pk);
        let key_b = derive_relay_session_key(&backend_sk, &relay_pk_b, &relay_pk_b, &backend_pk);

        assert_ne!(
            key_a, key_b,
            "distinct relay public keys must yield distinct session keys"
        );
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = hash_sha256(b"");
        assert_eq!(hash[..4], [0xe3, 0xb0, 0xc4, 0x42]);
    }

    #[test]
    fn sha256_hello() {
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let hash = hash_sha256(b"hello");
        assert_eq!(hash[0], 0x2c);
        assert_eq!(hash[1], 0xf2);
        assert_eq!(hash[2], 0x4d);
    }

    #[test]
    fn xchacha_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; XCHACHA_KEY_BYTES];
        let nonce = [0x11u8; XCHACHA_NONCE_BYTES];
        let plaintext = b"relay payload test 12345";

        let ciphertext = xchacha_encrypt(plaintext, &nonce, &key, &[]);
        assert_eq!(ciphertext.len(), plaintext.len() + XCHACHA_TAG_BYTES);

        let decrypted = xchacha_decrypt(&ciphertext, &nonce, &key, &[]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn xchacha_wrong_key_fails() {
        let key = [0x42u8; XCHACHA_KEY_BYTES];
        let bad_key = [0x99u8; XCHACHA_KEY_BYTES];
        let nonce = [0x11u8; XCHACHA_NONCE_BYTES];
        let plaintext = b"secret data";

        let ciphertext = xchacha_encrypt(plaintext, &nonce, &key, &[]);
        assert!(xchacha_decrypt(&ciphertext, &nonce, &bad_key, &[]).is_err());
    }

    #[test]
    fn xchacha_with_aad() {
        let key = [0x55u8; XCHACHA_KEY_BYTES];
        let nonce = [0x22u8; XCHACHA_NONCE_BYTES];
        let plaintext = b"token data";
        let aad = b"session_id=1234";

        let ciphertext = xchacha_encrypt(plaintext, &nonce, &key, aad);
        // correct aad -> ok
        let decrypted = xchacha_decrypt(&ciphertext, &nonce, &key, aad).unwrap();
        assert_eq!(decrypted, plaintext);
        // wrong aad -> fail
        assert!(xchacha_decrypt(&ciphertext, &nonce, &key, b"wrong").is_err());
    }

    #[test]
    fn xchacha_short_ciphertext_fails() {
        let key = [0u8; XCHACHA_KEY_BYTES];
        let nonce = [0u8; XCHACHA_NONCE_BYTES];
        // tag is 16 bytes, giving fewer bytes should fail immediately
        let short = [0u8; 4];
        assert!(xchacha_decrypt(&short, &nonce, &key, &[]).is_err());
    }
}
