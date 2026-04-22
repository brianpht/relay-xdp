// mod crypto - relay-sdk cryptographic primitives.
//
// Only two primitives are needed by relay-xdp wire format:
//   - SHA-256: header verification (HeaderData struct from relay-xdp-common)
//   - XChaCha20-Poly1305: token encryption (RouteToken, ContinueToken)
//
// All NaCl / BLAKE2 / Ed25519 / KX from rust-sdk are intentionally omitted.

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Sha256, Digest};
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
            Payload { msg: plaintext, aad },
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
            Payload { msg: ciphertext, aad },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = hash_sha256(b"");
        assert_eq!(
            hash[..4],
            [0xe3, 0xb0, 0xc4, 0x42]
        );
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

