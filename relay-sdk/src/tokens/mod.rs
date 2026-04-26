// mod tokens - encrypt/decrypt RouteToken and ContinueToken.
//
// Uses relay-xdp-common structs directly (wire-compatible with eBPF kfunc).
// Encrypted wire format: [nonce: 24 bytes][ciphertext + tag: plaintext_len + 16 bytes]
//
// RouteToken:   plaintext 71B -> encrypted 111B  (RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES)
// ContinueToken: plaintext 17B -> encrypted  57B  (RELAY_ENCRYPTED_CONTINUE_TOKEN_BYTES)

use crate::constants::{ENCRYPTED_CONTINUE_TOKEN_BYTES, ENCRYPTED_ROUTE_TOKEN_BYTES};
use crate::crypto::{
    xchacha_decrypt, xchacha_encrypt, CryptoError, XCHACHA_KEY_BYTES, XCHACHA_NONCE_BYTES,
};
use rand::RngCore;
use relay_xdp_common::{ContinueToken, RouteToken};
use thiserror::Error;

pub const ROUTE_TOKEN_BYTES: usize = 71;
pub const CONTINUE_TOKEN_BYTES: usize = 17;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("decrypted size mismatch: expected {expected}, got {got}")]
    SizeMismatch { expected: usize, got: usize },
}

// ── Raw byte serialization for relay-xdp-common structs ─────────────────────
//
// Both structs are #[repr(C, packed)] so there is no padding.
// Safety: we read/write the structs as raw bytes using pointer casts.
// This is valid because:
//   - the structs are Copy + #[repr(C, packed)]
//   - the byte slice length matches size_of::<T>()
//   - we own or have shared access to the struct for the duration

fn route_token_to_bytes(t: &RouteToken) -> [u8; ROUTE_TOKEN_BYTES] {
    // Safety: RouteToken is #[repr(C, packed)], no padding, all bytes valid.
    unsafe {
        let ptr = t as *const RouteToken as *const u8;
        let mut out = [0u8; ROUTE_TOKEN_BYTES];
        std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), ROUTE_TOKEN_BYTES);
        out
    }
}

fn route_token_from_bytes(bytes: &[u8; ROUTE_TOKEN_BYTES]) -> RouteToken {
    // Safety: RouteToken is #[repr(C, packed)], all bit patterns valid for its field types.
    unsafe {
        let mut t = std::mem::MaybeUninit::<RouteToken>::uninit();
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), t.as_mut_ptr() as *mut u8, ROUTE_TOKEN_BYTES);
        t.assume_init()
    }
}

fn continue_token_to_bytes(t: &ContinueToken) -> [u8; CONTINUE_TOKEN_BYTES] {
    // Safety: ContinueToken is #[repr(C, packed)], no padding, all bytes valid.
    unsafe {
        let ptr = t as *const ContinueToken as *const u8;
        let mut out = [0u8; CONTINUE_TOKEN_BYTES];
        std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), CONTINUE_TOKEN_BYTES);
        out
    }
}

fn continue_token_from_bytes(bytes: &[u8; CONTINUE_TOKEN_BYTES]) -> ContinueToken {
    // Safety: ContinueToken is #[repr(C, packed)], all bit patterns valid for its field types.
    unsafe {
        let mut t = std::mem::MaybeUninit::<ContinueToken>::uninit();
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            t.as_mut_ptr() as *mut u8,
            CONTINUE_TOKEN_BYTES,
        );
        t.assume_init()
    }
}

// ── RouteToken encrypt / decrypt ─────────────────────────────────────────────

/// Encrypt a RouteToken. Returns 111-byte blob: [nonce(24)][ciphertext+tag(87)].
pub fn encrypt_route_token(
    token: &RouteToken,
    key: &[u8; XCHACHA_KEY_BYTES],
) -> [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] {
    let mut nonce = [0u8; XCHACHA_NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);
    let plaintext = route_token_to_bytes(token);
    let ciphertext = xchacha_encrypt(&plaintext, &nonce, key, &[]);
    let mut out = [0u8; ENCRYPTED_ROUTE_TOKEN_BYTES];
    out[..XCHACHA_NONCE_BYTES].copy_from_slice(&nonce);
    out[XCHACHA_NONCE_BYTES..].copy_from_slice(&ciphertext);
    out
}

/// Decrypt a 111-byte RouteToken blob.
pub fn decrypt_route_token(
    data: &[u8; ENCRYPTED_ROUTE_TOKEN_BYTES],
    key: &[u8; XCHACHA_KEY_BYTES],
) -> Result<RouteToken, TokenError> {
    let nonce: &[u8; XCHACHA_NONCE_BYTES] = data[..XCHACHA_NONCE_BYTES]
        .try_into()
        .expect("infallible: data is [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] >= XCHACHA_NONCE_BYTES");
    let ciphertext = &data[XCHACHA_NONCE_BYTES..];
    let plaintext = xchacha_decrypt(ciphertext, nonce, key, &[])?;
    if plaintext.len() != ROUTE_TOKEN_BYTES {
        return Err(TokenError::SizeMismatch {
            expected: ROUTE_TOKEN_BYTES,
            got: plaintext.len(),
        });
    }
    let bytes: &[u8; ROUTE_TOKEN_BYTES] = plaintext
        .as_slice()
        .try_into()
        .expect("infallible: length verified by SizeMismatch guard above");
    Ok(route_token_from_bytes(bytes))
}

// ── ContinueToken encrypt / decrypt ──────────────────────────────────────────

/// Encrypt a ContinueToken. Returns 57-byte blob: [nonce(24)][ciphertext+tag(33)].
pub fn encrypt_continue_token(
    token: &ContinueToken,
    key: &[u8; XCHACHA_KEY_BYTES],
) -> [u8; ENCRYPTED_CONTINUE_TOKEN_BYTES] {
    let mut nonce = [0u8; XCHACHA_NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);
    let plaintext = continue_token_to_bytes(token);
    let ciphertext = xchacha_encrypt(&plaintext, &nonce, key, &[]);
    let mut out = [0u8; ENCRYPTED_CONTINUE_TOKEN_BYTES];
    out[..XCHACHA_NONCE_BYTES].copy_from_slice(&nonce);
    out[XCHACHA_NONCE_BYTES..].copy_from_slice(&ciphertext);
    out
}

/// Decrypt a 57-byte ContinueToken blob.
pub fn decrypt_continue_token(
    data: &[u8; ENCRYPTED_CONTINUE_TOKEN_BYTES],
    key: &[u8; XCHACHA_KEY_BYTES],
) -> Result<ContinueToken, TokenError> {
    let nonce: &[u8; XCHACHA_NONCE_BYTES] = data[..XCHACHA_NONCE_BYTES]
        .try_into()
        .expect("infallible: data is [u8; ENCRYPTED_CONTINUE_TOKEN_BYTES] >= XCHACHA_NONCE_BYTES");
    let ciphertext = &data[XCHACHA_NONCE_BYTES..];
    let plaintext = xchacha_decrypt(ciphertext, nonce, key, &[])?;
    if plaintext.len() != CONTINUE_TOKEN_BYTES {
        return Err(TokenError::SizeMismatch {
            expected: CONTINUE_TOKEN_BYTES,
            got: plaintext.len(),
        });
    }
    let bytes: &[u8; CONTINUE_TOKEN_BYTES] = plaintext
        .as_slice()
        .try_into()
        .expect("infallible: length verified by SizeMismatch guard above");
    Ok(continue_token_from_bytes(bytes))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::SESSION_PRIVATE_KEY_BYTES;
    use relay_xdp_common::{ContinueToken, RouteToken};

    fn make_route_token() -> RouteToken {
        RouteToken {
            session_private_key: [0x55u8; SESSION_PRIVATE_KEY_BYTES],
            expire_timestamp: 9_999_999,
            session_id: 0xCAFE_BABE_DEAD_BEEF,
            envelope_kbps_up: 1000,
            envelope_kbps_down: 2000,
            next_address: 0x0A00_0001u32.to_be(),
            prev_address: 0,
            next_port: 12345u16.to_be(),
            prev_port: 0,
            session_version: 3,
            next_internal: 0,
            prev_internal: 0,
        }
    }

    fn make_continue_token() -> ContinueToken {
        ContinueToken {
            expire_timestamp: 8_888_888,
            session_id: 0xDEAD_BEEF_CAFE_0001,
            session_version: 5,
        }
    }

    #[test]
    fn route_token_roundtrip() {
        let key = [0x42u8; XCHACHA_KEY_BYTES];
        let token = make_route_token();
        let enc = encrypt_route_token(&token, &key);
        assert_eq!(enc.len(), ENCRYPTED_ROUTE_TOKEN_BYTES);
        let dec = decrypt_route_token(&enc, &key).unwrap();
        // packed fields must be read into locals before comparing
        let dec_sid: u64 = dec.session_id;
        let tok_sid: u64 = token.session_id;
        assert_eq!(dec_sid, tok_sid);
        assert_eq!(dec.session_version, token.session_version);
        let dec_kup: u32 = dec.envelope_kbps_up;
        let tok_kup: u32 = token.envelope_kbps_up;
        assert_eq!(dec_kup, tok_kup);
        let dec_kdn: u32 = dec.envelope_kbps_down;
        let tok_kdn: u32 = token.envelope_kbps_down;
        assert_eq!(dec_kdn, tok_kdn);
        let dec_na: u32 = dec.next_address;
        let tok_na: u32 = token.next_address;
        assert_eq!(dec_na, tok_na);
        assert_eq!(dec.session_private_key, token.session_private_key);
    }

    #[test]
    fn route_token_wrong_key_fails() {
        let key = [0x42u8; XCHACHA_KEY_BYTES];
        let bad_key = [0x99u8; XCHACHA_KEY_BYTES];
        let enc = encrypt_route_token(&make_route_token(), &key);
        assert!(decrypt_route_token(&enc, &bad_key).is_err());
    }

    #[test]
    fn continue_token_roundtrip() {
        let key = [0x33u8; XCHACHA_KEY_BYTES];
        let token = make_continue_token();
        let enc = encrypt_continue_token(&token, &key);
        assert_eq!(enc.len(), ENCRYPTED_CONTINUE_TOKEN_BYTES);
        let dec = decrypt_continue_token(&enc, &key).unwrap();
        // packed fields must be read into locals before comparing
        let dec_sid: u64 = dec.session_id;
        let tok_sid: u64 = token.session_id;
        assert_eq!(dec_sid, tok_sid);
        assert_eq!(dec.session_version, token.session_version);
        let dec_exp: u64 = dec.expire_timestamp;
        let tok_exp: u64 = token.expire_timestamp;
        assert_eq!(dec_exp, tok_exp);
    }

    #[test]
    fn continue_token_wrong_key_fails() {
        let key = [0x33u8; XCHACHA_KEY_BYTES];
        let bad_key = [0x77u8; XCHACHA_KEY_BYTES];
        let enc = encrypt_continue_token(&make_continue_token(), &key);
        assert!(decrypt_continue_token(&enc, &bad_key).is_err());
    }

    #[test]
    fn route_token_encrypted_size() {
        let key = [0u8; XCHACHA_KEY_BYTES];
        let enc = encrypt_route_token(&make_route_token(), &key);
        // nonce(24) + plaintext(71) + tag(16) = 111
        assert_eq!(enc.len(), 111);
    }

    #[test]
    fn continue_token_encrypted_size() {
        let key = [0u8; XCHACHA_KEY_BYTES];
        let enc = encrypt_continue_token(&make_continue_token(), &key);
        // nonce(24) + plaintext(17) + tag(16) = 57
        assert_eq!(enc.len(), 57);
    }
}
