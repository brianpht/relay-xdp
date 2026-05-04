//! Parity test: relay-sdk's pittle/chonkle implementation must match the
//! canonical fixture byte-for-byte. The canonical impl is the userspace
//! `relay-xdp::packet_filter` (which mirrors C `relay_ping.c`); the eBPF
//! `relay-xdp-ebpf::compute_pittle / compute_chonkle` is byte-identical to
//! the userspace impl.
//!
//! See `tests/fixtures/pittle_chonkle_vectors.rs` for the source of truth.
//!
//! Both pittle and chonkle now match the canonical fixture. The SDK pittle
//! drift (P1-15) was fixed in the same change that landed this fixture: the
//! SDK's `1u8.wrapping_add(x)` was replaced with the canonical `1 | x` (see
//! `relay-sdk/src/route/mod.rs::generate_pittle`).

use relay_sdk::route as sdk;

#[path = "../../tests/fixtures/pittle_chonkle_vectors.rs"]
mod parity_vectors;

#[test]
fn sdk_chonkle_matches_canonical() {
    for v in parity_vectors::VECTORS.iter() {
        let mut actual = [0u8; 15];
        sdk::generate_chonkle(&mut actual, &v.magic, &v.from, &v.to, v.len);
        assert_eq!(
            actual, v.expected_chonkle,
            "chonkle drift for vector {:?}: expected {:?}, got {:?}",
            v.label, v.expected_chonkle, actual
        );
    }
}

#[test]
fn sdk_pittle_matches_canonical() {
    for v in parity_vectors::VECTORS.iter() {
        let mut actual = [0u8; 2];
        sdk::generate_pittle(&mut actual, &v.from, &v.to, v.len);
        assert_eq!(
            actual, v.expected_pittle,
            "pittle drift for vector {:?}: expected {:?}, got {:?}",
            v.label, v.expected_pittle, actual
        );
    }
}
