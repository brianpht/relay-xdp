//! Parity test: relay-xdp's userspace pittle/chonkle implementation must
//! match the canonical fixture byte-for-byte.
//!
//! See `tests/fixtures/pittle_chonkle_vectors.rs` for the source of truth.

use relay_xdp::packet_filter as canonical;

#[path = "../../tests/fixtures/pittle_chonkle_vectors.rs"]
mod parity_vectors;

#[test]
fn xdp_pittle_matches_canonical() {
    for v in parity_vectors::VECTORS.iter() {
        let actual = canonical::generate_pittle(&v.from, &v.to, v.len);
        assert_eq!(
            actual, v.expected_pittle,
            "pittle drift for vector {:?}: expected {:?}, got {:?}",
            v.label, v.expected_pittle, actual
        );
    }
}

#[test]
fn xdp_chonkle_matches_canonical() {
    for v in parity_vectors::VECTORS.iter() {
        let actual = canonical::generate_chonkle(&v.magic, &v.from, &v.to, v.len);
        assert_eq!(
            actual, v.expected_chonkle,
            "chonkle drift for vector {:?}: expected {:?}, got {:?}",
            v.label, v.expected_chonkle, actual
        );
    }
}
