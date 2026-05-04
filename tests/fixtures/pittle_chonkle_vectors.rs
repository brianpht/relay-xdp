//! Canonical pittle/chonkle parity vectors.
//!
//! This fixture is the single source of truth for the FNV-1a-based DDoS
//! packet filter that lives in three crates:
//!
//!   - `relay-xdp-ebpf::compute_pittle / compute_chonkle` (eBPF data plane)
//!   - `relay-xdp::packet_filter::generate_pittle / generate_chonkle` (userspace)
//!   - `relay-sdk::route::generate_pittle / generate_chonkle` (SDK)
//!
//! All three implementations MUST produce these exact bytes for these inputs.
//! Drift in any one is a correctness regression - the audit v2 (P1-08) calls
//! this "the single most likely correctness regression" because the three
//! implementations are by-hand copies of the same C reference in
//! `relay_ping.c` lines 129-189.
//!
//! The expected_pittle / expected_chonkle values were generated from
//! `relay-xdp::packet_filter` (which the file comment marks as the canonical
//! Rust mirror of the C reference).
//!
//! Vectors are written as a plain Rust const array rather than JSON so all
//! three crates - including the no_std `relay-xdp-ebpf` - can consume the
//! same fixture via `#[path = "..."]` without pulling in `serde_json`.

#![allow(dead_code)] // Each consumer uses a subset of fields.

#[derive(Debug, Clone, Copy)]
pub struct ParityVector {
    pub label: &'static str,
    pub from: [u8; 4],
    pub to: [u8; 4],
    pub len: u16,
    pub magic: [u8; 8],
    pub expected_pittle: [u8; 2],
    pub expected_chonkle: [u8; 15],
}

pub const VECTORS: &[ParityVector] = &[
    ParityVector {
        label: "all-zero",
        from: [0, 0, 0, 0],
        to: [0, 0, 0, 0],
        len: 0,
        magic: [0, 0, 0, 0, 0, 0, 0, 0],
        expected_pittle: [193, 79],
        expected_chonkle: [
            45, 207, 50, 45, 80, 145, 140, 7, 83, 129, 180, 73, 13, 224, 76,
        ],
    },
    ParityVector {
        label: "rfc1918-pair-len-100",
        from: [10, 0, 0, 1],
        to: [10, 0, 0, 2],
        len: 100,
        magic: [1, 2, 3, 4, 5, 6, 7, 8],
        expected_pittle: [187, 53],
        expected_chonkle: [
            42, 230, 65, 172, 79, 156, 101, 79, 37, 130, 175, 44, 13, 213, 73,
        ],
    },
    ParityVector {
        label: "lan-to-rfc1918-deadbeef-magic",
        from: [192, 168, 1, 1],
        to: [10, 0, 0, 1],
        len: 200,
        magic: [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
        expected_pittle: [255, 113],
        expected_chonkle: [
            45, 204, 27, 84, 80, 177, 152, 7, 37, 130, 181, 52, 13, 233, 137,
        ],
    },
    ParityVector {
        label: "all-ones-mtu",
        from: [255, 255, 255, 255],
        to: [255, 255, 255, 255],
        len: 1384,
        magic: [0xFF; 8],
        expected_pittle: [173, 35],
        expected_chonkle: [
            44, 224, 26, 70, 80, 97, 116, 79, 83, 128, 177, 43, 97, 238, 18,
        ],
    },
    ParityVector {
        label: "monotonic-incrementing",
        from: [1, 2, 3, 4],
        to: [5, 6, 7, 8],
        len: 1234,
        magic: [9, 10, 11, 12, 13, 14, 15, 16],
        expected_pittle: [59, 181],
        expected_chonkle: [
            44, 229, 29, 243, 80, 177, 126, 7, 83, 127, 178, 56, 43, 227, 96,
        ],
    },
    ParityVector {
        label: "minimal-len-2",
        from: [2, 0, 0, 0],
        to: [0, 0, 0, 0],
        len: 2,
        magic: [0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA],
        expected_pittle: [197, 75],
        expected_chonkle: [
            44, 218, 15, 197, 80, 185, 125, 79, 37, 127, 178, 45, 43, 230, 95,
        ],
    },
    ParityVector {
        label: "loopback-zero-magic",
        from: [127, 0, 0, 1],
        to: [127, 0, 0, 1],
        len: 18,
        magic: [0, 0, 0, 0, 0, 0, 0, 0],
        expected_pittle: [211, 93],
        expected_chonkle: [
            43, 226, 43, 239, 78, 141, 110, 79, 37, 129, 176, 63, 97, 232, 48,
        ],
    },
    ParityVector {
        label: "asymmetric-lengths-67",
        from: [8, 8, 8, 8],
        to: [1, 1, 1, 1],
        len: 67,
        magic: [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
        expected_pittle: [167, 41],
        expected_chonkle: [
            43, 204, 42, 42, 81, 217, 102, 79, 83, 128, 175, 92, 13, 230, 62,
        ],
    },
];
