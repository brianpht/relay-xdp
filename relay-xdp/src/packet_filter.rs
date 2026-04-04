//! Pittle/chonkle DDoS packet filter generation (FNV-1a based).
//! Matches `relay_ping.c` lines 129-189 byte-for-byte.

/// FNV-1a 64-bit hash.
pub struct Fnv1a(u64);

impl Fnv1a {
    pub fn new() -> Self {
        Self(0xCBF29CE484222325)
    }

    pub fn write(&mut self, data: &[u8]) {
        for &b in data {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x00000100000001B3);
        }
    }

    pub fn finish(&self) -> u64 {
        self.0
    }
}

/// Generate 2-byte pittle from source/dest IP addresses (4 bytes each, network byte order) and packet length.
///
/// `from_address` and `to_address` are 4-byte slices in network byte order.
/// `packet_length` is the UDP payload size in host byte order.
pub fn generate_pittle(from_address: &[u8; 4], to_address: &[u8; 4], packet_length: u16) -> [u8; 2] {
    let pl_le = packet_length.to_le_bytes();
    let mut sum: u16 = 0;
    for &b in from_address.iter() {
        sum = sum.wrapping_add(b as u16);
    }
    for &b in to_address.iter() {
        sum = sum.wrapping_add(b as u16);
    }
    sum = sum.wrapping_add(pl_le[0] as u16);
    sum = sum.wrapping_add(pl_le[1] as u16);

    let sum_le = sum.to_le_bytes();
    let sum_0 = sum_le[0];
    let sum_1 = sum_le[1];

    let p0 = 1 | (sum_0 ^ sum_1 ^ 193);
    let p1 = 1 | ((255u8.wrapping_sub(p0)) ^ 113);
    [p0, p1]
}

/// Generate 15-byte chonkle from magic, source/dest IP addresses, and packet length.
///
/// `magic` is 8 bytes. `from_address`/`to_address` are 4 bytes in network byte order.
/// `packet_length` is UDP payload size in host byte order.
pub fn generate_chonkle(
    magic: &[u8; 8],
    from_address: &[u8; 4],
    to_address: &[u8; 4],
    packet_length: u16,
) -> [u8; 15] {
    let pl_le = packet_length.to_le_bytes();

    let mut fnv = Fnv1a::new();
    fnv.write(magic);
    fnv.write(from_address);
    fnv.write(to_address);
    fnv.write(&pl_le);
    let hash = fnv.finish();

    let hash_le = hash.to_le_bytes();
    let d = hash_le; // d[0]..d[7]

    let mut c = [0u8; 15];
    c[0] = ((d[6] & 0xC0) >> 6) + 42;
    c[1] = (d[3] & 0x1F) + 200;
    c[2] = ((d[2] & 0xFC) >> 2) + 5;
    c[3] = d[0];
    c[4] = (d[2] & 0x03) + 78;
    c[5] = (d[4] & 0x7F) + 96;
    c[6] = ((d[1] & 0xFC) >> 2) + 100;
    c[7] = if (d[7] & 1) == 0 { 79 } else { 7 };
    c[8] = if (d[4] & 0x80) == 0 { 37 } else { 83 };
    c[9] = (d[5] & 0x07) + 124;
    c[10] = ((d[1] & 0xE0) >> 5) + 175;
    c[11] = (d[6] & 0x3F) + 33;
    c[12] = match d[1] & 0x03 {
        0 => 97,
        1 => 5,
        2 => 43,
        _ => 13,
    };
    c[13] = ((d[5] & 0xF8) >> 3) + 210;
    c[14] = ((d[7] & 0xFE) >> 1) + 17;

    c
}

/// Convert host-order u32 address to 4-byte network-order array.
pub fn address_to_bytes(host_order: u32) -> [u8; 4] {
    host_order.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pittle_symmetry() {
        let from = [10, 0, 0, 1];
        let to = [10, 0, 0, 2];
        let p = generate_pittle(&from, &to, 100);
        // pittle[1] must satisfy the relationship with pittle[0]
        assert_eq!(p[1], 1 | ((255u8.wrapping_sub(p[0])) ^ 113));
    }

    #[test]
    fn test_chonkle_range() {
        let magic = [1, 2, 3, 4, 5, 6, 7, 8];
        let from = [192, 168, 1, 1];
        let to = [10, 0, 0, 1];
        let c = generate_chonkle(&magic, &from, &to, 200);

        // Validate ranges match the basic packet filter in relay-xdp-ebpf
        assert!((0x2A..=0x2D).contains(&c[0]));
        assert!((0xC8..=0xE7).contains(&c[1]));
        assert!((0x05..=0x44).contains(&c[2]));
        // c[3] is any byte
        assert!((0x4E..=0x51).contains(&c[4]));
        assert!((0x60..=0xDF).contains(&c[5]));
        assert!((0x64..=0xE3).contains(&c[6]));
        assert!(c[7] == 0x07 || c[7] == 0x4F);
        assert!(c[8] == 0x25 || c[8] == 0x53);
        assert!((0x7C..=0x83).contains(&c[9]));
        assert!((0xAF..=0xB6).contains(&c[10]));
        assert!((0x21..=0x60).contains(&c[11]));
        assert!(c[12] == 0x61 || c[12] == 0x05 || c[12] == 0x2B || c[12] == 0x0D);
        assert!((0xD2..=0xF1).contains(&c[13]));
        assert!((0x11..=0x90).contains(&c[14]));
    }
}

