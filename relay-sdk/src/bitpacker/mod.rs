//! Port of next_bitpacker.h - BitWriter + BitReader
//!
//! Wire format: little-endian, bits packed right-to-left into 64-bit scratch,
//! flushed as 32-bit little-endian dwords.

// ── BitWriter ──────────────────────────────────────────────────────────────

/// Writes bit-packed values into a byte buffer.
/// Buffer must be a multiple of 4 bytes.
pub struct BitWriter {
    data: Vec<u32>, // working buffer in units of u32
    num_words: usize,
    num_bits: usize,
    bits_written: usize,
    word_index: usize,
    scratch: u64,
    scratch_bits: u32,
}

impl BitWriter {
    /// `bytes` must be a multiple of 4.
    pub fn new(bytes: usize) -> Self {
        assert!(
            bytes.is_multiple_of(4),
            "buffer must be a multiple of 4 bytes"
        );
        let num_words = bytes / 4;
        BitWriter {
            data: vec![0u32; num_words],
            num_words,
            num_bits: num_words * 32,
            bits_written: 0,
            word_index: 0,
            scratch: 0,
            scratch_bits: 0,
        }
    }

    /// Write `bits` low bits of `value` (1..=32).
    pub fn write_bits(&mut self, value: u32, bits: u32) {
        debug_assert!((1..=32).contains(&bits));
        debug_assert!(self.bits_written + bits as usize <= self.num_bits);
        debug_assert!(
            bits == 32 || (value as u64) < (1u64 << bits),
            "value {value} does not fit in {bits} bits"
        );

        self.scratch |= (value as u64) << self.scratch_bits;
        self.scratch_bits += bits;

        if self.scratch_bits >= 32 {
            debug_assert!(self.word_index < self.num_words);
            self.data[self.word_index] = (self.scratch as u32).to_le();
            self.scratch >>= 32;
            self.scratch_bits -= 32;
            self.word_index += 1;
        }

        self.bits_written += bits as usize;
    }

    /// Pad to next byte boundary with zero bits.
    pub fn write_align(&mut self) {
        let remainder = self.bits_written % 8;
        if remainder != 0 {
            self.write_bits(0, (8 - remainder) as u32);
        }
        debug_assert!(self.bits_written.is_multiple_of(8));
    }

    /// Copy `bytes` bytes into the stream (must be byte-aligned first).
    pub fn write_bytes(&mut self, data: &[u8]) {
        debug_assert!(self.bits_written.is_multiple_of(8));
        // Flush scratch so the current partial word is stored
        self.flush_bits();
        let byte_offset = self.bits_written / 8;
        let dst = unsafe {
            std::slice::from_raw_parts_mut(self.data.as_mut_ptr() as *mut u8, self.data.len() * 4)
        };
        dst[byte_offset..byte_offset + data.len()].copy_from_slice(data);
        self.bits_written += data.len() * 8;
        self.word_index = self.bits_written / 32;
        // Reload partial word into scratch so subsequent write_bits appends correctly.
        let remaining_bits = (self.bits_written % 32) as u32;
        if remaining_bits > 0 {
            let word = u32::from_le(self.data[self.word_index]);
            self.scratch = (word as u64) & ((1u64 << remaining_bits) - 1);
            self.scratch_bits = remaining_bits;
        } else {
            self.scratch = 0;
            self.scratch_bits = 0;
        }
    }

    /// Must be called after all writes before reading back the data.
    pub fn flush_bits(&mut self) {
        if self.scratch_bits > 0 {
            debug_assert!(self.word_index < self.num_words);
            self.data[self.word_index] = (self.scratch as u32).to_le();
        }
    }

    pub fn get_data(&self) -> &[u8] {
        let bytes = self.get_bytes_written();
        let raw: &[u8] = bytemuck_cast_slice(self.data.as_slice());
        &raw[..bytes]
    }

    pub fn get_bits_written(&self) -> usize {
        self.bits_written
    }

    pub fn get_bytes_written(&self) -> usize {
        self.bits_written.div_ceil(8)
    }

    pub fn get_align_bits(&self) -> u32 {
        let r = self.bits_written % 8;
        if r == 0 {
            0
        } else {
            (8 - r) as u32
        }
    }
}

// ── BitReader ──────────────────────────────────────────────────────────────

/// Reads bit-packed values from a byte slice.
pub struct BitReader<'a> {
    data: &'a [u8],
    num_bits: usize,
    bits_read: usize,
    scratch: u64,
    scratch_bits: u32,
    word_index: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            num_bits: data.len() * 8,
            bits_read: 0,
            scratch: 0,
            scratch_bits: 0,
            word_index: 0,
        }
    }

    /// Returns true if reading `bits` more bits would go past the end.
    pub fn would_read_past_end(&self, bits: u32) -> bool {
        self.bits_read + bits as usize > self.num_bits
    }

    /// Read `bits` bits (1..=32). Caller must call `would_read_past_end` first.
    pub fn read_bits(&mut self, bits: u32) -> u32 {
        debug_assert!((1..=32).contains(&bits));
        debug_assert!(!self.would_read_past_end(bits));

        while self.scratch_bits < bits {
            // Read next dword (little-endian)
            let word = if self.word_index * 4 + 4 <= self.data.len() {
                let b = &self.data[self.word_index * 4..self.word_index * 4 + 4];
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            } else {
                // partial last word
                let mut tmp = [0u8; 4];
                let start = self.word_index * 4;
                let end = self.data.len().min(start + 4);
                tmp[..end - start].copy_from_slice(&self.data[start..end]);
                u32::from_le_bytes(tmp)
            };
            self.scratch |= (word as u64) << self.scratch_bits;
            self.scratch_bits += 32;
            self.word_index += 1;
        }

        let mask = if bits == 32 {
            u32::MAX
        } else {
            (1u32 << bits) - 1
        };
        let value = (self.scratch as u32) & mask;
        self.scratch >>= bits;
        self.scratch_bits -= bits;
        self.bits_read += bits as usize;
        value
    }

    /// Consume zero-padding up to next byte boundary.
    pub fn read_align(&mut self) -> bool {
        let remainder = self.bits_read % 8;
        if remainder == 0 {
            return true;
        }
        let padding_bits = (8 - remainder) as u32;
        if self.would_read_past_end(padding_bits) {
            return false;
        }
        let padding = self.read_bits(padding_bits);
        padding == 0 // alignment bytes must be zero
    }

    /// Read `n` bytes into `out` (must be byte-aligned).
    pub fn read_bytes(&mut self, out: &mut [u8]) {
        debug_assert!(self.bits_read.is_multiple_of(8));
        let start = self.bits_read / 8;
        out.copy_from_slice(&self.data[start..start + out.len()]);
        self.bits_read += out.len() * 8;
        // Reset scratch so subsequent read_bits fetches from correct word position.
        self.word_index = self.bits_read / 32;
        self.scratch = 0;
        self.scratch_bits = 0;
        // Reload any partial word that was already consumed in bits_read position
        let remaining = (self.bits_read % 32) as u32;
        if remaining > 0 {
            let word = if self.word_index * 4 + 4 <= self.data.len() {
                let b = &self.data[self.word_index * 4..self.word_index * 4 + 4];
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            } else {
                let mut tmp = [0u8; 4];
                let start = self.word_index * 4;
                let end = self.data.len().min(start + 4);
                tmp[..end - start].copy_from_slice(&self.data[start..end]);
                u32::from_le_bytes(tmp)
            };
            // Only the bits from `remaining` onward are unread; shift out already-read bits
            self.scratch = (word as u64) >> remaining;
            self.scratch_bits = 32 - remaining;
            self.word_index += 1;
        }
    }

    pub fn get_bits_read(&self) -> usize {
        self.bits_read
    }

    pub fn get_align_bits(&self) -> u32 {
        let r = self.bits_read % 8;
        if r == 0 {
            0
        } else {
            (8 - r) as u32
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn bytemuck_cast_slice(s: &[u32]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(s.as_ptr() as *const u8, s.len() * 4) }
}

fn bytemuck_cast_slice_mut(s: &mut [u32]) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(s.as_mut_ptr() as *mut u8, s.len() * 4) }
}

pub fn bits_required(min: i32, max: i32) -> u32 {
    debug_assert!(min < max);
    let range = (max - min) as u32;
    32 - range.leading_zeros()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_single_bit() {
        let mut w = BitWriter::new(4);
        w.write_bits(1, 1);
        w.flush_bits();
        let mut r = BitReader::new(w.get_data());
        assert_eq!(r.read_bits(1), 1);
    }

    #[test]
    fn roundtrip_32bits() {
        let mut w = BitWriter::new(4);
        w.write_bits(0xDEAD_BEEF, 32);
        w.flush_bits();
        let mut r = BitReader::new(w.get_data());
        assert_eq!(r.read_bits(32), 0xDEAD_BEEF);
    }

    #[test]
    fn roundtrip_multiple_values() {
        let mut w = BitWriter::new(8);
        w.write_bits(7, 3);
        w.write_bits(255, 8);
        w.write_bits(0, 1);
        w.write_bits(100, 7);
        w.flush_bits();
        let data = w.get_data().to_vec();
        let mut r = BitReader::new(&data);
        assert_eq!(r.read_bits(3), 7);
        assert_eq!(r.read_bits(8), 255);
        assert_eq!(r.read_bits(1), 0);
        assert_eq!(r.read_bits(7), 100);
    }

    #[test]
    fn align_padding_zeros() {
        let mut w = BitWriter::new(4);
        w.write_bits(0b101, 3); // 3 bits
        w.write_align(); // pad to 8 bits
        w.flush_bits();
        let data = w.get_data().to_vec();
        let mut r = BitReader::new(&data);
        assert_eq!(r.read_bits(3), 0b101);
        assert!(r.read_align()); // padding should be zero
    }

    #[test]
    fn would_read_past_end() {
        let mut w = BitWriter::new(4);
        w.write_bits(1, 1);
        w.flush_bits();
        let data = w.get_data().to_vec();
        let r = BitReader::new(&data);
        assert!(!r.would_read_past_end(1));
        assert!(r.would_read_past_end(33)); // 33 bits in 4-byte buf (32 bits)
    }

    #[test]
    fn bits_required_range() {
        assert_eq!(bits_required(0, 1), 1);
        assert_eq!(bits_required(0, 255), 8);
        assert_eq!(bits_required(0, 256), 9);
        assert_eq!(bits_required(-1, 1), 2);
    }

    #[test]
    fn write_read_bytes() {
        let payload = b"hello!!\x00"; // 8 bytes
        let mut w = BitWriter::new(16);
        w.write_bits(0b11, 2);
        w.write_align();
        w.write_bytes(payload);
        w.flush_bits();
        let data = w.get_data().to_vec();
        let mut r = BitReader::new(&data);
        assert_eq!(r.read_bits(2), 0b11);
        assert!(r.read_align());
        let mut out = [0u8; 8];
        r.read_bytes(&mut out);
        assert_eq!(&out, payload);
    }
}
