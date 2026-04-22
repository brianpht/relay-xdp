/// Port of next_stream.h — WriteStream / ReadStream + serialize macros.
///
/// Design: a single `trait Stream` with const IS_WRITING allows callers
/// to write one `serialize_*` function body that compiles to both read
/// and write paths (same as the C++ template trick).

use crate::bitpacker::{BitReader, BitWriter, bits_required};

// ── Trait ──────────────────────────────────────────────────────────────────

pub trait Stream {
    const IS_WRITING: bool;
    fn is_writing(&self) -> bool { Self::IS_WRITING }
    fn serialize_bits(&mut self, value: &mut u32, bits: u32) -> bool;
    fn serialize_bytes(&mut self, data: &mut [u8]) -> bool;
    fn serialize_align(&mut self) -> bool;
    fn get_align_bits(&self) -> u32;
    fn get_bits_processed(&self) -> usize;
    fn get_bytes_processed(&self) -> usize;

    fn serialize_integer(&mut self, value: &mut i32, min: i32, max: i32) -> bool {
        debug_assert!(min < max);
        let bits = bits_required(min, max);
        let mut unsigned_value: u32 = 0;
        if Self::IS_WRITING {
            debug_assert!(*value >= min && *value <= max);
            unsigned_value = (*value - min) as u32;
        }
        if !self.serialize_bits(&mut unsigned_value, bits) {
            return false;
        }
        if !Self::IS_WRITING {
            *value = unsigned_value as i32 + min;
            if *value < min || *value > max {
                return false;
            }
        }
        true
    }
}

// ── WriteStream ────────────────────────────────────────────────────────────

pub struct WriteStream {
    writer: BitWriter,
}

impl WriteStream {
    pub fn new(bytes: usize) -> Self {
        WriteStream { writer: BitWriter::new(bytes) }
    }

    pub fn flush(&mut self) {
        self.writer.flush_bits();
    }

    pub fn get_data(&self) -> &[u8] {
        self.writer.get_data()
    }
}

impl Stream for WriteStream {
    const IS_WRITING: bool = true;

    fn serialize_bits(&mut self, value: &mut u32, bits: u32) -> bool {
        self.writer.write_bits(*value, bits);
        true
    }

    fn serialize_bytes(&mut self, data: &mut [u8]) -> bool {
        self.serialize_align();
        self.writer.write_bytes(data);
        true
    }

    fn serialize_align(&mut self) -> bool {
        self.writer.write_align();
        true
    }

    fn get_align_bits(&self) -> u32 {
        self.writer.get_align_bits()
    }

    fn get_bits_processed(&self) -> usize {
        self.writer.get_bits_written()
    }

    fn get_bytes_processed(&self) -> usize {
        self.writer.get_bytes_written()
    }
}

// ── ReadStream ─────────────────────────────────────────────────────────────

pub struct ReadStream<'a> {
    reader: BitReader<'a>,
}

impl<'a> ReadStream<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        ReadStream { reader: BitReader::new(data) }
    }
}

impl<'a> Stream for ReadStream<'a> {
    const IS_WRITING: bool = false;

    fn serialize_bits(&mut self, value: &mut u32, bits: u32) -> bool {
        if self.reader.would_read_past_end(bits) {
            return false;
        }
        *value = self.reader.read_bits(bits);
        true
    }

    fn serialize_bytes(&mut self, data: &mut [u8]) -> bool {
        if !self.serialize_align() {
            return false;
        }
        if self.reader.would_read_past_end((data.len() * 8) as u32) {
            return false;
        }
        self.reader.read_bytes(data);
        true
    }

    fn serialize_align(&mut self) -> bool {
        let align_bits = self.reader.get_align_bits();
        if self.reader.would_read_past_end(align_bits) {
            return false;
        }
        self.reader.read_align()
    }

    fn get_align_bits(&self) -> u32 {
        self.reader.get_align_bits()
    }

    fn get_bits_processed(&self) -> usize {
        self.reader.get_bits_read()
    }

    fn get_bytes_processed(&self) -> usize {
        (self.reader.get_bits_read() + 7) / 8
    }
}

// ── Macros ─────────────────────────────────────────────────────────────────

/// serialize_bits!(stream, value, bits) — read or write `bits` bits of a u32.
#[macro_export]
macro_rules! serialize_bits {
    ($stream:expr, $value:expr, $bits:expr) => {{
        use $crate::stream::Stream;
        let writing = $stream.is_writing();
        let mut tmp: u32 = if writing { $value as u32 } else { 0 };
        if !$stream.serialize_bits(&mut tmp, $bits) {
            return Err($crate::stream::SerializeError::ReadPastEnd);
        }
        if !writing {
            $value = tmp.try_into().map_err(|_| $crate::stream::SerializeError::OutOfRange)?;
        }
    }};
}

/// serialize_bool!(stream, value)
#[macro_export]
macro_rules! serialize_bool {
    ($stream:expr, $value:expr) => {{
        use $crate::stream::Stream;
        let writing = $stream.is_writing();
        let mut tmp: u32 = if writing { $value as u32 } else { 0 };
        if !$stream.serialize_bits(&mut tmp, 1u32) {
            return Err($crate::stream::SerializeError::ReadPastEnd);
        }
        if !writing {
            $value = tmp != 0;
        }
    }};
}

/// serialize_int!(stream, value, min, max) — range-checked integer.
#[macro_export]
macro_rules! serialize_int {
    ($stream:expr, $value:expr, $min:expr, $max:expr) => {{
        use $crate::stream::Stream;
        let writing = $stream.is_writing();
        let mut tmp: i32 = if writing { $value as i32 } else { 0 };
        if !$stream.serialize_integer(&mut tmp, $min as i32, $max as i32) {
            return Err($crate::stream::SerializeError::OutOfRange);
        }
        if !writing {
            $value = tmp.try_into().map_err(|_| $crate::stream::SerializeError::OutOfRange)?;
        }
    }};
}

/// serialize_uint64!(stream, value) — split into two 32-bit halves.
#[macro_export]
macro_rules! serialize_uint64 {
    ($stream:expr, $value:expr) => {{
        use $crate::stream::Stream;
        let writing = $stream.is_writing();
        let mut lo: u32 = if writing { ($value & 0xFFFF_FFFF) as u32 } else { 0 };
        let mut hi: u32 = if writing { (($value >> 32) & 0xFFFF_FFFF) as u32 } else { 0 };
        if !$stream.serialize_bits(&mut lo, 32) {
            return Err($crate::stream::SerializeError::ReadPastEnd);
        }
        if !$stream.serialize_bits(&mut hi, 32) {
            return Err($crate::stream::SerializeError::ReadPastEnd);
        }
        if !writing {
            $value = ((hi as u64) << 32) | (lo as u64);
        }
    }};
}

/// serialize_float!(stream, value) — as raw IEEE 754 bits.
#[macro_export]
macro_rules! serialize_float {
    ($stream:expr, $value:expr) => {{
        use $crate::stream::Stream;
        let writing = $stream.is_writing();
        let mut bits: u32 = if writing { $value.to_bits() } else { 0 };
        if !$stream.serialize_bits(&mut bits, 32) {
            return Err($crate::stream::SerializeError::ReadPastEnd);
        }
        if !writing {
            $value = f32::from_bits(bits);
        }
    }};
}

/// serialize_bytes!(stream, slice) — byte-aligned bulk copy.
#[macro_export]
macro_rules! serialize_bytes {
    ($stream:expr, $data:expr) => {{
        if !$stream.serialize_bytes($data) {
            return Err($crate::stream::SerializeError::ReadPastEnd);
        }
    }};
}

// ── Error ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SerializeError {
    #[error("read past end of buffer")]
    ReadPastEnd,
    #[error("value out of valid range")]
    OutOfRange,
}

pub type SerializeResult<T> = Result<T, SerializeError>;

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serialize_bits, serialize_bool, serialize_float, serialize_int, serialize_uint64, serialize_bytes};

    fn write_read<F1, F2>(write_fn: F1, read_fn: F2)
    where
        F1: Fn(&mut WriteStream) -> SerializeResult<()>,
        F2: Fn(&mut ReadStream) -> SerializeResult<()>,
    {
        let mut ws = WriteStream::new(256);
        write_fn(&mut ws).unwrap();
        ws.flush();
        let data = ws.get_data().to_vec();
        let mut rs = ReadStream::new(&data);
        read_fn(&mut rs).unwrap();
    }

    #[test]
    fn bits_roundtrip() {
        write_read(
            |s| { let mut v = 42u32; serialize_bits!(s, v, 6u32); Ok(()) },
            |s| { let mut v = 0u32; serialize_bits!(s, v, 6u32); assert_eq!(v, 42); Ok(()) },
        );
    }

    #[test]
    fn bool_roundtrip() {
        write_read(
            |s| { let mut v = true; serialize_bool!(s, v); Ok(()) },
            |s| { let mut v = false; serialize_bool!(s, v); assert!(v); Ok(()) },
        );
    }

    #[test]
    fn int_roundtrip() {
        write_read(
            |s| { let mut v = -5i32; serialize_int!(s, v, -10i32, 10i32); Ok(()) },
            |s| { let mut v = 0i32; serialize_int!(s, v, -10i32, 10i32); assert_eq!(v, -5); Ok(()) },
        );
    }

    #[test]
    fn uint64_roundtrip() {
        write_read(
            |s| { let mut v = 0xDEAD_BEEF_CAFE_BABEu64; serialize_uint64!(s, v); Ok(()) },
            |s| { let mut v = 0u64; serialize_uint64!(s, v); assert_eq!(v, 0xDEAD_BEEF_CAFE_BABEu64); Ok(()) },
        );
    }

    #[test]
    fn float_roundtrip() {
        write_read(
            |s| { let mut v = 3.14f32; serialize_float!(s, v); Ok(()) },
            |s| { let mut v = 0.0f32; serialize_float!(s, v); assert_eq!(v, 3.14f32); Ok(()) },
        );
    }

    #[test]
    fn bytes_roundtrip() {
        let payload = b"hello_world";
        write_read(
            |s| { let mut d = payload.clone(); serialize_bytes!(s, &mut d[..]); Ok(()) },
            |s| {
                let mut out = [0u8; 11];
                serialize_bytes!(s, &mut out[..]);
                assert_eq!(&out, payload);
                Ok(())
            },
        );
    }

    #[test]
    fn read_past_end_returns_error() {
        let data = [0u8; 1]; // only 8 bits
        let mut rs = ReadStream::new(&data);
        let mut v = 0u32;
        // reading 9 bits from 1 byte should fail
        assert!(!rs.serialize_bits(&mut v, 9));
    }
}

