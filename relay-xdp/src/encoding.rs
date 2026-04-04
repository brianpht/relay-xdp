//! Binary encoding helpers - little-endian wire format.

#![allow(dead_code)]


/// Writer: appends little-endian values to a byte buffer.
pub struct Writer<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn write_uint8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_uint16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_uint32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_uint64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_float32(&mut self, v: f32) {
        self.buf.extend_from_slice(&v.to_bits().to_le_bytes());
    }

    pub fn write_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn write_string(&mut self, s: &str, max_len: usize) {
        let bytes = s.as_bytes();
        let length = bytes.len().min(max_len - 1);
        self.write_uint32(length as u32);
        self.buf.extend_from_slice(&bytes[..length]);
    }

    /// Write an address in the relay update format: address_type(1) + ip(4, network order) + port(2, LE)
    pub fn write_address_ipv4(&mut self, address_be: u32, port: u16) {
        self.write_uint8(relay_xdp_common::RELAY_ADDRESS_IPV4);
        self.write_uint32(address_be);
        self.write_uint16(port);
    }

    pub fn position(&self) -> usize {
        self.buf.len()
    }
}

/// Reader: reads little-endian values from a byte slice.
/// All read methods return `Result` to avoid panics on truncated input.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

/// Error returned when a read exceeds available data.
#[derive(Debug, Clone)]
pub struct ReadError {
    pub needed: usize,
    pub available: usize,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "read requires {} bytes but only {} available",
            self.needed, self.available
        )
    }
}

impl std::error::Error for ReadError {}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Check that `n` bytes are available, returning an error if not.
    fn ensure(&self, n: usize) -> Result<(), ReadError> {
        if self.remaining() < n {
            Err(ReadError {
                needed: n,
                available: self.remaining(),
            })
        } else {
            Ok(())
        }
    }

    pub fn read_uint8(&mut self) -> Result<u8, ReadError> {
        self.ensure(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_uint16(&mut self) -> Result<u16, ReadError> {
        self.ensure(2)?;
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn read_uint32(&mut self) -> Result<u32, ReadError> {
        self.ensure(4)?;
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    pub fn read_uint64(&mut self) -> Result<u64, ReadError> {
        self.ensure(8)?;
        let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    pub fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, ReadError> {
        self.ensure(len)?;
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    pub fn read_bytes_into(&mut self, out: &mut [u8]) -> Result<(), ReadError> {
        let len = out.len();
        self.ensure(len)?;
        out.copy_from_slice(&self.data[self.pos..self.pos + len]);
        self.pos += len;
        Ok(())
    }

    /// Skip `n` bytes without allocating or copying.
    pub fn skip(&mut self, n: usize) -> Result<(), ReadError> {
        self.ensure(n)?;
        self.pos += n;
        Ok(())
    }

    pub fn read_string(&mut self, max_len: usize) -> Result<String, ReadError> {
        let length = self.read_uint32()? as usize;
        if length > max_len {
            return Ok(String::new());
        }
        self.ensure(length)?;
        let raw = &self.data[self.pos..self.pos + length];
        self.pos += length;
        Ok(String::from_utf8_lossy(raw).into_owned())
    }

    /// Read address in relay update response format: address_type(1) + ip(4) + port(2)
    /// Returns (address_host_order, port)
    pub fn read_address(&mut self) -> Result<(u32, u16), ReadError> {
        let _addr_type = self.read_uint8()?;
        let addr_be = self.read_uint32()?;
        let port = self.read_uint16()?;
        // Convert from big-endian (network order) to host order
        Ok((u32::from_be(addr_be), port))
    }

    /// Read address returning (host_order_addr, port)
    pub fn read_address_raw(&mut self) -> Result<(u32, u16), ReadError> {
        let addr = self.read_uint32()?;
        let port = self.read_uint16()?;
        Ok((addr, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_read_uint8() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.write_uint8(0x42);
        assert_eq!(buf, [0x42]);
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_uint8().unwrap(), 0x42);
    }

    #[test]
    fn test_write_read_uint16_le() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.write_uint16(0x1234);
        // Little-endian: low byte first
        assert_eq!(buf, [0x34, 0x12]);
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_uint16().unwrap(), 0x1234);
    }

    #[test]
    fn test_write_read_uint32_le() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.write_uint32(0xDEADBEEF);
        assert_eq!(buf, [0xEF, 0xBE, 0xAD, 0xDE]);
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_uint32().unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn test_write_read_uint64_le() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.write_uint64(0x0102030405060708);
        assert_eq!(buf, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_uint64().unwrap(), 0x0102030405060708);
    }

    #[test]
    fn test_write_read_float32() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.write_float32(1.0f32);
        // IEEE 754: 1.0 = 0x3F800000, LE = [0x00, 0x00, 0x80, 0x3F]
        assert_eq!(buf, [0x00, 0x00, 0x80, 0x3F]);
    }

    #[test]
    fn test_write_read_string_length_prefixed() {
        // C format: uint32 length + string bytes (no null terminator, no padding)
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.write_string("hello", 32);

        // First 4 bytes: LE uint32 length = 5
        assert_eq!(&buf[0..4], &[5, 0, 0, 0]);
        // Next 5 bytes: "hello"
        assert_eq!(&buf[4..9], b"hello");
        // Total: 9 bytes
        assert_eq!(buf.len(), 9);

        let mut r = Reader::new(&buf);
        assert_eq!(r.read_string(32).unwrap(), "hello");
    }

    #[test]
    fn test_write_read_string_truncation() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        // max_len=5, string "hello world" -> truncated to 4 chars (max_len - 1)
        w.write_string("hello world", 5);
        assert_eq!(&buf[0..4], &[4, 0, 0, 0]); // length = 4
        assert_eq!(&buf[4..8], b"hell");
    }

    #[test]
    fn test_write_read_address_ipv4() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        // Address 10.0.0.1 in big-endian = 0x0A000001
        w.write_address_ipv4(0x0A000001u32.to_be(), 40000);

        // byte[0] = RELAY_ADDRESS_IPV4 = 1
        assert_eq!(buf[0], 1);

        let mut r = Reader::new(&buf);
        let (_addr, port) = r.read_address().unwrap();
        assert_eq!(port, 40000);
    }

    #[test]
    fn test_mixed_read_write_sequence() {
        // Simulate a mini relay update payload header
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.write_uint8(1); // version
        w.write_uint8(1); // RELAY_ADDRESS_IPV4
        w.write_uint32(0x0100007F); // 127.0.0.1 in network order, stored LE
        w.write_uint16(40000);
        w.write_uint64(1234567890);
        w.write_uint64(9876543210);
        w.write_uint32(0); // num_relays

        let mut r = Reader::new(&buf);
        assert_eq!(r.read_uint8().unwrap(), 1);
        assert_eq!(r.read_uint8().unwrap(), 1);
        assert_eq!(r.read_uint32().unwrap(), 0x0100007F);
        assert_eq!(r.read_uint16().unwrap(), 40000);
        assert_eq!(r.read_uint64().unwrap(), 1234567890);
        assert_eq!(r.read_uint64().unwrap(), 9876543210);
        assert_eq!(r.read_uint32().unwrap(), 0);
    }

    #[test]
    fn test_reader_bounds_check() {
        let buf = [0x42];
        let mut r = Reader::new(&buf);
        assert!(r.read_uint8().is_ok());
        assert!(r.read_uint8().is_err()); // no more data
    }

    #[test]
    fn test_reader_short_buffer() {
        let buf = [0x01, 0x02]; // only 2 bytes
        let mut r = Reader::new(&buf);
        assert!(r.read_uint32().is_err()); // needs 4 bytes
    }
}
