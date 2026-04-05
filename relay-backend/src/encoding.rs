//! Binary serialization with bitpacking.
//! Port of `modules/encoding/` (bitpacker.go, read_stream.go, write_stream.go, encoding.go).

#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::constants::*;

// -------------------------------------------------------
// Bit utilities
// -------------------------------------------------------

pub fn log2(x: u32) -> u32 {
    let a = x | (x >> 1);
    let b = a | (a >> 2);
    let c = b | (b >> 4);
    let d = c | (c >> 8);
    let e = d | (d >> 16);
    let f = e >> 1;
    f.count_ones()
}

pub fn bits_required(min: u32, max: u32) -> u32 {
    if min == max {
        0
    } else {
        log2(max.wrapping_sub(min)) + 1
    }
}

pub fn bits_required_signed(min: i32, max: i32) -> u32 {
    if min == max {
        0
    } else {
        log2((max.wrapping_sub(min)) as u32) + 1
    }
}

pub fn tri_matrix_length(size: usize) -> usize {
    (size * (size.wrapping_sub(1))) / 2
}

pub fn tri_matrix_index(i: usize, j: usize) -> usize {
    let (i, j) = if i > j { (i, j) } else { (j, i) };
    i * (i + 1) / 2 - i + j
}

// -------------------------------------------------------
// BitWriter
// -------------------------------------------------------

pub struct BitWriter {
    buffer: Vec<u8>,
    scratch: u64,
    _num_bits: usize,
    bits_written: usize,
    word_index: usize,
    scratch_bits: usize,
    _num_words: usize,
}

impl BitWriter {
    pub fn new(size: usize) -> Self {
        let aligned = (size + 3) & !3;
        BitWriter {
            buffer: vec![0u8; aligned],
            scratch: 0,
            _num_bits: (aligned / 4) * 32,
            bits_written: 0,
            word_index: 0,
            scratch_bits: 0,
            _num_words: aligned / 4,
        }
    }

    pub fn write_bits(&mut self, value: u32, bits: usize) {
        self.scratch |= (value as u64) << self.scratch_bits;
        self.scratch_bits += bits;

        if self.scratch_bits >= 32 {
            let word = (self.scratch & 0xFFFFFFFF) as u32;
            let offset = self.word_index * 4;
            self.buffer[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
            self.scratch >>= 32;
            self.scratch_bits -= 32;
            self.word_index += 1;
        }

        self.bits_written += bits;
    }

    pub fn write_align(&mut self) {
        let remainder = self.bits_written % 8;
        if remainder != 0 {
            self.write_bits(0, 8 - remainder);
        }
    }

    pub fn write_bytes(&mut self, data: &[u8]) {
        let head_bytes = (4 - (self.bits_written % 32) / 8) % 4;
        let head_bytes = head_bytes.min(data.len());

        for &byte in data.iter().take(head_bytes) {
            self.write_bits(byte as u32, 8);
        }

        if head_bytes == data.len() {
            return;
        }

        self.flush_bits();

        let num_words = (data.len() - head_bytes) / 4;
        for i in 0..num_words {
            let offset = head_bytes + i * 4;
            let word = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let buf_offset = self.word_index * 4;
            self.buffer[buf_offset..buf_offset + 4].copy_from_slice(&word.to_le_bytes());
            self.bits_written += 32;
            self.word_index += 1;
        }

        self.scratch = 0;

        let tail_start = head_bytes + num_words * 4;
        let tail_bytes = data.len() - tail_start;
        for i in 0..tail_bytes {
            self.write_bits(data[tail_start + i] as u32, 8);
        }
    }

    pub fn flush_bits(&mut self) {
        if self.scratch_bits != 0 {
            let word = (self.scratch & 0xFFFFFFFF) as u32;
            let offset = self.word_index * 4;
            self.buffer[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
            self.scratch >>= 32;
            self.scratch_bits = 0;
            self.word_index += 1;
        }
    }

    pub fn get_bytes_written(&self) -> usize {
        self.bits_written.div_ceil(8)
    }

    pub fn get_bits_written(&self) -> usize {
        self.bits_written
    }

    pub fn get_data(&self) -> &[u8] {
        &self.buffer
    }
}

// -------------------------------------------------------
// BitReader
// -------------------------------------------------------

pub struct BitReader {
    buffer: Vec<u8>,
    num_bits: usize,
    num_words: usize,
    bits_read: usize,
    scratch: u64,
    scratch_bits: usize,
    word_index: usize,
}

impl BitReader {
    pub fn new(data: &[u8]) -> Self {
        BitReader {
            buffer: data.to_vec(),
            num_bits: data.len() * 8,
            num_words: data.len().div_ceil(4),
            bits_read: 0,
            scratch: 0,
            scratch_bits: 0,
            word_index: 0,
        }
    }

    pub fn would_read_past_end(&self, bits: usize) -> bool {
        self.bits_read + bits > self.num_bits
    }

    pub fn read_bits(&mut self, bits: usize) -> Result<u32, &'static str> {
        if self.bits_read + bits > self.num_bits {
            return Err("would read past end of buffer");
        }

        self.bits_read += bits;

        if self.scratch_bits < bits {
            if self.word_index >= self.num_words {
                return Err("would read past end of buffer");
            }
            let offset = self.word_index * 4;
            let word = if offset + 4 <= self.buffer.len() {
                u32::from_le_bytes([
                    self.buffer[offset],
                    self.buffer[offset + 1],
                    self.buffer[offset + 2],
                    self.buffer[offset + 3],
                ])
            } else {
                // Partial word at end of buffer
                let mut bytes = [0u8; 4];
                let len = (self.buffer.len() - offset).min(4);
                bytes[..len].copy_from_slice(&self.buffer[offset..offset + len]);
                u32::from_le_bytes(bytes)
            };
            self.scratch |= (word as u64) << self.scratch_bits;
            self.scratch_bits += 32;
            self.word_index += 1;
        }

        let mask = if bits == 32 {
            0xFFFFFFFF_u64
        } else {
            (1u64 << bits) - 1
        };
        let output = self.scratch & mask;
        self.scratch >>= bits;
        self.scratch_bits -= bits;

        Ok(output as u32)
    }

    pub fn read_align(&mut self) -> Result<(), &'static str> {
        let remainder = self.bits_read % 8;
        if remainder != 0 {
            self.read_bits(8 - remainder)?;
        }
        Ok(())
    }

    pub fn read_bytes(&mut self, buffer: &mut [u8]) -> Result<(), &'static str> {
        if self.bits_read + buffer.len() * 8 > self.num_bits {
            return Err("would read past end of buffer");
        }

        let head_bytes = (4 - (self.bits_read % 32) / 8) % 4;
        let head_bytes = head_bytes.min(buffer.len());
        for item in buffer.iter_mut().take(head_bytes) {
            *item = self.read_bits(8)? as u8;
        }
        if head_bytes == buffer.len() {
            return Ok(());
        }

        let num_words = (buffer.len() - head_bytes) / 4;
        for i in 0..num_words {
            let src_offset = self.word_index * 4;
            let dst_offset = head_bytes + i * 4;
            buffer[dst_offset..dst_offset + 4]
                .copy_from_slice(&self.buffer[src_offset..src_offset + 4]);
            self.bits_read += 32;
            self.word_index += 1;
        }
        self.scratch_bits = 0;

        let tail_start = head_bytes + num_words * 4;
        let tail_bytes = buffer.len() - tail_start;
        for i in 0..tail_bytes {
            buffer[tail_start + i] = self.read_bits(8)? as u8;
        }

        Ok(())
    }

    pub fn get_align_bits(&self) -> usize {
        (8 - self.bits_read % 8) % 8
    }

    pub fn get_bits_read(&self) -> usize {
        self.bits_read
    }
}

// -------------------------------------------------------
// WriteStream - high-level serialization (write mode)
// -------------------------------------------------------

pub struct WriteStream {
    writer: BitWriter,
    err: Option<String>,
}

impl WriteStream {
    pub fn new(size: usize) -> Self {
        WriteStream {
            writer: BitWriter::new(size),
            err: None,
        }
    }

    fn set_error(&mut self, msg: &str) {
        if self.err.is_none() {
            self.err = Some(msg.to_string());
        }
    }

    pub fn error(&self) -> Option<&str> {
        self.err.as_deref()
    }

    pub fn serialize_integer(&mut self, value: i32, min: i32, max: i32) {
        if self.err.is_some() {
            return;
        }
        if min >= max {
            self.set_error("min should be less than max");
            return;
        }
        if value < min || value > max {
            self.set_error("value out of range");
            return;
        }
        let bits = bits_required(min as u32, max as u32) as usize;
        let unsigned_value = (value - min) as u32;
        self.writer.write_bits(unsigned_value, bits);
    }

    pub fn serialize_bits(&mut self, value: u32, bits: usize) {
        if self.err.is_some() {
            return;
        }
        self.writer.write_bits(value, bits);
    }

    pub fn serialize_uint32(&mut self, value: u32) {
        self.serialize_bits(value, 32);
    }

    pub fn serialize_bool(&mut self, value: bool) {
        if self.err.is_some() {
            return;
        }
        self.writer.write_bits(if value { 1 } else { 0 }, 1);
    }

    pub fn serialize_float32(&mut self, value: f32) {
        if self.err.is_some() {
            return;
        }
        self.writer.write_bits(value.to_bits(), 32);
    }

    pub fn serialize_uint64(&mut self, value: u64) {
        if self.err.is_some() {
            return;
        }
        let lo = (value & 0xFFFFFFFF) as u32;
        let hi = (value >> 32) as u32;
        self.serialize_bits(lo, 32);
        self.serialize_bits(hi, 32);
    }

    pub fn serialize_bytes(&mut self, data: &[u8]) {
        if self.err.is_some() || data.is_empty() {
            return;
        }
        self.serialize_align();
        self.writer.write_bytes(data);
    }

    pub fn serialize_string(&mut self, value: &str, max_size: usize) {
        if self.err.is_some() {
            return;
        }
        let length = value.len() as i32;
        let min = 0i32;
        let max = (max_size as i32) - 1;
        self.serialize_integer(length, min, max);
        if length > 0 {
            self.serialize_bytes(value.as_bytes());
        }
    }

    pub fn serialize_address(&mut self, addr: &SocketAddrV4) {
        if self.err.is_some() {
            return;
        }
        let ip = addr.ip();
        if ip.is_unspecified() && addr.port() == 0 {
            self.serialize_bits(IP_ADDRESS_NONE, 2);
        } else {
            self.serialize_bits(IP_ADDRESS_IPV4, 2);
            self.serialize_bytes(&ip.octets());
            self.serialize_bits(addr.port() as u32, 16);
        }
    }

    pub fn serialize_align(&mut self) {
        if self.err.is_some() {
            return;
        }
        self.writer.write_align();
    }

    pub fn flush(&mut self) {
        if self.err.is_some() {
            return;
        }
        self.writer.flush_bits();
    }

    pub fn get_data(&self) -> &[u8] {
        self.writer.get_data()
    }

    pub fn get_bytes_processed(&self) -> usize {
        self.writer.get_bytes_written()
    }

    pub fn get_bits_processed(&self) -> usize {
        self.writer.get_bits_written()
    }
}

// -------------------------------------------------------
// ReadStream - high-level serialization (read mode)
// -------------------------------------------------------

pub struct ReadStream {
    reader: BitReader,
    err: Option<String>,
}

impl ReadStream {
    pub fn new(data: &[u8]) -> Self {
        ReadStream {
            reader: BitReader::new(data),
            err: None,
        }
    }

    fn set_error(&mut self, msg: &str) {
        if self.err.is_none() {
            self.err = Some(msg.to_string());
        }
    }

    pub fn error(&self) -> Option<&str> {
        self.err.as_deref()
    }

    pub fn serialize_integer(&mut self, min: i32, max: i32) -> i32 {
        if self.err.is_some() {
            return 0;
        }
        if min >= max {
            self.set_error("min should be less than max");
            return 0;
        }
        let bits = bits_required_signed(min, max) as usize;
        if self.reader.would_read_past_end(bits) {
            self.set_error("would read past end of buffer");
            return 0;
        }
        match self.reader.read_bits(bits) {
            Ok(unsigned_value) => {
                let candidate = (unsigned_value as i32) + min;
                if candidate > max {
                    self.set_error("value above max");
                    return 0;
                }
                candidate
            }
            Err(e) => {
                self.set_error(e);
                0
            }
        }
    }

    pub fn serialize_bits(&mut self, bits: usize) -> u32 {
        if self.err.is_some() {
            return 0;
        }
        if self.reader.would_read_past_end(bits) {
            self.set_error("would read past end of buffer");
            return 0;
        }
        match self.reader.read_bits(bits) {
            Ok(v) => v,
            Err(e) => {
                self.set_error(e);
                0
            }
        }
    }

    pub fn serialize_uint32(&mut self) -> u32 {
        self.serialize_bits(32)
    }

    pub fn serialize_bool(&mut self) -> bool {
        if self.err.is_some() {
            return false;
        }
        if self.reader.would_read_past_end(1) {
            self.set_error("would read past end of buffer");
            return false;
        }
        match self.reader.read_bits(1) {
            Ok(v) => v != 0,
            Err(e) => {
                self.set_error(e);
                false
            }
        }
    }

    pub fn serialize_float32(&mut self) -> f32 {
        if self.err.is_some() {
            return 0.0;
        }
        if self.reader.would_read_past_end(32) {
            self.set_error("would read past end of buffer");
            return 0.0;
        }
        match self.reader.read_bits(32) {
            Ok(v) => f32::from_bits(v),
            Err(e) => {
                self.set_error(e);
                0.0
            }
        }
    }

    pub fn serialize_uint64(&mut self) -> u64 {
        if self.err.is_some() {
            return 0;
        }
        let lo = self.serialize_bits(32);
        let hi = self.serialize_bits(32);
        ((hi as u64) << 32) | (lo as u64)
    }

    pub fn serialize_bytes(&mut self, buffer: &mut [u8]) {
        if self.err.is_some() || buffer.is_empty() {
            return;
        }
        self.serialize_align();
        if self.err.is_some() {
            return;
        }
        if self.reader.would_read_past_end(buffer.len() * 8) {
            self.set_error("would read past end of buffer");
            return;
        }
        if let Err(e) = self.reader.read_bytes(buffer) {
            self.set_error(e);
        }
    }

    pub fn serialize_string(&mut self, max_size: usize) -> String {
        if self.err.is_some() {
            return String::new();
        }
        let min = 0i32;
        let max = (max_size as i32) - 1;
        let length = self.serialize_integer(min, max);
        if self.err.is_some() || length == 0 {
            return String::new();
        }
        let mut bytes = vec![0u8; length as usize];
        self.serialize_bytes(&mut bytes);
        String::from_utf8_lossy(&bytes).to_string()
    }

    pub fn serialize_address(&mut self) -> SocketAddrV4 {
        if self.err.is_some() {
            return SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        }
        let addr_type = self.serialize_bits(2);
        if self.err.is_some() {
            return SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        }
        if addr_type == IP_ADDRESS_IPV4 {
            let mut ip_bytes = [0u8; 4];
            self.serialize_bytes(&mut ip_bytes);
            if self.err.is_some() {
                return SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
            }
            let port = self.serialize_bits(16) as u16;
            SocketAddrV4::new(
                Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]),
                port,
            )
        } else {
            // For IPv6 and None, return unspecified
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
        }
    }

    pub fn serialize_align(&mut self) {
        if self.err.is_some() {
            return;
        }
        let align_bits = self.reader.get_align_bits();
        if self.reader.would_read_past_end(align_bits) {
            self.set_error("would read past end of buffer");
            return;
        }
        if let Err(e) = self.reader.read_align() {
            self.set_error(e);
        }
    }

    pub fn get_bits_processed(&self) -> usize {
        self.reader.get_bits_read()
    }

    pub fn get_bytes_processed(&self) -> usize {
        self.reader.get_bits_read().div_ceil(8)
    }
}

// -------------------------------------------------------
// Simple LE encoding (non-bitpacked, for relay update packets)
// -------------------------------------------------------

pub struct SimpleReader<'a> {
    data: &'a [u8],
    index: usize,
}

impl<'a> SimpleReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        SimpleReader { data, index: 0 }
    }

    pub fn read_uint8(&mut self) -> Option<u8> {
        if self.index + 1 > self.data.len() {
            return None;
        }
        let v = self.data[self.index];
        self.index += 1;
        Some(v)
    }

    pub fn read_uint16(&mut self) -> Option<u16> {
        if self.index + 2 > self.data.len() {
            return None;
        }
        let v = u16::from_le_bytes([self.data[self.index], self.data[self.index + 1]]);
        self.index += 2;
        Some(v)
    }

    pub fn read_uint32(&mut self) -> Option<u32> {
        if self.index + 4 > self.data.len() {
            return None;
        }
        let v = u32::from_le_bytes([
            self.data[self.index],
            self.data[self.index + 1],
            self.data[self.index + 2],
            self.data[self.index + 3],
        ]);
        self.index += 4;
        Some(v)
    }

    pub fn read_uint64(&mut self) -> Option<u64> {
        if self.index + 8 > self.data.len() {
            return None;
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[self.index..self.index + 8]);
        self.index += 8;
        Some(u64::from_le_bytes(bytes))
    }

    pub fn read_float32(&mut self) -> Option<f32> {
        self.read_uint32().map(f32::from_bits)
    }

    pub fn read_string(&mut self, max_len: u32) -> Option<String> {
        let len = self.read_uint32()?;
        if len > max_len {
            return None;
        }
        if self.index + len as usize > self.data.len() {
            return None;
        }
        let s =
            String::from_utf8_lossy(&self.data[self.index..self.index + len as usize]).to_string();
        self.index += len as usize;
        Some(s)
    }

    pub fn read_address(&mut self) -> Option<SocketAddrV4> {
        let addr_type = self.read_uint8()?;
        match addr_type {
            0 => Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)), // NONE
            1 => {
                // IPv4
                if self.index + 6 > self.data.len() {
                    return None;
                }
                let ip = Ipv4Addr::new(
                    self.data[self.index],
                    self.data[self.index + 1],
                    self.data[self.index + 2],
                    self.data[self.index + 3],
                );
                let port =
                    u16::from_le_bytes([self.data[self.index + 4], self.data[self.index + 5]]);
                self.index += 6;
                Some(SocketAddrV4::new(ip, port))
            }
            2 => {
                // IPv6 - skip 18 bytes
                if self.index + 18 > self.data.len() {
                    return None;
                }
                self.index += 18;
                Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
            }
            _ => None,
        }
    }

    pub fn read_bytes(&mut self, len: usize) -> Option<Vec<u8>> {
        if self.index + len > self.data.len() {
            return None;
        }
        let v = self.data[self.index..self.index + len].to_vec();
        self.index += len;
        Some(v)
    }
}

pub struct SimpleWriter {
    data: Vec<u8>,
    index: usize,
}

impl SimpleWriter {
    pub fn new(size: usize) -> Self {
        SimpleWriter {
            data: vec![0u8; size],
            index: 0,
        }
    }

    pub fn write_uint8(&mut self, value: u8) {
        self.data[self.index] = value;
        self.index += 1;
    }

    pub fn write_uint16(&mut self, value: u16) {
        self.data[self.index..self.index + 2].copy_from_slice(&value.to_le_bytes());
        self.index += 2;
    }

    pub fn write_uint32(&mut self, value: u32) {
        self.data[self.index..self.index + 4].copy_from_slice(&value.to_le_bytes());
        self.index += 4;
    }

    pub fn write_uint64(&mut self, value: u64) {
        self.data[self.index..self.index + 8].copy_from_slice(&value.to_le_bytes());
        self.index += 8;
    }

    pub fn write_float32(&mut self, value: f32) {
        self.write_uint32(value.to_bits());
    }

    pub fn write_string(&mut self, value: &str, _max_len: u32) {
        let len = value.len() as u32;
        self.write_uint32(len);
        for b in value.bytes() {
            self.data[self.index] = b;
            self.index += 1;
        }
    }

    pub fn write_address(&mut self, addr: &SocketAddrV4) {
        let ip = addr.ip();
        if ip.is_unspecified() && addr.port() == 0 {
            self.write_uint8(0); // NONE
        } else {
            self.write_uint8(1); // IPv4
            let octets = ip.octets();
            self.data[self.index..self.index + 4].copy_from_slice(&octets);
            self.index += 4;
            self.data[self.index..self.index + 2].copy_from_slice(&addr.port().to_le_bytes());
            self.index += 2;
        }
    }

    pub fn write_bytes(&mut self, data: &[u8]) {
        self.data[self.index..self.index + data.len()].copy_from_slice(data);
        self.index += data.len();
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data[..self.index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits_required() {
        assert_eq!(bits_required(0, 0), 0);
        assert_eq!(bits_required(0, 1), 1);
        assert_eq!(bits_required(0, 255), 8);
        assert_eq!(bits_required(0, 16), 5);
    }

    #[test]
    fn test_tri_matrix() {
        assert_eq!(tri_matrix_length(0), 0);
        assert_eq!(tri_matrix_length(1), 0);
        assert_eq!(tri_matrix_length(2), 1);
        assert_eq!(tri_matrix_length(3), 3);
        assert_eq!(tri_matrix_length(4), 6);
        assert_eq!(tri_matrix_index(1, 0), 0);
        assert_eq!(tri_matrix_index(0, 1), 0);
        assert_eq!(tri_matrix_index(2, 0), 1);
        assert_eq!(tri_matrix_index(2, 1), 2);
    }

    #[test]
    fn test_write_read_roundtrip() {
        let mut ws = WriteStream::new(1024);
        ws.serialize_uint32(42);
        ws.serialize_uint64(0xDEADBEEFCAFEBABE);
        ws.serialize_float32(3.14);
        ws.serialize_bool(true);
        ws.serialize_bool(false);
        ws.serialize_integer(100, 0, 255);
        ws.serialize_string("hello", MAX_RELAY_NAME_LENGTH);
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
        ws.serialize_address(&addr);
        ws.flush();
        assert!(ws.error().is_none());

        let data = &ws.get_data()[..ws.get_bytes_processed()];
        let mut rs = ReadStream::new(data);
        assert_eq!(rs.serialize_uint32(), 42);
        assert_eq!(rs.serialize_uint64(), 0xDEADBEEFCAFEBABE);
        assert!((rs.serialize_float32() - 3.14).abs() < 0.001);
        assert!(rs.serialize_bool());
        assert!(!rs.serialize_bool());
        assert_eq!(rs.serialize_integer(0, 255), 100);
        assert_eq!(rs.serialize_string(MAX_RELAY_NAME_LENGTH), "hello");
        let read_addr = rs.serialize_address();
        assert_eq!(read_addr, addr);
        assert!(rs.error().is_none());
    }
}
