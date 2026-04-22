//! Port of sdk/include/next_read_write.h
//!
//! Flat little-endian byte serialization used by tokens and packet headers.
//! This is distinct from the bitpacking stream (mod stream).

use crate::address::Address;
use crate::constants::*;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReadWriteError {
    #[error("read past end of buffer (need {need} bytes, have {have})")]
    ReadPastEnd { need: usize, have: usize },
    #[error("write past end of buffer")]
    WritePastEnd,
    #[error("invalid address type {0}")]
    InvalidAddressType(u8),
}
pub type RwResult<T> = Result<T, ReadWriteError>;

// ── WriteBuf ───────────────────────────────────────────────────────────────

pub struct WriteBuf<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> WriteBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        WriteBuf { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn write_u8(&mut self, v: u8) -> RwResult<()> {
        self.check_write(1)?;
        self.buf[self.pos] = v;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u16_le(&mut self, v: u16) -> RwResult<()> {
        self.check_write(2)?;
        self.buf[self.pos..self.pos + 2].copy_from_slice(&v.to_le_bytes());
        self.pos += 2;
        Ok(())
    }

    pub fn write_u32_le(&mut self, v: u32) -> RwResult<()> {
        self.check_write(4)?;
        self.buf[self.pos..self.pos + 4].copy_from_slice(&v.to_le_bytes());
        self.pos += 4;
        Ok(())
    }

    pub fn write_u64_le(&mut self, v: u64) -> RwResult<()> {
        self.check_write(8)?;
        self.buf[self.pos..self.pos + 8].copy_from_slice(&v.to_le_bytes());
        self.pos += 8;
        Ok(())
    }

    pub fn write_bytes(&mut self, data: &[u8]) -> RwResult<()> {
        self.check_write(data.len())?;
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }

    /// Write address using flat format (1-byte type tag, then raw bytes).
    pub fn write_address(&mut self, addr: &Address) -> RwResult<()> {
        match addr {
            Address::None => self.write_u8(ADDRESS_NONE),
            Address::V4 { octets, port } => {
                self.write_u8(ADDRESS_IPV4)?;
                self.write_bytes(octets)?;
                self.write_u16_le(*port)
            }
            Address::V6 { words, port } => {
                self.write_u8(ADDRESS_IPV6)?;
                for w in words {
                    self.write_u16_le(*w)?;
                }
                self.write_u16_le(*port)
            }
        }
    }

    fn check_write(&self, n: usize) -> RwResult<()> {
        if self.pos + n > self.buf.len() {
            Err(ReadWriteError::WritePastEnd)
        } else {
            Ok(())
        }
    }
}

// ── ReadBuf ────────────────────────────────────────────────────────────────

pub struct ReadBuf<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ReadBuf<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        ReadBuf { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn read_u8(&mut self) -> RwResult<u8> {
        self.check_read(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16_le(&mut self) -> RwResult<u16> {
        self.check_read(2)?;
        let v = u16::from_le_bytes(self.buf[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(v)
    }

    pub fn read_u32_le(&mut self) -> RwResult<u32> {
        self.check_read(4)?;
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    pub fn read_u64_le(&mut self) -> RwResult<u64> {
        self.check_read(8)?;
        let v = u64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    pub fn read_bytes(&mut self, out: &mut [u8]) -> RwResult<()> {
        let n = out.len();
        self.check_read(n)?;
        out.copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(())
    }

    pub fn read_bytes_vec(&mut self, n: usize) -> RwResult<Vec<u8>> {
        self.check_read(n)?;
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }

    /// Read address using flat format (1-byte type tag, then raw bytes).
    pub fn read_address(&mut self) -> RwResult<Address> {
        let ty = self.read_u8()?;
        match ty {
            t if t == ADDRESS_NONE => Ok(Address::None),
            t if t == ADDRESS_IPV4 => {
                let mut octets = [0u8; 4];
                self.read_bytes(&mut octets)?;
                let port = self.read_u16_le()?;
                Ok(Address::V4 { octets, port })
            }
            t if t == ADDRESS_IPV6 => {
                let mut words = [0u16; 8];
                for w in words.iter_mut() {
                    *w = self.read_u16_le()?;
                }
                let port = self.read_u16_le()?;
                Ok(Address::V6 { words, port })
            }
            t => Err(ReadWriteError::InvalidAddressType(t)),
        }
    }

    fn check_read(&self, n: usize) -> RwResult<()> {
        let have = self.remaining();
        if n > have {
            Err(ReadWriteError::ReadPastEnd { need: n, have })
        } else {
            Ok(())
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_primitives() {
        let mut buf = [0u8; 64];
        let mut w = WriteBuf::new(&mut buf);
        w.write_u8(0xAB).unwrap();
        w.write_u16_le(0x1234).unwrap();
        w.write_u32_le(0xDEAD_BEEF).unwrap();
        w.write_u64_le(0xCAFE_BABE_1234_5678).unwrap();
        let pos = w.pos();

        let mut r = ReadBuf::new(&buf[..pos]);
        assert_eq!(r.read_u8().unwrap(), 0xAB);
        assert_eq!(r.read_u16_le().unwrap(), 0x1234);
        assert_eq!(r.read_u32_le().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.read_u64_le().unwrap(), 0xCAFE_BABE_1234_5678);
    }

    #[test]
    fn roundtrip_address_ipv4() {
        let addr = Address::V4 {
            octets: [10, 0, 0, 1],
            port: 40000,
        };
        let mut buf = [0u8; 16];
        let mut w = WriteBuf::new(&mut buf);
        w.write_address(&addr).unwrap();
        let n = w.pos();
        let mut r = ReadBuf::new(&buf[..n]);
        assert_eq!(r.read_address().unwrap(), addr);
    }

    #[test]
    fn roundtrip_address_ipv6() {
        let addr = Address::V6 {
            words: [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1],
            port: 443,
        };
        let mut buf = [0u8; 32];
        let mut w = WriteBuf::new(&mut buf);
        w.write_address(&addr).unwrap();
        let n = w.pos();
        let mut r = ReadBuf::new(&buf[..n]);
        assert_eq!(r.read_address().unwrap(), addr);
    }

    #[test]
    fn read_past_end_returns_error() {
        let buf = [0u8; 1];
        let mut r = ReadBuf::new(&buf);
        assert!(r.read_u16_le().is_err());
    }

    #[test]
    fn write_past_end_returns_error() {
        let mut buf = [0u8; 1];
        let mut w = WriteBuf::new(&mut buf);
        assert!(w.write_u16_le(1).is_err());
    }
}
