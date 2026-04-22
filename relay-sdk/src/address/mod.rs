// mod address - relay-xdp wire encoding.
//
// Wire format (byte-level LE, matches relay-xdp encoding.rs):
//   V4: [type: u8 = 1][ip: 4 bytes network/BE][port: u16 LE]  = 7 bytes
//   V6: [type: u8 = 2][ip: 16 bytes network/BE][port: u16 LE] = 19 bytes
//   None: [type: u8 = 0]                                      = 1 byte
//
// Constants match relay-xdp-common: RELAY_ADDRESS_NONE/IPV4/IPV6

use crate::constants::{ADDRESS_IPV4, ADDRESS_IPV6, ADDRESS_NONE};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("buffer too small: need {need} bytes, have {have}")]
    BufferTooSmall { need: usize, have: usize },
    #[error("unknown address type: {0}")]
    UnknownType(u8),
    #[error("truncated data")]
    Truncated,
}

// ── Address ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Address {
    #[default]
    None,
    /// IPv4 address. `octets` are in network byte order (big-endian).
    V4 { octets: [u8; 4], port: u16 },
    /// IPv6 address. `words` are in network byte order (host u16 values).
    V6 { words: [u16; 8], port: u16 },
}

impl Address {
    pub fn from_ipv4(octets: [u8; 4], port: u16) -> Self {
        Address::V4 { octets, port }
    }

    pub fn from_ipv6(words: [u16; 8], port: u16) -> Self {
        Address::V6 { words, port }
    }

    pub fn address_type(&self) -> u8 {
        match self {
            Address::None => ADDRESS_NONE,
            Address::V4 { .. } => ADDRESS_IPV4,
            Address::V6 { .. } => ADDRESS_IPV6,
        }
    }

    pub fn port(&self) -> Option<u16> {
        match self {
            Address::None => None,
            Address::V4 { port, .. } | Address::V6 { port, .. } => Some(*port),
        }
    }

    /// Encoded byte length.
    pub fn encoded_len(&self) -> usize {
        match self {
            Address::None => 1,
            Address::V4 { .. } => 7,  // 1 + 4 + 2
            Address::V6 { .. } => 19, // 1 + 16 + 2
        }
    }

    /// Encode into `buf`, returns number of bytes written.
    /// Port is written little-endian; IP bytes are network (big-endian) order.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, AddressError> {
        match self {
            Address::None => {
                if buf.is_empty() {
                    return Err(AddressError::BufferTooSmall { need: 1, have: 0 });
                }
                buf[0] = ADDRESS_NONE;
                Ok(1)
            }
            Address::V4 { octets, port } => {
                if buf.len() < 7 {
                    return Err(AddressError::BufferTooSmall {
                        need: 7,
                        have: buf.len(),
                    });
                }
                buf[0] = ADDRESS_IPV4;
                buf[1..5].copy_from_slice(octets);
                buf[5..7].copy_from_slice(&port.to_le_bytes());
                Ok(7)
            }
            Address::V6 { words, port } => {
                if buf.len() < 19 {
                    return Err(AddressError::BufferTooSmall {
                        need: 19,
                        have: buf.len(),
                    });
                }
                buf[0] = ADDRESS_IPV6;
                for (i, w) in words.iter().enumerate() {
                    let be = w.to_be_bytes();
                    buf[1 + i * 2] = be[0];
                    buf[2 + i * 2] = be[1];
                }
                buf[17..19].copy_from_slice(&port.to_le_bytes());
                Ok(19)
            }
        }
    }

    /// Decode from `buf`. Returns `(Address, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), AddressError> {
        if buf.is_empty() {
            return Err(AddressError::Truncated);
        }
        match buf[0] {
            t if t == ADDRESS_NONE => Ok((Address::None, 1)),
            t if t == ADDRESS_IPV4 => {
                if buf.len() < 7 {
                    return Err(AddressError::BufferTooSmall {
                        need: 7,
                        have: buf.len(),
                    });
                }
                let octets = [buf[1], buf[2], buf[3], buf[4]];
                let port = u16::from_le_bytes([buf[5], buf[6]]);
                Ok((Address::V4 { octets, port }, 7))
            }
            t if t == ADDRESS_IPV6 => {
                if buf.len() < 19 {
                    return Err(AddressError::BufferTooSmall {
                        need: 19,
                        have: buf.len(),
                    });
                }
                let mut words = [0u16; 8];
                for (i, w) in words.iter_mut().enumerate() {
                    *w = u16::from_be_bytes([buf[1 + i * 2], buf[2 + i * 2]]);
                }
                let port = u16::from_le_bytes([buf[17], buf[18]]);
                Ok((Address::V6 { words, port }, 19))
            }
            t => Err(AddressError::UnknownType(t)),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::None => write!(f, "NONE"),
            Address::V4 { octets, port } => {
                write!(
                    f,
                    "{}.{}.{}.{}:{}",
                    octets[0], octets[1], octets[2], octets[3], port
                )
            }
            Address::V6 { words, port } => {
                let addr = Ipv6Addr::new(
                    words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7],
                );
                write!(f, "[{}]:{}", addr, port)
            }
        }
    }
}

impl FromStr for Address {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("none") {
            return Ok(Address::None);
        }
        let sa: SocketAddr = s
            .parse()
            .map_err(|e: std::net::AddrParseError| e.to_string())?;
        Ok(Address::from(sa))
    }
}

impl From<SocketAddr> for Address {
    fn from(sa: SocketAddr) -> Self {
        match sa.ip() {
            IpAddr::V4(v4) => Address::V4 {
                octets: v4.octets(),
                port: sa.port(),
            },
            IpAddr::V6(v6) => Address::V6 {
                words: v6.segments(),
                port: sa.port(),
            },
        }
    }
}

impl From<Address> for Option<SocketAddr> {
    fn from(a: Address) -> Self {
        match a {
            Address::None => None,
            Address::V4 { octets, port } => {
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
            }
            Address::V6 { words, port } => {
                Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(words)), port))
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(addr: Address) -> Address {
        let mut buf = [0u8; 32];
        let n = addr.encode(&mut buf).unwrap();
        let (decoded, consumed) = Address::decode(&buf[..n]).unwrap();
        assert_eq!(consumed, n);
        decoded
    }

    #[test]
    fn ipv4_roundtrip() {
        let a = Address::V4 {
            octets: [192, 168, 1, 1],
            port: 40000,
        };
        assert_eq!(roundtrip(a), a);
    }

    #[test]
    fn ipv6_roundtrip() {
        let a = Address::V6 {
            words: [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1],
            port: 443,
        };
        assert_eq!(roundtrip(a), a);
    }

    #[test]
    fn none_roundtrip() {
        assert_eq!(roundtrip(Address::None), Address::None);
    }

    #[test]
    fn parse_ipv4() {
        let a: Address = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            a,
            Address::V4 {
                octets: [127, 0, 0, 1],
                port: 8080
            }
        );
    }

    #[test]
    fn display_ipv4() {
        let a = Address::V4 {
            octets: [10, 0, 0, 1],
            port: 9999,
        };
        assert_eq!(a.to_string(), "10.0.0.1:9999");
    }

    #[test]
    fn ipv4_wire_bytes() {
        // 10.0.0.1:40000 -> [1][10][0][0][1][0x40][0x9C]
        // port 40000 = 0x9C40, LE -> [0x40, 0x9C]
        let a = Address::V4 {
            octets: [10, 0, 0, 1],
            port: 40000,
        };
        let mut buf = [0u8; 8];
        let n = a.encode(&mut buf).unwrap();
        assert_eq!(n, 7);
        assert_eq!(buf[0], 1); // ADDRESS_IPV4
        assert_eq!(&buf[1..5], &[10, 0, 0, 1]); // octets BE
        assert_eq!(u16::from_le_bytes([buf[5], buf[6]]), 40000); // port LE
    }

    #[test]
    fn encoded_len() {
        assert_eq!(Address::None.encoded_len(), 1);
        assert_eq!(
            Address::V4 {
                octets: [0; 4],
                port: 0
            }
            .encoded_len(),
            7
        );
        assert_eq!(
            Address::V6 {
                words: [0; 8],
                port: 0
            }
            .encoded_len(),
            19
        );
    }
}
