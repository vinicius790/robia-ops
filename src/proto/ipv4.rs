//! IPv4 (RFC 791) — cabeçalho mínimo 20 bytes, sem opções neste MVP.

use crate::checksum::internet_checksum;
use crate::error::{Error, Result};

pub const IPV4_HEADER_MIN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Other(u8),
}

impl IpProtocol {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            x => Self::Other(x),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Other(x) => x,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_frag: u16, // DF/MF + offset
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub checksum: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

impl Ipv4Header {
    pub fn new(src: [u8; 4], dst: [u8; 4], protocol: IpProtocol, payload_len: usize) -> Self {
        let total = (IPV4_HEADER_MIN + payload_len) as u16;
        Self {
            tos: 0,
            total_length: total,
            identification: 0,
            flags_frag: 0x4000, // DF
            ttl: 64,
            protocol,
            checksum: 0,
            src,
            dst,
        }
    }

    pub fn parse(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < IPV4_HEADER_MIN {
            return Err(Error::Truncated {
                layer: "ipv4",
                need: IPV4_HEADER_MIN,
                got: buf.len(),
            });
        }
        let ver_ihl = buf[0];
        let version = ver_ihl >> 4;
        let ihl = (ver_ihl & 0x0f) as usize * 4;
        if version != 4 {
            return Err(Error::Unsupported("ipv4: versão ≠ 4"));
        }
        if ihl < IPV4_HEADER_MIN || buf.len() < ihl {
            return Err(Error::Truncated {
                layer: "ipv4-ihl",
                need: ihl,
                got: buf.len(),
            });
        }
        // Valida checksum do cabeçalho
        if internet_checksum(&buf[..ihl]) != 0 {
            return Err(Error::BadChecksum("ipv4"));
        }
        let mut src = [0u8; 4];
        let mut dst = [0u8; 4];
        src.copy_from_slice(&buf[12..16]);
        dst.copy_from_slice(&buf[16..20]);
        let h = Self {
            tos: buf[1],
            total_length: u16::from_be_bytes([buf[2], buf[3]]),
            identification: u16::from_be_bytes([buf[4], buf[5]]),
            flags_frag: u16::from_be_bytes([buf[6], buf[7]]),
            ttl: buf[8],
            protocol: IpProtocol::from_u8(buf[9]),
            checksum: u16::from_be_bytes([buf[10], buf[11]]),
            src,
            dst,
        };
        Ok((h, ihl))
    }

    /// Codifica cabeçalho com checksum recalculado.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; IPV4_HEADER_MIN];
        out[0] = 0x45; // v4, IHL=5
        out[1] = self.tos;
        out[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        out[4..6].copy_from_slice(&self.identification.to_be_bytes());
        out[6..8].copy_from_slice(&self.flags_frag.to_be_bytes());
        out[8] = self.ttl;
        out[9] = self.protocol.as_u8();
        out[10] = 0;
        out[11] = 0;
        out[12..16].copy_from_slice(&self.src);
        out[16..20].copy_from_slice(&self.dst);
        let csum = internet_checksum(&out);
        out[10..12].copy_from_slice(&csum.to_be_bytes());
        out
    }
}

/// Empacota cabeçalho + payload em um datagrama IPv4.
pub fn encapsulate(src: [u8; 4], dst: [u8; 4], protocol: IpProtocol, payload: &[u8]) -> Vec<u8> {
    let hdr = Ipv4Header::new(src, dst, protocol, payload.len());
    let mut out = hdr.encode();
    out.extend_from_slice(payload);
    // Atualiza total_length se necessário (já correto em new)
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_parse_checksum_ok() {
        let payload = b"hello";
        let pkt = encapsulate([10, 0, 0, 1], [10, 0, 0, 2], IpProtocol::Udp, payload);
        let (h, ihl) = Ipv4Header::parse(&pkt).unwrap();
        assert_eq!(ihl, 20);
        assert_eq!(h.src, [10, 0, 0, 1]);
        assert_eq!(h.dst, [10, 0, 0, 2]);
        assert_eq!(h.protocol, IpProtocol::Udp);
        assert_eq!(&pkt[ihl..], payload);
    }

    #[test]
    fn bad_checksum_detected() {
        let mut pkt = encapsulate([1, 1, 1, 1], [2, 2, 2, 2], IpProtocol::Icmp, &[8, 0]);
        pkt[10] ^= 0xff;
        assert!(matches!(
            Ipv4Header::parse(&pkt),
            Err(Error::BadChecksum(_))
        ));
    }
}
