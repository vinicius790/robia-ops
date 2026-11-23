//! Ethernet II (DIX) — 14 bytes de cabeçalho.

use crate::error::{Error, Result};

pub const ETH_HEADER_LEN: usize = 14;
pub const MAC_BROADCAST: [u8; 6] = [0xff; 6];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Other(u16),
}

impl EtherType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            x => Self::Other(x),
        }
    }

    pub fn as_u16(self) -> u16 {
        match self {
            Self::Ipv4 => 0x0800,
            Self::Arp => 0x0806,
            Self::Other(x) => x,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: EtherType,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    pub fn new(dst: [u8; 6], src: [u8; 6], ethertype: EtherType, payload: Vec<u8>) -> Self {
        Self {
            dst,
            src,
            ethertype,
            payload,
        }
    }

    pub fn parse(frame: &[u8]) -> Result<Self> {
        if frame.len() < ETH_HEADER_LEN {
            return Err(Error::Truncated {
                layer: "ethernet",
                need: ETH_HEADER_LEN,
                got: frame.len(),
            });
        }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&frame[0..6]);
        src.copy_from_slice(&frame[6..12]);
        let et = u16::from_be_bytes([frame[12], frame[13]]);
        Ok(Self {
            dst,
            src,
            ethertype: EtherType::from_u16(et),
            payload: frame[ETH_HEADER_LEN..].to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ETH_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.dst);
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.ethertype.as_u16().to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let f = EthernetFrame::new([0x11; 6], [0x22; 6], EtherType::Ipv4, vec![0x45, 0x00]);
        let raw = f.encode();
        let p = EthernetFrame::parse(&raw).unwrap();
        assert_eq!(p, f);
    }

    #[test]
    fn truncated() {
        assert!(EthernetFrame::parse(&[0u8; 10]).is_err());
    }
}
