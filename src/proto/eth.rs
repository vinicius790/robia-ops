//! Ethernet II (DIX) + suporte opcional a VLAN IEEE 802.1Q (tag de 4 bytes, TPID 0x8100).

use crate::error::{Error, Result};

pub const ETH_HEADER_LEN: usize = 14;
pub const VLAN_TAG_LEN: usize = 4;
pub const ETHERTYPE_VLAN_8021Q: u16 = 0x8100;
pub const MAC_BROADCAST: [u8; 6] = [0xff; 6];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanTag {
    /// Priority Code Point (0..=7).
    pub pcp: u8,
    /// Drop Eligible Indicator.
    pub dei: bool,
    /// VLAN Identifier (0..=4095).
    pub vid: u16,
}

impl VlanTag {
    pub fn new(vid: u16) -> Self {
        Self {
            pcp: 0,
            dei: false,
            vid: vid & 0x0fff,
        }
    }

    pub fn from_tci(tci: u16) -> Self {
        Self {
            pcp: ((tci >> 13) & 0x07) as u8,
            dei: ((tci >> 12) & 0x01) != 0,
            vid: tci & 0x0fff,
        }
    }

    pub fn to_tci(self) -> u16 {
        (((self.pcp & 0x07) as u16) << 13)
            | (if self.dei { 1u16 << 12 } else { 0 })
            | (self.vid & 0x0fff)
    }
}

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
    pub vlan: Option<VlanTag>,
    pub ethertype: EtherType,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    pub fn new(dst: [u8; 6], src: [u8; 6], ethertype: EtherType, payload: Vec<u8>) -> Self {
        Self {
            dst,
            src,
            vlan: None,
            ethertype,
            payload,
        }
    }

    pub fn with_vlan(
        dst: [u8; 6],
        src: [u8; 6],
        vlan: VlanTag,
        ethertype: EtherType,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            dst,
            src,
            vlan: Some(vlan),
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
        let et_or_tpid = u16::from_be_bytes([frame[12], frame[13]]);
        if et_or_tpid == ETHERTYPE_VLAN_8021Q {
            let need = ETH_HEADER_LEN + VLAN_TAG_LEN;
            if frame.len() < need {
                return Err(Error::Truncated {
                    layer: "ethernet-8021q",
                    need,
                    got: frame.len(),
                });
            }
            let tci = u16::from_be_bytes([frame[14], frame[15]]);
            let inner_et = u16::from_be_bytes([frame[16], frame[17]]);
            return Ok(Self {
                dst,
                src,
                vlan: Some(VlanTag::from_tci(tci)),
                ethertype: EtherType::from_u16(inner_et),
                payload: frame[need..].to_vec(),
            });
        }
        Ok(Self {
            dst,
            src,
            vlan: None,
            ethertype: EtherType::from_u16(et_or_tpid),
            payload: frame[ETH_HEADER_LEN..].to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let extra = if self.vlan.is_some() { VLAN_TAG_LEN } else { 0 };
        let mut out = Vec::with_capacity(ETH_HEADER_LEN + extra + self.payload.len());
        out.extend_from_slice(&self.dst);
        out.extend_from_slice(&self.src);
        if let Some(tag) = self.vlan {
            out.extend_from_slice(&ETHERTYPE_VLAN_8021Q.to_be_bytes());
            out.extend_from_slice(&tag.to_tci().to_be_bytes());
        }
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
    fn vlan_8021q_roundtrip() {
        let tag = VlanTag {
            pcp: 5,
            dei: true,
            vid: 100,
        };
        let f = EthernetFrame::with_vlan([0xaa; 6], [0xbb; 6], tag, EtherType::Ipv4, vec![1, 2, 3]);
        let raw = f.encode();
        assert_eq!(raw.len(), ETH_HEADER_LEN + VLAN_TAG_LEN + 3);
        let parsed = EthernetFrame::parse(&raw).unwrap();
        assert_eq!(parsed, f);
        assert_eq!(parsed.vlan.unwrap().vid, 100);
        assert_eq!(parsed.vlan.unwrap().pcp, 5);
        assert!(parsed.vlan.unwrap().dei);
    }

    #[test]
    fn truncated() {
        assert!(EthernetFrame::parse(&[0u8; 10]).is_err());
        // VLAN tag truncado
        let mut bad_vlan = vec![0u8; 16];
        bad_vlan[12] = 0x81;
        bad_vlan[13] = 0x00;
        assert!(EthernetFrame::parse(&bad_vlan).is_err());
    }
}
