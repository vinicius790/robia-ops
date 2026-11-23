//! ARP IPv4 over Ethernet (RFC 826) — 28 bytes.

use crate::error::{Error, Result};

pub const ARP_PACKET_LEN: usize = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ArpOp {
    Request = 1,
    Reply = 2,
}

impl ArpOp {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Request),
            2 => Some(Self::Reply),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: ArpOp,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

impl ArpPacket {
    pub fn request(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Self {
        Self {
            op: ArpOp::Request,
            sender_mac,
            sender_ip,
            target_mac: [0; 6],
            target_ip,
        }
    }

    pub fn reply(
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> Self {
        Self {
            op: ArpOp::Reply,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < ARP_PACKET_LEN {
            return Err(Error::Truncated {
                layer: "arp",
                need: ARP_PACKET_LEN,
                got: buf.len(),
            });
        }
        let htype = u16::from_be_bytes([buf[0], buf[1]]);
        let ptype = u16::from_be_bytes([buf[2], buf[3]]);
        let hlen = buf[4];
        let plen = buf[5];
        if htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4 {
            return Err(Error::Unsupported("arp: apenas Ethernet/IPv4"));
        }
        let op = ArpOp::from_u16(u16::from_be_bytes([buf[6], buf[7]]))
            .ok_or(Error::Unsupported("arp: opcode desconhecido"))?;
        let mut sender_mac = [0u8; 6];
        let mut sender_ip = [0u8; 4];
        let mut target_mac = [0u8; 6];
        let mut target_ip = [0u8; 4];
        sender_mac.copy_from_slice(&buf[8..14]);
        sender_ip.copy_from_slice(&buf[14..18]);
        target_mac.copy_from_slice(&buf[18..24]);
        target_ip.copy_from_slice(&buf[24..28]);
        Ok(Self {
            op,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; ARP_PACKET_LEN];
        out[0..2].copy_from_slice(&1u16.to_be_bytes()); // HTYPE Ethernet
        out[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // PTYPE IPv4
        out[4] = 6;
        out[5] = 4;
        out[6..8].copy_from_slice(&(self.op as u16).to_be_bytes());
        out[8..14].copy_from_slice(&self.sender_mac);
        out[14..18].copy_from_slice(&self.sender_ip);
        out[18..24].copy_from_slice(&self.target_mac);
        out[24..28].copy_from_slice(&self.target_ip);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let p = ArpPacket::request([1, 2, 3, 4, 5, 6], [10, 0, 0, 1], [10, 0, 0, 2]);
        let e = p.encode();
        let q = ArpPacket::parse(&e).unwrap();
        assert_eq!(q.op, ArpOp::Request);
        assert_eq!(q.sender_ip, [10, 0, 0, 1]);
        assert_eq!(q.target_ip, [10, 0, 0, 2]);
    }
}
