//! ICMP echo (RFC 792) — types 8 (request) e 0 (reply).

use crate::checksum::internet_checksum;
use crate::error::{Error, Result};

pub const ICMP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    EchoReply = 0,
    EchoRequest = 8,
}

impl IcmpType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::EchoReply),
            8 => Some(Self::EchoRequest),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpEcho {
    pub kind: IcmpType,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

impl IcmpEcho {
    pub fn request(identifier: u16, sequence: u16, payload: Vec<u8>) -> Self {
        Self {
            kind: IcmpType::EchoRequest,
            identifier,
            sequence,
            payload,
        }
    }

    pub fn to_reply(&self) -> Self {
        Self {
            kind: IcmpType::EchoReply,
            identifier: self.identifier,
            sequence: self.sequence,
            payload: self.payload.clone(),
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < ICMP_HEADER_LEN {
            return Err(Error::Truncated {
                layer: "icmp",
                need: ICMP_HEADER_LEN,
                got: buf.len(),
            });
        }
        if internet_checksum(buf) != 0 {
            return Err(Error::BadChecksum("icmp"));
        }
        let kind = IcmpType::from_u8(buf[0]).ok_or(Error::Unsupported("icmp: tipo não-echo"))?;
        // code deve ser 0 para echo
        if buf[1] != 0 {
            return Err(Error::Unsupported("icmp: code ≠ 0"));
        }
        Ok(Self {
            kind,
            identifier: u16::from_be_bytes([buf[4], buf[5]]),
            sequence: u16::from_be_bytes([buf[6], buf[7]]),
            payload: buf[ICMP_HEADER_LEN..].to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ICMP_HEADER_LEN + self.payload.len());
        out.push(self.kind as u8);
        out.push(0); // code
        out.extend_from_slice(&[0, 0]); // checksum placeholder
        out.extend_from_slice(&self.identifier.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.payload);
        let csum = internet_checksum(&out);
        out[2..4].copy_from_slice(&csum.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_roundtrip_and_reply() {
        let req = IcmpEcho::request(0x1234, 7, b"ping".to_vec());
        let raw = req.encode();
        let parsed = IcmpEcho::parse(&raw).unwrap();
        assert_eq!(parsed.kind, IcmpType::EchoRequest);
        assert_eq!(parsed.payload, b"ping");
        let rep = parsed.to_reply().encode();
        let r = IcmpEcho::parse(&rep).unwrap();
        assert_eq!(r.kind, IcmpType::EchoReply);
        assert_eq!(r.identifier, 0x1234);
        assert_eq!(r.sequence, 7);
    }
}
