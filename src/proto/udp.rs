//! UDP (RFC 768) com checksum IPv4 obrigatório neste stack (não-zero).

use crate::checksum::{internet_checksum_with_seed, ipv4_pseudo_header_sum};
use crate::error::{Error, Result};

pub const UDP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8])> {
        if buf.len() < UDP_HEADER_LEN {
            return Err(Error::Truncated {
                layer: "udp",
                need: UDP_HEADER_LEN,
                got: buf.len(),
            });
        }
        let length = u16::from_be_bytes([buf[4], buf[5]]);
        if (length as usize) < UDP_HEADER_LEN || (length as usize) > buf.len() {
            return Err(Error::Unsupported("udp: length inválido"));
        }
        let h = Self {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            length,
            checksum: u16::from_be_bytes([buf[6], buf[7]]),
        };
        Ok((h, &buf[UDP_HEADER_LEN..length as usize]))
    }
}

/// Monta datagrama UDP com checksum IPv4 (pseudo-header).
pub fn encapsulate(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let length = (UDP_HEADER_LEN + payload.len()) as u16;
    let mut out = Vec::with_capacity(length as usize);
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&[0, 0]); // checksum
    out.extend_from_slice(payload);

    let seed = ipv4_pseudo_header_sum(src_ip, dst_ip, 17, length);
    let mut csum = internet_checksum_with_seed(&out, seed);
    if csum == 0 {
        csum = 0xffff; // RFC 768: zero transmitido como FFFF
    }
    out[6..8].copy_from_slice(&csum.to_be_bytes());
    out
}

/// Valida checksum UDP (retorna Ok se 0 no fio = não usado, ou se bate).
pub fn verify_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp: &[u8]) -> Result<()> {
    if udp.len() < UDP_HEADER_LEN {
        return Err(Error::Truncated {
            layer: "udp",
            need: UDP_HEADER_LEN,
            got: udp.len(),
        });
    }
    let csum_field = u16::from_be_bytes([udp[6], udp[7]]);
    if csum_field == 0 {
        return Ok(()); // checksum opcional em IPv4; aceitamos
    }
    let length = u16::from_be_bytes([udp[4], udp[5]]);
    let seed = ipv4_pseudo_header_sum(src_ip, dst_ip, 17, length);
    if internet_checksum_with_seed(&udp[..length as usize], seed) != 0 {
        return Err(Error::BadChecksum("udp"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_roundtrip_checksum() {
        let src = [192, 168, 0, 1];
        let dst = [192, 168, 0, 2];
        let raw = encapsulate(src, dst, 12345, 53, b"query");
        verify_checksum(src, dst, &raw).unwrap();
        let (h, payload) = UdpHeader::parse(&raw).unwrap();
        assert_eq!(h.src_port, 12345);
        assert_eq!(h.dst_port, 53);
        assert_eq!(payload, b"query");
    }
}
