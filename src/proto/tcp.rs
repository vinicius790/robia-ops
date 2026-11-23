//! TCP (RFC 793 / RFC 2018 SACK / RFC 7323 WScale) com parse/encode completo de opções.

use crate::checksum::{internet_checksum_with_seed, ipv4_pseudo_header_sum};
use crate::error::{Error, Result};

pub const TCP_HEADER_MIN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: Self = Self(0x01);
    pub const SYN: Self = Self(0x02);
    pub const RST: Self = Self(0x04);
    pub const PSH: Self = Self(0x08);
    pub const ACK: Self = Self(0x10);
    pub const URG: Self = Self(0x20);

    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn bits(self) -> u8 {
        self.0
    }
}

impl std::ops::BitOr for TcpFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Opções TCP suportadas: MSS (kind 2), Window Scale (kind 3), SACK-Permitted (kind 4) e SACK blocks (kind 5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub sack_blocks: Vec<(u32, u32)>,
}

impl TcpOptions {
    pub fn is_empty(&self) -> bool {
        self.mss.is_none()
            && self.window_scale.is_none()
            && !self.sack_permitted
            && self.sack_blocks.is_empty()
    }

    pub fn encode(&self) -> Vec<u8> {
        if self.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        if let Some(mss) = self.mss {
            out.push(2);
            out.push(4);
            out.extend_from_slice(&mss.to_be_bytes());
        }
        if let Some(ws) = self.window_scale {
            out.push(3);
            out.push(3);
            out.push(ws.min(14));
        }
        if self.sack_permitted {
            out.push(4);
            out.push(2);
        }
        if !self.sack_blocks.is_empty() {
            // Máximo 4 blocos SACK (4*8 + 2 = 34 bytes, cabe nos 40 bytes de opções)
            let count = self.sack_blocks.len().min(4);
            out.push(5);
            out.push((2 + count * 8) as u8);
            for &(left, right) in &self.sack_blocks[..count] {
                out.extend_from_slice(&left.to_be_bytes());
                out.extend_from_slice(&right.to_be_bytes());
            }
        }
        // Padding com EOL/0 para alinhar em 4 bytes
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    pub fn parse(buf: &[u8]) -> Self {
        let mut opts = Self::default();
        let mut i = 0;
        while i < buf.len() {
            match buf[i] {
                0 => break,  // EOL
                1 => i += 1, // NOP
                kind => {
                    if i + 1 >= buf.len() {
                        break;
                    }
                    let len = buf[i + 1] as usize;
                    if len < 2 || i + len > buf.len() {
                        break;
                    }
                    let data = &buf[i + 2..i + len];
                    match kind {
                        2 if data.len() == 2 => {
                            opts.mss = Some(u16::from_be_bytes([data[0], data[1]]));
                        }
                        3 if data.len() == 1 => {
                            opts.window_scale = Some(data[0].min(14));
                        }
                        4 if data.is_empty() => {
                            opts.sack_permitted = true;
                        }
                        5 if data.len().is_multiple_of(8) => {
                            for chunk in data.as_chunks::<8>().0 {
                                let left =
                                    u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                                let right =
                                    u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                                opts.sack_blocks.push((left, right));
                            }
                        }
                        _ => {}
                    }
                    i += len;
                }
            }
        }
        opts
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8, // em palavras de 32 bits (≥5)
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent: u16,
    pub options: TcpOptions,
}

impl TcpHeader {
    pub fn new(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        window: u16,
    ) -> Self {
        Self {
            src_port,
            dst_port,
            seq,
            ack,
            data_offset: 5,
            flags,
            window,
            checksum: 0,
            urgent: 0,
            options: TcpOptions::default(),
        }
    }

    pub fn with_options(mut self, options: TcpOptions) -> Self {
        let opt_len = options.encode().len();
        self.data_offset = (5 + opt_len / 4) as u8;
        self.options = options;
        self
    }

    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8])> {
        if buf.len() < TCP_HEADER_MIN {
            return Err(Error::Truncated {
                layer: "tcp",
                need: TCP_HEADER_MIN,
                got: buf.len(),
            });
        }
        let data_offset = buf[12] >> 4;
        let hdr_len = (data_offset as usize) * 4;
        if data_offset < 5 || buf.len() < hdr_len {
            return Err(Error::Truncated {
                layer: "tcp-hdr",
                need: hdr_len,
                got: buf.len(),
            });
        }
        let options = if hdr_len > TCP_HEADER_MIN {
            TcpOptions::parse(&buf[TCP_HEADER_MIN..hdr_len])
        } else {
            TcpOptions::default()
        };
        let h = Self {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            seq: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            ack: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            data_offset,
            flags: TcpFlags(buf[13]),
            window: u16::from_be_bytes([buf[14], buf[15]]),
            checksum: u16::from_be_bytes([buf[16], buf[17]]),
            urgent: u16::from_be_bytes([buf[18], buf[19]]),
            options,
        };
        Ok((h, &buf[hdr_len..]))
    }
}

/// Segmento TCP completo (header + opções + payload) com checksum IPv4.
pub fn encapsulate(src_ip: [u8; 4], dst_ip: [u8; 4], hdr: &TcpHeader, payload: &[u8]) -> Vec<u8> {
    let opt_bytes = hdr.options.encode();
    let hdr_len = TCP_HEADER_MIN + opt_bytes.len();
    let data_offset = (hdr_len / 4) as u8;
    let mut out = vec![0u8; hdr_len + payload.len()];
    out[0..2].copy_from_slice(&hdr.src_port.to_be_bytes());
    out[2..4].copy_from_slice(&hdr.dst_port.to_be_bytes());
    out[4..8].copy_from_slice(&hdr.seq.to_be_bytes());
    out[8..12].copy_from_slice(&hdr.ack.to_be_bytes());
    out[12] = (data_offset << 4) & 0xf0;
    out[13] = hdr.flags.bits();
    out[14..16].copy_from_slice(&hdr.window.to_be_bytes());
    // checksum 16..18 = 0
    out[18..20].copy_from_slice(&hdr.urgent.to_be_bytes());
    if !opt_bytes.is_empty() {
        out[TCP_HEADER_MIN..hdr_len].copy_from_slice(&opt_bytes);
    }
    out[hdr_len..].copy_from_slice(payload);

    let tcp_len = out.len().min(u16::MAX as usize) as u16;
    let seed = ipv4_pseudo_header_sum(src_ip, dst_ip, 6, tcp_len);
    let csum = internet_checksum_with_seed(&out, seed);
    out[16..18].copy_from_slice(&csum.to_be_bytes());
    out
}

pub fn verify_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp: &[u8]) -> Result<()> {
    if tcp.len() < TCP_HEADER_MIN {
        return Err(Error::Truncated {
            layer: "tcp",
            need: TCP_HEADER_MIN,
            got: tcp.len(),
        });
    }
    let seed = ipv4_pseudo_header_sum(src_ip, dst_ip, 6, tcp.len() as u16);
    if internet_checksum_with_seed(tcp, seed) != 0 {
        return Err(Error::BadChecksum("tcp"));
    }
    Ok(())
}

/// Comprimento de sequência consumido por um segmento (SYN/FIN contam 1).
pub fn seq_consumed(flags: TcpFlags, payload_len: usize) -> u32 {
    let mut n = payload_len as u32;
    if flags.contains(TcpFlags::SYN) {
        n += 1;
    }
    if flags.contains(TcpFlags::FIN) {
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_segment_checksum() {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let h = TcpHeader::new(40000, 80, 1000, 0, TcpFlags::SYN, 65535);
        let seg = encapsulate(src, dst, &h, &[]);
        verify_checksum(src, dst, &seg).unwrap();
        let (ph, payload) = TcpHeader::parse(&seg).unwrap();
        assert!(ph.flags.contains(TcpFlags::SYN));
        assert!(!ph.flags.contains(TcpFlags::ACK));
        assert!(payload.is_empty());
        assert_eq!(seq_consumed(ph.flags, 0), 1);
    }

    #[test]
    fn data_with_ack_and_options_roundtrip() {
        let src = [1, 1, 1, 1];
        let dst = [2, 2, 2, 2];
        let opts = TcpOptions {
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: true,
            sack_blocks: vec![(200, 300), (400, 500)],
        };
        let h = TcpHeader::new(1234, 5678, 50, 99, TcpFlags::ACK | TcpFlags::PSH, 1024)
            .with_options(opts.clone());
        let seg = encapsulate(src, dst, &h, b"hi");
        verify_checksum(src, dst, &seg).unwrap();
        let (ph, payload) = TcpHeader::parse(&seg).unwrap();
        assert_eq!(payload, b"hi");
        assert_eq!(ph.ack, 99);
        assert_eq!(ph.options, opts);
    }
}
