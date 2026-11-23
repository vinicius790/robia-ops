//! IPv4 (RFC 791) — parse/encode com validação estrita, fragmentação por MTU e reassembly.

use std::collections::{BTreeMap, HashMap};

use crate::checksum::internet_checksum;
use crate::error::{Error, Result};

pub const IPV4_HEADER_MIN: usize = 20;
pub const IPV4_FLAG_DF: u16 = 0x4000;
pub const IPV4_FLAG_MF: u16 = 0x2000;
pub const IPV4_FRAG_OFFSET_MASK: u16 = 0x1fff;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    pub flags_frag: u16, // DF/MF + offset em blocos de 8 bytes
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub checksum: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

impl Ipv4Header {
    pub fn new(src: [u8; 4], dst: [u8; 4], protocol: IpProtocol, payload_len: usize) -> Self {
        let total = (IPV4_HEADER_MIN + payload_len).min(u16::MAX as usize) as u16;
        Self {
            tos: 0,
            total_length: total,
            identification: 0,
            flags_frag: IPV4_FLAG_DF,
            ttl: 64,
            protocol,
            checksum: 0,
            src,
            dst,
        }
    }

    pub fn dont_fragment(&self) -> bool {
        (self.flags_frag & IPV4_FLAG_DF) != 0
    }

    pub fn more_fragments(&self) -> bool {
        (self.flags_frag & IPV4_FLAG_MF) != 0
    }

    pub fn frag_offset_bytes(&self) -> usize {
        ((self.flags_frag & IPV4_FRAG_OFFSET_MASK) as usize) * 8
    }

    pub fn is_fragmented(&self) -> bool {
        self.more_fragments() || self.frag_offset_bytes() > 0
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
        let total_length = u16::from_be_bytes([buf[2], buf[3]]);
        if (total_length as usize) < ihl || (total_length as usize) > buf.len() {
            return Err(Error::Truncated {
                layer: "ipv4-total-len",
                need: total_length as usize,
                got: buf.len(),
            });
        }
        let mut src = [0u8; 4];
        let mut dst = [0u8; 4];
        src.copy_from_slice(&buf[12..16]);
        dst.copy_from_slice(&buf[16..20]);
        let h = Self {
            tos: buf[1],
            total_length,
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
    out
}

/// Fragmenta um payload IPv4 em datagramas respeitando `mtu` (RFC 791, blocos de 8 bytes).
pub fn fragment_ipv4(
    src: [u8; 4],
    dst: [u8; 4],
    protocol: IpProtocol,
    identification: u16,
    ttl: u8,
    payload: &[u8],
    mtu: usize,
) -> Result<Vec<Vec<u8>>> {
    if mtu < IPV4_HEADER_MIN + 8 {
        return Err(Error::Unsupported("ipv4: MTU menor que 28 bytes"));
    }
    let max_payload = ((mtu - IPV4_HEADER_MIN) / 8) * 8;
    if IPV4_HEADER_MIN + payload.len() <= mtu {
        let mut hdr = Ipv4Header::new(src, dst, protocol, payload.len());
        hdr.identification = identification;
        hdr.ttl = ttl;
        let mut pkt = hdr.encode();
        pkt.extend_from_slice(payload);
        return Ok(vec![pkt]);
    }
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < payload.len() {
        let end = (offset + max_payload).min(payload.len());
        let chunk = &payload[offset..end];
        let more = end < payload.len();
        let frag_units = (offset / 8) as u16;
        let mut hdr = Ipv4Header::new(src, dst, protocol, chunk.len());
        hdr.identification = identification;
        hdr.ttl = ttl;
        hdr.flags_frag =
            (if more { IPV4_FLAG_MF } else { 0 }) | (frag_units & IPV4_FRAG_OFFSET_MASK);
        let mut pkt = hdr.encode();
        pkt.extend_from_slice(chunk);
        out.push(pkt);
        offset = end;
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ReassemblyKey {
    src: [u8; 4],
    dst: [u8; 4],
    identification: u16,
    protocol: u8,
}

#[derive(Debug, Clone)]
struct ReassemblyEntry {
    created_ms: u64,
    total_len: Option<usize>,
    /// offset -> payload slice
    fragments: BTreeMap<usize, Vec<u8>>,
    /// Primeiro fragmento original (para eventual ICMP Time Exceeded).
    first_hdr_and_data: Option<Vec<u8>>,
}

/// Reassembler IPv4 com suporte a fragmentos fora de ordem e expiração por timeout (RFC 791).
#[derive(Debug, Default)]
pub struct Ipv4Reassembler {
    entries: HashMap<ReassemblyKey, ReassemblyEntry>,
    pub timeout_ms: u64,
}

impl Ipv4Reassembler {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            entries: HashMap::new(),
            timeout_ms,
        }
    }

    /// Insere um fragmento. Retorna `Some(payload_completo)` quando todos os bytes chegam.
    pub fn push(
        &mut self,
        hdr: &Ipv4Header,
        frag_payload: &[u8],
        raw_packet: &[u8],
        now_ms: u64,
    ) -> Option<Vec<u8>> {
        let offset = hdr.frag_offset_bytes();
        let key = ReassemblyKey {
            src: hdr.src,
            dst: hdr.dst,
            identification: hdr.identification,
            protocol: hdr.protocol.as_u8(),
        };
        let entry = self.entries.entry(key).or_insert_with(|| ReassemblyEntry {
            created_ms: now_ms,
            total_len: None,
            fragments: BTreeMap::new(),
            first_hdr_and_data: None,
        });
        if offset == 0 && entry.first_hdr_and_data.is_none() {
            entry.first_hdr_and_data = Some(raw_packet.iter().copied().take(28).collect());
        }
        entry.fragments.insert(offset, frag_payload.to_vec());
        if !hdr.more_fragments() {
            entry.total_len = Some(offset + frag_payload.len());
        }

        let target_len = entry.total_len?;
        // Verifica cobertura contígua 0..target_len
        let mut cursor = 0usize;
        let mut assembled = vec![0u8; target_len];
        for (&frag_off, data) in &entry.fragments {
            if frag_off > cursor {
                return None; // buraco
            }
            let end = (frag_off + data.len()).min(target_len);
            if end > cursor {
                let slice_start = cursor - frag_off;
                assembled[cursor..end].copy_from_slice(&data[slice_start..end - frag_off]);
                cursor = end;
            }
        }
        if cursor == target_len {
            self.entries.remove(&key);
            Some(assembled)
        } else {
            None
        }
    }

    /// Remove montagens expiradas, retornando `(src_ip, first_packet_excerpt)` para ICMP Time Exceeded.
    pub fn expire(&mut self, now_ms: u64) -> Vec<([u8; 4], Vec<u8>)> {
        let mut expired = Vec::new();
        let timeout = self.timeout_ms;
        self.entries.retain(|k, entry| {
            if now_ms.saturating_sub(entry.created_ms) >= timeout {
                if let Some(excerpt) = entry.first_hdr_and_data.take() {
                    expired.push((k.src, excerpt));
                }
                false
            } else {
                true
            }
        });
        expired
    }

    pub fn pending_count(&self) -> usize {
        self.entries.len()
    }
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

    #[test]
    fn truncated_total_length_rejected() {
        let mut pkt = encapsulate([10, 0, 0, 1], [10, 0, 0, 2], IpProtocol::Udp, b"abcd");
        pkt.truncate(22); // total_length diz 24, mas só temos 22 bytes
        assert!(matches!(
            Ipv4Header::parse(&pkt),
            Err(Error::Truncated {
                layer: "ipv4-total-len",
                ..
            })
        ));
    }

    #[test]
    fn fragment_and_out_of_order_reassembly() {
        let data: Vec<u8> = (0..100u8).collect();
        let frags = fragment_ipv4(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            IpProtocol::Udp,
            77,
            64,
            &data,
            44,
        )
        .unwrap();
        assert!(frags.len() >= 4);
        let mut reasm = Ipv4Reassembler::new(30_000);
        // Entrega fora de ordem (último primeiro)
        let mut assembled = None;
        for raw in frags.iter().rev() {
            let (h, ihl) = Ipv4Header::parse(raw).unwrap();
            assert!(h.is_fragmented());
            assembled = reasm.push(&h, &raw[ihl..h.total_length as usize], raw, 100);
        }
        assert_eq!(assembled.unwrap(), data);
        assert_eq!(reasm.pending_count(), 0);
    }
}
