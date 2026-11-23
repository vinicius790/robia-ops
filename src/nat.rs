//! NAT44 / NAPT (RFC 3022) — tradução stateful de endereços e portas IPv4 (TCP/UDP) com recálculo de checksum.

use std::collections::HashMap;

use crate::checksum::{internet_checksum, internet_checksum_with_seed, ipv4_pseudo_header_sum};
use crate::error::{Error, Result};
use crate::proto::ipv4::{IpProtocol, Ipv4Header};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NatInternalKey {
    protocol: u8,
    internal_ip: [u8; 4],
    internal_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NatExternalKey {
    protocol: u8,
    external_port: u16,
}

/// Tabela NAPT (Masquerade) determinística para traduzir pacotes IPv4/TCP/UDP entre LAN e WAN.
#[derive(Debug)]
pub struct NatTable {
    pub public_ip: [u8; 4],
    next_port: u16,
    outbound: HashMap<NatInternalKey, u16>,
    inbound: HashMap<NatExternalKey, ([u8; 4], u16)>,
}

impl NatTable {
    pub fn new(public_ip: [u8; 4]) -> Self {
        Self {
            public_ip,
            next_port: 40000,
            outbound: HashMap::new(),
            inbound: HashMap::new(),
        }
    }

    fn alloc_port(&mut self, protocol: u8) -> u16 {
        loop {
            let p = self.next_port;
            self.next_port = if self.next_port >= 60000 {
                40000
            } else {
                self.next_port + 1
            };
            let ext_key = NatExternalKey {
                protocol,
                external_port: p,
            };
            if !self.inbound.contains_key(&ext_key) {
                return p;
            }
        }
    }

    /// Traduz pacote saindo da LAN (source IP/port -> public_ip / external_port).
    pub fn translate_outbound(&mut self, raw_ip: &[u8]) -> Result<Vec<u8>> {
        let (hdr, ihl) = Ipv4Header::parse(raw_ip)?;
        let proto_u8 = hdr.protocol.as_u8();
        if !matches!(hdr.protocol, IpProtocol::Tcp | IpProtocol::Udp) {
            return Err(Error::Unsupported("nat: apenas TCP/UDP"));
        }
        let body = &raw_ip[ihl..hdr.total_length as usize];
        if body.len() < 8 {
            return Err(Error::Truncated {
                layer: "nat-l4",
                need: 8,
                got: body.len(),
            });
        }
        let src_port = u16::from_be_bytes([body[0], body[1]]);
        let key = NatInternalKey {
            protocol: proto_u8,
            internal_ip: hdr.src,
            internal_port: src_port,
        };
        let ext_port = if let Some(&p) = self.outbound.get(&key) {
            p
        } else {
            let p = self.alloc_port(proto_u8);
            self.outbound.insert(key, p);
            self.inbound.insert(
                NatExternalKey {
                    protocol: proto_u8,
                    external_port: p,
                },
                (hdr.src, src_port),
            );
            p
        };

        let mut out = raw_ip[..hdr.total_length as usize].to_vec();
        // Reescreve IP de origem + checksum IPv4
        out[12..16].copy_from_slice(&self.public_ip);
        out[10] = 0;
        out[11] = 0;
        let ip_csum = internet_checksum(&out[..ihl]);
        out[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        // Reescreve porta de origem + checksum L4
        out[ihl..ihl + 2].copy_from_slice(&ext_port.to_be_bytes());
        recompute_l4_checksum(&mut out, ihl, self.public_ip, hdr.dst, hdr.protocol);
        Ok(out)
    }

    /// Traduz pacote retornando da WAN (dst public_ip / external_port -> internal_ip / internal_port).
    pub fn translate_inbound(&self, raw_ip: &[u8]) -> Result<Vec<u8>> {
        let (hdr, ihl) = Ipv4Header::parse(raw_ip)?;
        if hdr.dst != self.public_ip {
            return Err(Error::Unsupported(
                "nat: destino não pertence ao IP público",
            ));
        }
        let proto_u8 = hdr.protocol.as_u8();
        if !matches!(hdr.protocol, IpProtocol::Tcp | IpProtocol::Udp) {
            return Err(Error::Unsupported("nat: apenas TCP/UDP"));
        }
        let body = &raw_ip[ihl..hdr.total_length as usize];
        if body.len() < 8 {
            return Err(Error::Truncated {
                layer: "nat-l4",
                need: 8,
                got: body.len(),
            });
        }
        let dst_port = u16::from_be_bytes([body[2], body[3]]);
        let &(internal_ip, internal_port) = self
            .inbound
            .get(&NatExternalKey {
                protocol: proto_u8,
                external_port: dst_port,
            })
            .ok_or(Error::Unsupported("nat: fluxo inbound sem mapeamento"))?;

        let mut out = raw_ip[..hdr.total_length as usize].to_vec();
        // Reescreve IP de destino + checksum IPv4
        out[16..20].copy_from_slice(&internal_ip);
        out[10] = 0;
        out[11] = 0;
        let ip_csum = internet_checksum(&out[..ihl]);
        out[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        // Reescreve porta de destino + checksum L4
        out[ihl + 2..ihl + 4].copy_from_slice(&internal_port.to_be_bytes());
        recompute_l4_checksum(&mut out, ihl, hdr.src, internal_ip, hdr.protocol);
        Ok(out)
    }

    pub fn active_mappings(&self) -> usize {
        self.inbound.len()
    }
}

fn recompute_l4_checksum(
    pkt: &mut [u8],
    ihl: usize,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    proto: IpProtocol,
) {
    let l4 = &mut pkt[ihl..];
    let l4_len = l4.len() as u16;
    match proto {
        IpProtocol::Udp if l4.len() >= 8 => {
            l4[6] = 0;
            l4[7] = 0;
            let seed = ipv4_pseudo_header_sum(src_ip, dst_ip, 17, l4_len);
            let mut csum = internet_checksum_with_seed(l4, seed);
            if csum == 0 {
                csum = 0xffff;
            }
            l4[6..8].copy_from_slice(&csum.to_be_bytes());
        }
        IpProtocol::Tcp if l4.len() >= 20 => {
            l4[16] = 0;
            l4[17] = 0;
            let seed = ipv4_pseudo_header_sum(src_ip, dst_ip, 6, l4_len);
            let csum = internet_checksum_with_seed(l4, seed);
            l4[16..18].copy_from_slice(&csum.to_be_bytes());
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ipv4::encapsulate as ip_encap;
    use crate::proto::udp::{encapsulate as udp_encap, verify_checksum, UdpHeader};

    #[test]
    fn nat44_udp_roundtrip() {
        let mut nat = NatTable::new([203, 0, 113, 1]);
        let lan_ip = [192, 168, 1, 10];
        let wan_ip = [198, 51, 100, 9];
        let udp = udp_encap(lan_ip, wan_ip, 5555, 8080, b"hello");
        let pkt = ip_encap(lan_ip, wan_ip, IpProtocol::Udp, &udp);

        let translated_out = nat.translate_outbound(&pkt).unwrap();
        let (h_out, ihl) = Ipv4Header::parse(&translated_out).unwrap();
        assert_eq!(h_out.src, [203, 0, 113, 1]);
        verify_checksum(h_out.src, h_out.dst, &translated_out[ihl..]).unwrap();
        let (u_out, _) = UdpHeader::parse(&translated_out[ihl..]).unwrap();
        assert_eq!(nat.active_mappings(), 1);

        // Resposta WAN -> NAT -> LAN
        let reply_udp = udp_encap(wan_ip, [203, 0, 113, 1], 8080, u_out.src_port, b"world");
        let reply_pkt = ip_encap(wan_ip, [203, 0, 113, 1], IpProtocol::Udp, &reply_udp);
        let translated_in = nat.translate_inbound(&reply_pkt).unwrap();
        let (h_in, ihl_in) = Ipv4Header::parse(&translated_in).unwrap();
        assert_eq!(h_in.dst, lan_ip);
        verify_checksum(h_in.src, h_in.dst, &translated_in[ihl_in..]).unwrap();
        let (u_in, payload) = UdpHeader::parse(&translated_in[ihl_in..]).unwrap();
        assert_eq!(u_in.dst_port, 5555);
        assert_eq!(payload, b"world");
    }
}
