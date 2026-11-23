//! DHCPv4 (RFC 2131) — DISCOVER / OFFER / REQUEST / ACK sobre UDP 67/68.

use std::collections::HashMap;

use crate::error::{Error, Result};

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const DHCP_FIXED_LEN: usize = 236;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Ack = 5,
    Nak = 6,
}

impl DhcpMessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpPacket {
    pub op: u8, // 1 = BOOTREQUEST, 2 = BOOTREPLY
    pub xid: u32,
    pub yiaddr: [u8; 4],
    pub siaddr: [u8; 4],
    pub chaddr: [u8; 6],
    pub msg_type: DhcpMessageType,
    pub requested_ip: Option<[u8; 4]>,
    pub subnet_mask: Option<[u8; 4]>,
    pub router: Option<[u8; 4]>,
    pub lease_time_secs: Option<u32>,
}

impl DhcpPacket {
    pub fn discover(xid: u32, chaddr: [u8; 6]) -> Self {
        Self {
            op: 1,
            xid,
            yiaddr: [0; 4],
            siaddr: [0; 4],
            chaddr,
            msg_type: DhcpMessageType::Discover,
            requested_ip: None,
            subnet_mask: None,
            router: None,
            lease_time_secs: None,
        }
    }

    pub fn request(xid: u32, chaddr: [u8; 6], requested_ip: [u8; 4]) -> Self {
        Self {
            op: 1,
            xid,
            yiaddr: [0; 4],
            siaddr: [0; 4],
            chaddr,
            msg_type: DhcpMessageType::Request,
            requested_ip: Some(requested_ip),
            subnet_mask: None,
            router: None,
            lease_time_secs: None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; DHCP_FIXED_LEN];
        out[0] = self.op;
        out[1] = 1; // Ethernet
        out[2] = 6; // MAC len
        out[4..8].copy_from_slice(&self.xid.to_be_bytes());
        out[16..20].copy_from_slice(&self.yiaddr);
        out[20..24].copy_from_slice(&self.siaddr);
        out[28..34].copy_from_slice(&self.chaddr);
        out.extend_from_slice(&DHCP_MAGIC_COOKIE);
        // Option 53: DHCP Message Type
        out.extend_from_slice(&[53, 1, self.msg_type as u8]);
        if let Some(ip) = self.requested_ip {
            out.extend_from_slice(&[50, 4]);
            out.extend_from_slice(&ip);
        }
        if let Some(mask) = self.subnet_mask {
            out.extend_from_slice(&[1, 4]);
            out.extend_from_slice(&mask);
        }
        if let Some(gw) = self.router {
            out.extend_from_slice(&[3, 4]);
            out.extend_from_slice(&gw);
        }
        if let Some(lease) = self.lease_time_secs {
            out.extend_from_slice(&[51, 4]);
            out.extend_from_slice(&lease.to_be_bytes());
        }
        out.push(255); // End option
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < DHCP_FIXED_LEN + 4 {
            return Err(Error::Truncated {
                layer: "dhcp",
                need: DHCP_FIXED_LEN + 4,
                got: buf.len(),
            });
        }
        if buf[DHCP_FIXED_LEN..DHCP_FIXED_LEN + 4] != DHCP_MAGIC_COOKIE {
            return Err(Error::Unsupported("dhcp: magic cookie inválido"));
        }
        let op = buf[0];
        let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mut yiaddr = [0u8; 4];
        let mut siaddr = [0u8; 4];
        let mut chaddr = [0u8; 6];
        yiaddr.copy_from_slice(&buf[16..20]);
        siaddr.copy_from_slice(&buf[20..24]);
        chaddr.copy_from_slice(&buf[28..34]);

        let mut msg_type = None;
        let mut requested_ip = None;
        let mut subnet_mask = None;
        let mut router = None;
        let mut lease_time_secs = None;
        let mut i = DHCP_FIXED_LEN + 4;
        while i < buf.len() {
            match buf[i] {
                0 => i += 1,
                255 => break,
                code => {
                    if i + 1 >= buf.len() {
                        break;
                    }
                    let len = buf[i + 1] as usize;
                    if i + 2 + len > buf.len() {
                        break;
                    }
                    let data = &buf[i + 2..i + 2 + len];
                    match code {
                        53 if len == 1 => msg_type = DhcpMessageType::from_u8(data[0]),
                        50 if len == 4 => requested_ip = Some([data[0], data[1], data[2], data[3]]),
                        1 if len == 4 => subnet_mask = Some([data[0], data[1], data[2], data[3]]),
                        3 if len == 4 => router = Some([data[0], data[1], data[2], data[3]]),
                        51 if len == 4 => {
                            lease_time_secs =
                                Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                        }
                        _ => {}
                    }
                    i += 2 + len;
                }
            }
        }
        let msg_type = msg_type.ok_or(Error::Unsupported("dhcp: option 53 ausente"))?;
        Ok(Self {
            op,
            xid,
            yiaddr,
            siaddr,
            chaddr,
            msg_type,
            requested_ip,
            subnet_mask,
            router,
            lease_time_secs,
        })
    }
}

/// Servidor DHCPv4 minimalista determinístico para concessão de leases em sub-rede.
#[derive(Debug, Clone)]
pub struct DhcpServer {
    pub server_ip: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub router: [u8; 4],
    pub lease_time_secs: u32,
    pool: Vec<[u8; 4]>,
    leases: HashMap<[u8; 6], [u8; 4]>,
}

impl DhcpServer {
    pub fn new(
        server_ip: [u8; 4],
        subnet_mask: [u8; 4],
        router: [u8; 4],
        pool: Vec<[u8; 4]>,
    ) -> Self {
        Self {
            server_ip,
            subnet_mask,
            router,
            lease_time_secs: 3600,
            pool,
            leases: HashMap::new(),
        }
    }

    pub fn lease_for(&self, mac: &[u8; 6]) -> Option<[u8; 4]> {
        self.leases.get(mac).copied()
    }

    pub fn handle(&mut self, req: &DhcpPacket) -> Option<DhcpPacket> {
        match req.msg_type {
            DhcpMessageType::Discover => {
                let ip = self.leases.get(&req.chaddr).copied().or_else(|| {
                    self.pool
                        .iter()
                        .copied()
                        .find(|cand| !self.leases.values().any(|used| used == cand))
                })?;
                Some(DhcpPacket {
                    op: 2,
                    xid: req.xid,
                    yiaddr: ip,
                    siaddr: self.server_ip,
                    chaddr: req.chaddr,
                    msg_type: DhcpMessageType::Offer,
                    requested_ip: None,
                    subnet_mask: Some(self.subnet_mask),
                    router: Some(self.router),
                    lease_time_secs: Some(self.lease_time_secs),
                })
            }
            DhcpMessageType::Request => {
                let wanted = req
                    .requested_ip
                    .or_else(|| self.leases.get(&req.chaddr).copied())?;
                let in_pool = self.pool.contains(&wanted);
                let taken_by_other = self
                    .leases
                    .iter()
                    .any(|(m, ip)| *ip == wanted && *m != req.chaddr);
                if !in_pool || taken_by_other {
                    return Some(DhcpPacket {
                        op: 2,
                        xid: req.xid,
                        yiaddr: [0; 4],
                        siaddr: self.server_ip,
                        chaddr: req.chaddr,
                        msg_type: DhcpMessageType::Nak,
                        requested_ip: None,
                        subnet_mask: None,
                        router: None,
                        lease_time_secs: None,
                    });
                }
                self.leases.insert(req.chaddr, wanted);
                Some(DhcpPacket {
                    op: 2,
                    xid: req.xid,
                    yiaddr: wanted,
                    siaddr: self.server_ip,
                    chaddr: req.chaddr,
                    msg_type: DhcpMessageType::Ack,
                    requested_ip: None,
                    subnet_mask: Some(self.subnet_mask),
                    router: Some(self.router),
                    lease_time_secs: Some(self.lease_time_secs),
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_dora_flow() {
        let mut srv = DhcpServer::new(
            [10, 0, 0, 1],
            [255, 255, 255, 0],
            [10, 0, 0, 1],
            vec![[10, 0, 0, 50], [10, 0, 0, 51]],
        );
        let mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let disc = DhcpPacket::discover(0x1234_5678, mac);
        let offer = srv
            .handle(&DhcpPacket::parse(&disc.encode()).unwrap())
            .unwrap();
        assert_eq!(offer.msg_type, DhcpMessageType::Offer);
        assert_eq!(offer.yiaddr, [10, 0, 0, 50]);

        let req = DhcpPacket::request(0x1234_5678, mac, offer.yiaddr);
        let ack = srv
            .handle(&DhcpPacket::parse(&req.encode()).unwrap())
            .unwrap();
        assert_eq!(ack.msg_type, DhcpMessageType::Ack);
        assert_eq!(srv.lease_for(&mac), Some([10, 0, 0, 50]));
    }
}
