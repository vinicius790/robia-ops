//! Parsers/builders de protocolos L2–L7 (Ethernet/802.1Q, ARP, IPv4, ICMP, UDP, TCP, DHCP).

pub mod arp;
pub mod dhcp;
pub mod eth;
pub mod icmp;
pub mod ipv4;
pub mod tcp;
pub mod udp;

pub use arp::{ArpOp, ArpPacket};
pub use dhcp::{DhcpMessageType, DhcpPacket, DhcpServer, DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
pub use eth::{EtherType, EthernetFrame, VlanTag, MAC_BROADCAST};
pub use icmp::{IcmpEcho, IcmpError, IcmpMessage, IcmpType, ICMP_HEADER_LEN};
pub use ipv4::{fragment_ipv4, IpProtocol, Ipv4Header, Ipv4Reassembler, IPV4_HEADER_MIN};
pub use tcp::{TcpFlags, TcpHeader, TcpOptions, TCP_HEADER_MIN};
pub use udp::{is_multicast_ipv4, UdpHeader, UDP_HEADER_LEN};
