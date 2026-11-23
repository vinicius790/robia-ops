//! # userspace-tcpip — stack TCP/IP completo no espaço do usuário (catálogo 3.2)
//!
//! Camadas: Ethernet II / VLAN 802.1Q → ARP (cache + aging + proxy) → IPv4 (fragmentação/reassembly
//! e roteamento) → ICMP (Echo + Unreachable + TimeExceeded) → UDP (multicast + connected) →
//! TCP confiável (OOO + SACK + RTO/Karn + Fast Retransmit + Reno/Cubic) → HTTP/1.1, DHCPv4 e NAT44.
//!
//! Datapath de testes: [`netdev::MemoryNic`] e [`netdev::FaultyNic`] (zero root, determinístico).
//! TUN real: feature `tun` + `CAP_NET_ADMIN` — veja `CAPABILITIES.md`.
//!
//! **Sem claims de pps/throughput.** Meça no seu hardware se precisar.

pub mod checksum;
pub mod error;
pub mod http;
pub mod nat;
pub mod netdev;
pub mod proto;
pub mod rto;
pub mod seq;
pub mod stack;
pub mod tcp_conn;

pub use error::{Error, Result};
pub use http::{HttpRequest, HttpResponse};
pub use nat::NatTable;
pub use netdev::{
    paired_faulty_nics, paired_nics, FaultyNic, LinkImpairment, MemoryNic, NetDevice,
};
pub use stack::{RouteEntry, Stack};
pub use tcp_conn::{CongestionAlgo, FourTuple, TcpState};

#[cfg(feature = "tun")]
pub use netdev::TunDevice;
