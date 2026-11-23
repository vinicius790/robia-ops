//! # userspace-tcpip — stack TCP/IP no espaço do usuário (catálogo 3.2)
//!
//! Camadas: Ethernet + ARP → IPv4 + ICMP → UDP → TCP subset (SYN/ACK/dados/FIN).
//! Datapath de testes: [`netdev::MemoryNic`] (sem root). TUN real: feature `tun`
//! + `CAP_NET_ADMIN` — veja `CAPABILITIES.md`.
//!
//! **Sem claims de pps/throughput.** Meça no seu hardware se precisar.

pub mod checksum;
pub mod error;
pub mod netdev;
pub mod proto;
pub mod stack;
pub mod tcp_conn;

pub use error::{Error, Result};
pub use netdev::{paired_nics, MemoryNic, NetDevice};
pub use stack::Stack;
pub use tcp_conn::{FourTuple, TcpState};

#[cfg(feature = "tun")]
pub use netdev::TunDevice;
pub mod rto;
pub mod seq;
