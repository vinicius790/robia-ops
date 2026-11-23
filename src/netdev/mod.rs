//! Abstração de NIC: em memória (testes sem root) e TUN opcional.

mod memory;
#[cfg(feature = "tun")]
mod tun;

pub use memory::{paired_nics, MemoryNic};

use crate::error::Result;

/// Dispositivo de enlace que troca quadros Ethernet (ou IP puro no TUN).
pub trait NetDevice: Send {
    fn mac(&self) -> [u8; 6];
    fn send(&mut self, frame: &[u8]) -> Result<()>;
    /// Não-bloqueante: `WouldBlock` se vazio.
    fn recv(&mut self) -> Result<Vec<u8>>;
    /// Nome descritivo (ex.: `mem0`, `tun0`).
    fn name(&self) -> &str;
}

#[cfg(feature = "tun")]
pub use tun::TunDevice;
