//! NIC em memória: dois pares ligados por canais MPSC (sem root, sem kernel).

use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

use parking_lot::Mutex;

use crate::error::{Error, Result};
use crate::netdev::NetDevice;

/// Extremidade de um enlace virtual Ethernet.
pub struct MemoryNic {
    name: String,
    mac: [u8; 6],
    tx: Sender<Vec<u8>>,
    rx: Mutex<Receiver<Vec<u8>>>,
}

impl MemoryNic {
    fn new(
        name: impl Into<String>,
        mac: [u8; 6],
        tx: Sender<Vec<u8>>,
        rx: Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            name: name.into(),
            mac,
            tx,
            rx: Mutex::new(rx),
        }
    }
}

impl NetDevice for MemoryNic {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.tx
            .send(frame.to_vec())
            .map_err(|_| Error::Device("peer MemoryNic desconectado".into()))
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        match self.rx.lock().try_recv() {
            Ok(f) => Ok(f),
            Err(TryRecvError::Empty) => Err(Error::WouldBlock),
            Err(TryRecvError::Disconnected) => {
                Err(Error::Device("peer MemoryNic desconectado".into()))
            }
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Cria um cabo virtual: tudo que A envia, B recebe (e vice-versa).
pub fn paired_nics(mac_a: [u8; 6], mac_b: [u8; 6]) -> (MemoryNic, MemoryNic) {
    let (tx_ab, rx_ba) = mpsc::channel::<Vec<u8>>();
    let (tx_ba, rx_ab) = mpsc::channel::<Vec<u8>>();
    let a = MemoryNic::new("mem0", mac_a, tx_ab, rx_ab);
    let b = MemoryNic::new("mem1", mac_b, tx_ba, rx_ba);
    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cable_delivers_frames() {
        let (mut a, mut b) = paired_nics([0xaa; 6], [0xbb; 6]);
        a.send(b"frame-a").unwrap();
        assert_eq!(b.recv().unwrap(), b"frame-a");
        b.send(b"frame-b").unwrap();
        assert_eq!(a.recv().unwrap(), b"frame-b");
        assert!(matches!(a.recv(), Err(Error::WouldBlock)));
    }
}
