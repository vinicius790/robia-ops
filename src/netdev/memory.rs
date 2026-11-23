//! NIC em memória: enlace virtual determinístico (`MemoryNic`) e enlace com injeção de falhas (`FaultyNic`).

use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::netdev::NetDevice;

/// Extremidade de um enlace virtual Ethernet sem perdas.
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
        match self.rx.lock().unwrap_or_else(|e| e.into_inner()).try_recv() {
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

/// Parâmetros determinísticos de degradação de enlace para testar retransmissão e reordenação em CI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkImpairment {
    /// Probabilidade percentual (0..=100) de descartar um frame no envio.
    pub loss_pct: u8,
    /// Probabilidade percentual (0..=100) de reordenar (atrasar em 1 frame) um envio.
    pub reorder_pct: u8,
    /// Probabilidade percentual (0..=100) de duplicar um frame no envio.
    pub duplicate_pct: u8,
    /// Semente do PRNG xorshift64 para reprodutibilidade 100% determinística.
    pub seed: u64,
}

impl Default for LinkImpairment {
    fn default() -> Self {
        Self {
            loss_pct: 0,
            reorder_pct: 0,
            duplicate_pct: 0,
            seed: 0x9e37_79b9_7f4a_7c15,
        }
    }
}

/// Wrapper sobre [`MemoryNic`] que injeta perda, reordenação e duplicação de forma determinística.
pub struct FaultyNic {
    inner: MemoryNic,
    impairment: LinkImpairment,
    rng_state: u64,
    delayed_frame: Option<Vec<u8>>,
    pub dropped_frames: u64,
    pub reordered_frames: u64,
    pub duplicated_frames: u64,
}

impl FaultyNic {
    pub fn new(inner: MemoryNic, impairment: LinkImpairment) -> Self {
        let seed = if impairment.seed == 0 {
            1
        } else {
            impairment.seed
        };
        Self {
            inner,
            impairment,
            rng_state: seed,
            delayed_frame: None,
            dropped_frames: 0,
            reordered_frames: 0,
            duplicated_frames: 0,
        }
    }

    fn next_pct(&mut self) -> u8 {
        let mut x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state = x;
        (x % 100) as u8
    }

    /// Libera eventual frame atrasado para reordenação.
    pub fn flush_delayed(&mut self) -> Result<()> {
        if let Some(frame) = self.delayed_frame.take() {
            self.inner.send(&frame)?;
        }
        Ok(())
    }
}

impl NetDevice for FaultyNic {
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }

    fn send(&mut self, frame: &[u8]) -> Result<()> {
        if self.impairment.loss_pct > 0 && self.next_pct() < self.impairment.loss_pct {
            self.dropped_frames += 1;
            return Ok(());
        }
        if self.impairment.reorder_pct > 0
            && self.delayed_frame.is_none()
            && self.next_pct() < self.impairment.reorder_pct
        {
            self.delayed_frame = Some(frame.to_vec());
            self.reordered_frames += 1;
            return Ok(());
        }
        self.inner.send(frame)?;
        if self.impairment.duplicate_pct > 0 && self.next_pct() < self.impairment.duplicate_pct {
            self.duplicated_frames += 1;
            self.inner.send(frame)?;
        }
        if let Some(delayed) = self.delayed_frame.take() {
            self.inner.send(&delayed)?;
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        self.inner.recv()
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
}

/// Cria um par de NICs em memória com injeção determinística de falhas.
pub fn paired_faulty_nics(
    mac_a: [u8; 6],
    mac_b: [u8; 6],
    impairment_a: LinkImpairment,
    impairment_b: LinkImpairment,
) -> (FaultyNic, FaultyNic) {
    let (a, b) = paired_nics(mac_a, mac_b);
    (
        FaultyNic::new(a, impairment_a),
        FaultyNic::new(b, impairment_b),
    )
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

    #[test]
    fn faulty_nic_injects_loss_and_reordering() {
        let imp = LinkImpairment {
            loss_pct: 30,
            reorder_pct: 40,
            duplicate_pct: 10,
            seed: 42,
        };
        let (mut a, mut b) =
            paired_faulty_nics([0xaa; 6], [0xbb; 6], imp, LinkImpairment::default());
        for i in 0..40u8 {
            a.send(&[i]).unwrap();
        }
        a.flush_delayed().unwrap();
        assert!(a.dropped_frames > 0);
        assert!(a.reordered_frames > 0);
        let mut received = Vec::new();
        while let Ok(f) = b.recv() {
            received.push(f[0]);
        }
        assert!(!received.is_empty());
        assert!(received.len() < 40 || a.duplicated_frames > 0);
    }
}
