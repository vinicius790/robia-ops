//! Máquina de estados TCP (subset): Listen → SynSent/SynRcvd → Established → … → Closed.

use std::collections::VecDeque;

use crate::error::{Error, Result};
use crate::proto::tcp::{TcpFlags, TcpHeader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FourTuple {
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
}

#[derive(Debug)]
pub struct TcpConn {
    pub tuple: FourTuple,
    pub state: TcpState,
    pub snd_una: u32, // oldest unacked
    pub snd_nxt: u32, // next seq to send
    pub rcv_nxt: u32, // next expected
    pub irs: u32,     // initial receive seq
    pub iss: u32,     // initial send seq
    pub window: u16,
    /// Dados de aplicação prontos para leitura.
    pub rx_app: VecDeque<u8>,
    /// Segmentos outbound pendentes (já com header TCP, sem IP): (flags, seq, payload)
    /// Empacotados pelo Stack.
    pub pending_out: VecDeque<OutboundSeg>,
    pub listener: bool,
}

#[derive(Debug, Clone)]
pub struct OutboundSeg {
    pub flags: TcpFlags,
    pub seq: u32,
    pub ack: u32,
    pub payload: Vec<u8>,
}

impl TcpConn {
    pub fn listen(local_ip: [u8; 4], local_port: u16) -> Self {
        Self {
            tuple: FourTuple {
                local_ip,
                local_port,
                remote_ip: [0; 4],
                remote_port: 0,
            },
            state: TcpState::Listen,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            irs: 0,
            iss: 0,
            window: 65535,
            rx_app: VecDeque::new(),
            pending_out: VecDeque::new(),
            listener: true,
        }
    }

    pub fn active_open(
        local_ip: [u8; 4],
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
        iss: u32,
    ) -> Self {
        let mut c = Self {
            tuple: FourTuple {
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            },
            state: TcpState::SynSent,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            rcv_nxt: 0,
            irs: 0,
            iss,
            window: 65535,
            rx_app: VecDeque::new(),
            pending_out: VecDeque::new(),
            listener: false,
        };
        c.pending_out.push_back(OutboundSeg {
            flags: TcpFlags::SYN,
            seq: iss,
            ack: 0,
            payload: vec![],
        });
        c
    }

    pub fn is_established(&self) -> bool {
        self.state == TcpState::Established
    }

    /// Enfileira dados (só em Established).
    pub fn send_data(&mut self, data: &[u8]) -> Result<()> {
        if self.state != TcpState::Established {
            return Err(Error::Tcp("send_data: não Established"));
        }
        if data.is_empty() {
            return Ok(());
        }
        let seq = self.snd_nxt;
        self.snd_nxt = self.snd_nxt.wrapping_add(data.len() as u32);
        self.pending_out.push_back(OutboundSeg {
            flags: TcpFlags::ACK | TcpFlags::PSH,
            seq,
            ack: self.rcv_nxt,
            payload: data.to_vec(),
        });
        Ok(())
    }

    pub fn close(&mut self) -> Result<()> {
        match self.state {
            TcpState::Established => {
                let seq = self.snd_nxt;
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.pending_out.push_back(OutboundSeg {
                    flags: TcpFlags::FIN | TcpFlags::ACK,
                    seq,
                    ack: self.rcv_nxt,
                    payload: vec![],
                });
                self.state = TcpState::FinWait1;
                Ok(())
            }
            TcpState::CloseWait => {
                let seq = self.snd_nxt;
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.pending_out.push_back(OutboundSeg {
                    flags: TcpFlags::FIN | TcpFlags::ACK,
                    seq,
                    ack: self.rcv_nxt,
                    payload: vec![],
                });
                self.state = TcpState::LastAck;
                Ok(())
            }
            _ => Err(Error::Tcp("close: estado inválido")),
        }
    }

    /// Processa um segmento inbound já validado (checksum OK).
    /// Retorna `Some(new_child)` quando um listener aceita SYN (syn-rcvd child).
    pub fn on_segment(
        &mut self,
        remote_ip: [u8; 4],
        hdr: &TcpHeader,
        payload: &[u8],
        next_iss: u32,
    ) -> Result<Option<TcpConn>> {
        match self.state {
            TcpState::Listen => {
                if !hdr.flags.contains(TcpFlags::SYN) || hdr.flags.contains(TcpFlags::ACK) {
                    return Ok(None);
                }
                // Cria filho SynRcvd
                let iss = next_iss;
                let mut child = TcpConn {
                    tuple: FourTuple {
                        local_ip: self.tuple.local_ip,
                        local_port: self.tuple.local_port,
                        remote_ip,
                        remote_port: hdr.src_port,
                    },
                    state: TcpState::SynRcvd,
                    snd_una: iss,
                    snd_nxt: iss.wrapping_add(1),
                    rcv_nxt: hdr.seq.wrapping_add(1),
                    irs: hdr.seq,
                    iss,
                    window: 65535,
                    rx_app: VecDeque::new(),
                    pending_out: VecDeque::new(),
                    listener: false,
                };
                child.pending_out.push_back(OutboundSeg {
                    flags: TcpFlags::SYN | TcpFlags::ACK,
                    seq: iss,
                    ack: child.rcv_nxt,
                    payload: vec![],
                });
                Ok(Some(child))
            }
            TcpState::SynSent => {
                let has_syn = hdr.flags.contains(TcpFlags::SYN);
                let has_ack = hdr.flags.contains(TcpFlags::ACK);
                if has_syn && has_ack {
                    // Verifica ACK do nosso SYN
                    if hdr.ack != self.iss.wrapping_add(1) {
                        return Err(Error::Tcp("SynSent: ACK inesperado"));
                    }
                    self.irs = hdr.seq;
                    self.rcv_nxt = hdr.seq.wrapping_add(1);
                    self.snd_una = hdr.ack;
                    self.state = TcpState::Established;
                    self.pending_out.push_back(OutboundSeg {
                        flags: TcpFlags::ACK,
                        seq: self.snd_nxt,
                        ack: self.rcv_nxt,
                        payload: vec![],
                    });
                } else if has_syn && !has_ack {
                    // Simultaneous open — raro; trata como SynRcvd
                    self.irs = hdr.seq;
                    self.rcv_nxt = hdr.seq.wrapping_add(1);
                    self.state = TcpState::SynRcvd;
                    self.pending_out.push_back(OutboundSeg {
                        flags: TcpFlags::SYN | TcpFlags::ACK,
                        seq: self.iss,
                        ack: self.rcv_nxt,
                        payload: vec![],
                    });
                }
                Ok(None)
            }
            TcpState::SynRcvd => {
                if hdr.flags.contains(TcpFlags::ACK) && hdr.ack == self.iss.wrapping_add(1) {
                    self.snd_una = hdr.ack;
                    self.state = TcpState::Established;
                }
                Ok(None)
            }
            TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::CloseWait => {
                self.handle_established(hdr, payload)?;
                Ok(None)
            }
            TcpState::LastAck => {
                if hdr.flags.contains(TcpFlags::ACK) && hdr.ack == self.snd_nxt {
                    self.state = TcpState::Closed;
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn handle_established(&mut self, hdr: &TcpHeader, payload: &[u8]) -> Result<()> {
        // Aceita dados em-ordem simples (sem reordenação/retransmit neste MVP).
        if !payload.is_empty() && hdr.seq == self.rcv_nxt {
            self.rx_app.extend(payload.iter().copied());
            self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
            self.pending_out.push_back(OutboundSeg {
                flags: TcpFlags::ACK,
                seq: self.snd_nxt,
                ack: self.rcv_nxt,
                payload: vec![],
            });
        }

        if hdr.flags.contains(TcpFlags::ACK) {
            // Avança snd_una de forma simplificada
            if wrapping_gte(hdr.ack, self.snd_una) && wrapping_lte(hdr.ack, self.snd_nxt) {
                self.snd_una = hdr.ack;
            }
        }

        if hdr.flags.contains(TcpFlags::FIN) && hdr.seq == self.rcv_nxt {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.pending_out.push_back(OutboundSeg {
                flags: TcpFlags::ACK,
                seq: self.snd_nxt,
                ack: self.rcv_nxt,
                payload: vec![],
            });
            match self.state {
                TcpState::Established => self.state = TcpState::CloseWait,
                TcpState::FinWait1 => self.state = TcpState::TimeWait, // simplificado (pula FinWait2 se ACK+FIN)
                TcpState::FinWait2 => self.state = TcpState::TimeWait,
                _ => {}
            }
        } else if self.state == TcpState::FinWait1
            && hdr.flags.contains(TcpFlags::ACK)
            && hdr.ack == self.snd_nxt
        {
            self.state = TcpState::FinWait2;
        }

        Ok(())
    }

    pub fn build_segment(&self, seg: &OutboundSeg) -> (TcpHeader, Vec<u8>) {
        let hdr = TcpHeader::new(
            self.tuple.local_port,
            self.tuple.remote_port,
            seg.seq,
            seg.ack,
            seg.flags,
            self.window,
        );
        (hdr, seg.payload.clone())
    }
}

fn wrapping_gte(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) < 0x8000_0000
}

fn wrapping_lte(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) < 0x8000_0000
}
