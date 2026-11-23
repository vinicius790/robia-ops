//! Máquina de estados TCP completa: handshake, RST, simultaneous open/close, reassembly OOO,
//! SACK (RFC 2018), controle de fluxo dinâmico, RTO Jacobson/Karels + backoff, Fast Retransmit
//! e controle de congestionamento Reno / Cubic-lite.

use std::collections::{BTreeMap, VecDeque};

use crate::error::{Error, Result};
use crate::proto::tcp::{seq_consumed, TcpFlags, TcpHeader, TcpOptions};
use crate::rto::Rto;
use crate::seq::{wrapping_ge, wrapping_gt, wrapping_le};

pub const DEFAULT_MSS: u16 = 1460;
pub const DEFAULT_RCV_BUF: usize = 65535;
pub const TIME_WAIT_MS: u64 = 4_000;

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
    Closing,
    LastAck,
    TimeWait,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgo {
    Reno,
    Cubic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FourTuple {
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
}

#[derive(Debug, Clone)]
pub struct OutboundSeg {
    pub flags: TcpFlags,
    pub seq: u32,
    pub ack: u32,
    pub payload: Vec<u8>,
    pub options: TcpOptions,
}

#[derive(Debug, Clone)]
struct InFlightSeg {
    seg: OutboundSeg,
    sent_ms: u64,
    retransmitted: bool,
    retries: u8,
}

#[derive(Debug)]
pub struct TcpConn {
    pub tuple: FourTuple,
    pub state: TcpState,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    pub irs: u32,
    pub iss: u32,
    pub window: u16,
    pub peer_window: u32,
    pub mss: u16,
    pub sack_enabled: bool,
    /// Dados de aplicação prontos para leitura em ordem.
    pub rx_app: VecDeque<u8>,
    /// Buffer de reordenação (segmentos recebidos fora de ordem: seq -> bytes).
    ooo_buf: BTreeMap<u32, Vec<u8>>,
    /// Segmentos prontos para transmissão pelo Stack.
    pub pending_out: VecDeque<OutboundSeg>,
    /// Segmentos em trânsito aguardando ACK (para RTO e Fast Retransmit).
    in_flight: VecDeque<InFlightSeg>,
    /// Dados de aplicação ainda não segmentados por limite de janela/cwnd.
    tx_queue: VecDeque<u8>,
    pub listener: bool,
    /// Estimador RTO Jacobson/Karels + regra de Karn.
    pub rto: Rto,
    /// Controle de congestionamento (Reno ou Cubic-lite).
    pub congestion_algo: CongestionAlgo,
    pub cwnd: u32,
    pub ssthresh: u32,
    pub dup_acks: u8,
    cubic_w_max: f64,
    cubic_epoch_start_ms: Option<u64>,
    pub retransmissions: u64,
    now_ms: u64,
    time_wait_since_ms: Option<u64>,
}

impl TcpConn {
    fn base(tuple: FourTuple, state: TcpState, iss: u32, listener: bool) -> Self {
        let mss = DEFAULT_MSS;
        Self {
            tuple,
            state,
            snd_una: iss,
            snd_nxt: iss,
            rcv_nxt: 0,
            irs: 0,
            iss,
            window: DEFAULT_RCV_BUF as u16,
            peer_window: DEFAULT_RCV_BUF as u32,
            mss,
            sack_enabled: true,
            rx_app: VecDeque::new(),
            ooo_buf: BTreeMap::new(),
            pending_out: VecDeque::new(),
            in_flight: VecDeque::new(),
            tx_queue: VecDeque::new(),
            listener,
            rto: Rto::default(),
            congestion_algo: CongestionAlgo::Cubic,
            cwnd: (mss as u32) * 10, // RFC 6928 IW10
            ssthresh: 65535,
            dup_acks: 0,
            cubic_w_max: ((mss as u32) * 10) as f64,
            cubic_epoch_start_ms: None,
            retransmissions: 0,
            now_ms: 0,
            time_wait_since_ms: None,
        }
    }

    pub fn listen(local_ip: [u8; 4], local_port: u16) -> Self {
        Self::base(
            FourTuple {
                local_ip,
                local_port,
                remote_ip: [0; 4],
                remote_port: 0,
            },
            TcpState::Listen,
            0,
            true,
        )
    }

    pub fn active_open(
        local_ip: [u8; 4],
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
        iss: u32,
    ) -> Self {
        let mut c = Self::base(
            FourTuple {
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            },
            TcpState::SynSent,
            iss,
            false,
        );
        c.snd_nxt = iss.wrapping_add(1);
        let seg = OutboundSeg {
            flags: TcpFlags::SYN,
            seq: iss,
            ack: 0,
            payload: vec![],
            options: TcpOptions {
                mss: Some(c.mss),
                window_scale: None,
                sack_permitted: true,
                sack_blocks: vec![],
            },
        };
        c.enqueue_reliable(seg);
        c
    }

    fn enqueue_reliable(&mut self, seg: OutboundSeg) {
        self.pending_out.push_back(seg.clone());
        self.in_flight.push_back(InFlightSeg {
            seg,
            sent_ms: self.now_ms,
            retransmitted: false,
            retries: 0,
        });
    }

    pub fn is_established(&self) -> bool {
        self.state == TcpState::Established
    }

    /// Janela de recepção dinâmica baseada no espaço livre de `rx_app`.
    pub fn advertised_window(&self) -> u16 {
        DEFAULT_RCV_BUF
            .saturating_sub(self.rx_app.len())
            .min(u16::MAX as usize) as u16
    }

    /// Enfileira dados (em Established ou CloseWait) segmentando por MSS e janela/cwnd.
    pub fn send_data(&mut self, data: &[u8]) -> Result<()> {
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
            return Err(Error::Tcp("send_data: não Established"));
        }
        if data.is_empty() {
            return Ok(());
        }
        self.tx_queue.extend(data.iter().copied());
        self.drain_tx_queue();
        Ok(())
    }

    fn drain_tx_queue(&mut self) {
        let eff_win = self.peer_window.min(self.cwnd).max(self.mss as u32);
        while !self.tx_queue.is_empty() {
            let bytes_in_flight = self.snd_nxt.wrapping_sub(self.snd_una);
            if bytes_in_flight >= eff_win {
                break;
            }
            let avail = (eff_win - bytes_in_flight) as usize;
            let chunk_len = avail.min(self.mss as usize).min(self.tx_queue.len());
            if chunk_len == 0 {
                break;
            }
            let payload: Vec<u8> = self.tx_queue.drain(..chunk_len).collect();
            let seq = self.snd_nxt;
            self.snd_nxt = self.snd_nxt.wrapping_add(payload.len() as u32);
            let seg = OutboundSeg {
                flags: TcpFlags::ACK | TcpFlags::PSH,
                seq,
                ack: self.rcv_nxt,
                payload,
                options: TcpOptions::default(),
            };
            self.enqueue_reliable(seg);
        }
    }

    pub fn close(&mut self) -> Result<()> {
        match self.state {
            TcpState::Established => {
                self.drain_tx_queue();
                let seq = self.snd_nxt;
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.enqueue_reliable(OutboundSeg {
                    flags: TcpFlags::FIN | TcpFlags::ACK,
                    seq,
                    ack: self.rcv_nxt,
                    payload: vec![],
                    options: TcpOptions::default(),
                });
                self.state = TcpState::FinWait1;
                Ok(())
            }
            TcpState::CloseWait => {
                self.drain_tx_queue();
                let seq = self.snd_nxt;
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.enqueue_reliable(OutboundSeg {
                    flags: TcpFlags::FIN | TcpFlags::ACK,
                    seq,
                    ack: self.rcv_nxt,
                    payload: vec![],
                    options: TcpOptions::default(),
                });
                self.state = TcpState::LastAck;
                Ok(())
            }
            _ => Err(Error::Tcp("close: estado inválido")),
        }
    }

    /// Avança o relógio virtual: dispara retransmissões por RTO (com backoff) e expira TIME-WAIT.
    pub fn tick(&mut self, now_ms: u64) -> usize {
        self.now_ms = now_ms;
        if self.state == TcpState::TimeWait {
            if let Some(since) = self.time_wait_since_ms {
                if now_ms.saturating_sub(since) >= TIME_WAIT_MS {
                    self.state = TcpState::Closed;
                    self.in_flight.clear();
                }
            }
            return 0;
        }
        if self.in_flight.is_empty() {
            return 0;
        }
        let rto_ms = (self.rto.rto * 1000.0).max(200.0) as u64;
        let mut retransmitted = 0;
        if let Some(front) = self.in_flight.front_mut() {
            if now_ms.saturating_sub(front.sent_ms) >= rto_ms {
                front.sent_ms = now_ms;
                front.retransmitted = true;
                front.retries = front.retries.saturating_add(1);
                let mut seg = front.seg.clone();
                seg.ack = self.rcv_nxt;
                self.pending_out.push_back(seg);
                self.retransmissions += 1;
                retransmitted += 1;
                // Backoff exponencial + redução de cwnd (Reno/Cubic)
                self.rto.on_timeout();
                self.on_congestion_event(true);
            }
        }
        retransmitted
    }

    fn on_congestion_event(&mut self, is_timeout: bool) {
        let mss = self.mss as u32;
        match self.congestion_algo {
            CongestionAlgo::Reno => {
                self.ssthresh = (self.cwnd / 2).max(2 * mss);
                self.cwnd = if is_timeout { mss } else { self.ssthresh };
            }
            CongestionAlgo::Cubic => {
                self.cubic_w_max = self.cwnd as f64;
                self.cubic_epoch_start_ms = Some(self.now_ms);
                self.ssthresh = ((self.cwnd as f64 * 0.7) as u32).max(2 * mss);
                self.cwnd = if is_timeout { mss } else { self.ssthresh };
            }
        }
    }

    fn on_new_ack_cc(&mut self, acked_bytes: u32) {
        let mss = self.mss as u32;
        if self.cwnd < self.ssthresh {
            // Slow start
            self.cwnd = self.cwnd.saturating_add(acked_bytes.min(mss * 2));
            return;
        }
        match self.congestion_algo {
            CongestionAlgo::Reno => {
                // Congestion avoidance: +MSS^2 / cwnd por ACK
                let inc = ((mss as u64 * mss as u64) / (self.cwnd.max(1) as u64)).max(1) as u32;
                self.cwnd = self.cwnd.saturating_add(inc);
            }
            CongestionAlgo::Cubic => {
                let start = *self.cubic_epoch_start_ms.get_or_insert(self.now_ms);
                let t = (self.now_ms.saturating_sub(start) as f64) / 1000.0;
                let w_max_segs = (self.cubic_w_max / mss as f64).max(2.0);
                let k = (w_max_segs * 0.3 / 0.4).cbrt();
                let w_cubic_segs = 0.4 * (t - k).powi(3) + w_max_segs;
                let target = (w_cubic_segs.max(2.0) * mss as f64) as u32;
                let inc = if target > self.cwnd {
                    ((target - self.cwnd) / 4).max(1)
                } else {
                    ((mss as u64 * mss as u64) / (self.cwnd.max(1) as u64)).max(1) as u32
                };
                self.cwnd = self.cwnd.saturating_add(inc);
            }
        }
    }

    fn compute_sack_blocks(&self) -> Vec<(u32, u32)> {
        if !self.sack_enabled || self.ooo_buf.is_empty() {
            return Vec::new();
        }
        let mut blocks: Vec<(u32, u32)> = Vec::new();
        for (&seq, data) in &self.ooo_buf {
            let right = seq.wrapping_add(data.len() as u32);
            if let Some(last) = blocks.last_mut() {
                if last.1 == seq {
                    last.1 = right;
                    continue;
                }
            }
            blocks.push((seq, right));
            if blocks.len() == 4 {
                break;
            }
        }
        blocks
    }

    /// Processa um segmento inbound já validado (checksum OK).
    pub fn on_segment(
        &mut self,
        remote_ip: [u8; 4],
        hdr: &TcpHeader,
        payload: &[u8],
        next_iss: u32,
    ) -> Result<Option<TcpConn>> {
        // RST imediato encerra qualquer conexão não-listener
        if hdr.flags.contains(TcpFlags::RST) && self.state != TcpState::Listen {
            self.state = TcpState::Closed;
            self.in_flight.clear();
            self.pending_out.clear();
            self.tx_queue.clear();
            return Ok(None);
        }

        self.peer_window = hdr.window as u32;

        match self.state {
            TcpState::Listen => {
                if !hdr.flags.contains(TcpFlags::SYN) || hdr.flags.contains(TcpFlags::ACK) {
                    return Ok(None);
                }
                let iss = next_iss;
                let mut child = Self::base(
                    FourTuple {
                        local_ip: self.tuple.local_ip,
                        local_port: self.tuple.local_port,
                        remote_ip,
                        remote_port: hdr.src_port,
                    },
                    TcpState::SynRcvd,
                    iss,
                    false,
                );
                child.snd_nxt = iss.wrapping_add(1);
                child.rcv_nxt = hdr.seq.wrapping_add(1);
                child.irs = hdr.seq;
                child.now_ms = self.now_ms;
                if let Some(peer_mss) = hdr.options.mss {
                    child.mss = child.mss.min(peer_mss.max(536));
                }
                child.sack_enabled = hdr.options.sack_permitted;
                child.enqueue_reliable(OutboundSeg {
                    flags: TcpFlags::SYN | TcpFlags::ACK,
                    seq: iss,
                    ack: child.rcv_nxt,
                    payload: vec![],
                    options: TcpOptions {
                        mss: Some(child.mss),
                        window_scale: None,
                        sack_permitted: child.sack_enabled,
                        sack_blocks: vec![],
                    },
                });
                Ok(Some(child))
            }
            TcpState::SynSent => {
                let has_syn = hdr.flags.contains(TcpFlags::SYN);
                let has_ack = hdr.flags.contains(TcpFlags::ACK);
                if has_syn && has_ack {
                    if hdr.ack != self.iss.wrapping_add(1) {
                        return Err(Error::Tcp("SynSent: ACK inesperado"));
                    }
                    if let Some(peer_mss) = hdr.options.mss {
                        self.mss = self.mss.min(peer_mss.max(536));
                    }
                    self.sack_enabled = hdr.options.sack_permitted;
                    self.irs = hdr.seq;
                    self.rcv_nxt = hdr.seq.wrapping_add(1);
                    self.process_ack(hdr.ack, &hdr.options.sack_blocks);
                    self.state = TcpState::Established;
                    self.pending_out.push_back(OutboundSeg {
                        flags: TcpFlags::ACK,
                        seq: self.snd_nxt,
                        ack: self.rcv_nxt,
                        payload: vec![],
                        options: TcpOptions::default(),
                    });
                } else if has_syn && !has_ack {
                    // Simultaneous open (RFC 793)
                    self.irs = hdr.seq;
                    self.rcv_nxt = hdr.seq.wrapping_add(1);
                    self.state = TcpState::SynRcvd;
                    self.pending_out.push_back(OutboundSeg {
                        flags: TcpFlags::SYN | TcpFlags::ACK,
                        seq: self.iss,
                        ack: self.rcv_nxt,
                        payload: vec![],
                        options: TcpOptions {
                            mss: Some(self.mss),
                            window_scale: None,
                            sack_permitted: self.sack_enabled,
                            sack_blocks: vec![],
                        },
                    });
                }
                Ok(None)
            }
            TcpState::SynRcvd => {
                if hdr.flags.contains(TcpFlags::ACK) && hdr.ack == self.iss.wrapping_add(1) {
                    self.process_ack(hdr.ack, &hdr.options.sack_blocks);
                    self.state = TcpState::Established;
                    // Processa eventual payload/FIN piggybacked no ACK final
                    if !payload.is_empty() || hdr.flags.contains(TcpFlags::FIN) {
                        self.handle_established(hdr, payload)?;
                    }
                }
                Ok(None)
            }
            TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::CloseWait
            | TcpState::Closing => {
                self.handle_established(hdr, payload)?;
                Ok(None)
            }
            TcpState::LastAck => {
                if hdr.flags.contains(TcpFlags::ACK) && hdr.ack == self.snd_nxt {
                    self.process_ack(hdr.ack, &hdr.options.sack_blocks);
                    self.state = TcpState::Closed;
                }
                Ok(None)
            }
            TcpState::TimeWait => {
                // Reenvia ACK caso peer retransmita FIN
                if hdr.flags.contains(TcpFlags::FIN) {
                    self.pending_out.push_back(OutboundSeg {
                        flags: TcpFlags::ACK,
                        seq: self.snd_nxt,
                        ack: self.rcv_nxt,
                        payload: vec![],
                        options: TcpOptions::default(),
                    });
                }
                Ok(None)
            }
            TcpState::Closed => Ok(None),
        }
    }

    fn process_ack(&mut self, ack_num: u32, sack_blocks: &[(u32, u32)]) {
        if wrapping_gt(ack_num, self.snd_una) && wrapping_le(ack_num, self.snd_nxt) {
            let acked_bytes = ack_num.wrapping_sub(self.snd_una);
            self.snd_una = ack_num;
            self.dup_acks = 0;

            while let Some(front) = self.in_flight.front() {
                let end = front
                    .seg
                    .seq
                    .wrapping_add(seq_consumed(front.seg.flags, front.seg.payload.len()));
                if wrapping_le(end, ack_num) {
                    let done = self.in_flight.pop_front().unwrap();
                    let rtt_secs = self.now_ms.saturating_sub(done.sent_ms) as f64 / 1000.0;
                    if rtt_secs > 0.0 {
                        self.rto.sample_ack(rtt_secs, done.retransmitted);
                    }
                } else {
                    break;
                }
            }
            self.on_new_ack_cc(acked_bytes);
            self.drain_tx_queue();
        } else if ack_num == self.snd_una && !self.in_flight.is_empty() {
            // ACK duplicado -> Fast Retransmit no 3º dup-ACK
            self.dup_acks = self.dup_acks.saturating_add(1);
            // Remove segmentos já confirmados por SACK da fila de retransmissão opcionalmente
            if !sack_blocks.is_empty() {
                self.in_flight.retain(|f| {
                    let s = f.seg.seq;
                    let e = s.wrapping_add(seq_consumed(f.seg.flags, f.seg.payload.len()));
                    !sack_blocks
                        .iter()
                        .any(|&(l, r)| wrapping_ge(s, l) && wrapping_le(e, r))
                });
            }
            if self.dup_acks == 3 {
                if let Some(front) = self.in_flight.front_mut() {
                    front.sent_ms = self.now_ms;
                    front.retransmitted = true;
                    front.retries = front.retries.saturating_add(1);
                    let mut seg = front.seg.clone();
                    seg.ack = self.rcv_nxt;
                    self.pending_out.push_back(seg);
                    self.retransmissions += 1;
                    self.on_congestion_event(false);
                }
            }
        }
    }

    fn handle_established(&mut self, hdr: &TcpHeader, payload: &[u8]) -> Result<()> {
        // 1. Processa ACK antes de gerar novas respostas
        if hdr.flags.contains(TcpFlags::ACK) {
            self.process_ack(hdr.ack, &hdr.options.sack_blocks);
        }

        // 2. Processa dados (em ordem ou fora de ordem com buffer OOO + SACK)
        // Se receber SYN duplicado (peer retransmitiu SYN-ACK porque nosso ACK se perdeu), reenvia ACK.
        let mut need_ack = hdr.flags.contains(TcpFlags::SYN);
        if !payload.is_empty() {
            let seg_seq = hdr.seq;
            let seg_end = seg_seq.wrapping_add(payload.len() as u32);
            if seg_seq == self.rcv_nxt {
                self.rx_app.extend(payload.iter().copied());
                self.rcv_nxt = seg_end;
                self.drain_ooo_buffer();
                need_ack = true;
            } else if wrapping_gt(seg_seq, self.rcv_nxt) {
                // Segmento futuro -> guarda no buffer de reordenação e envia dup-ACK + SACK
                self.ooo_buf
                    .entry(seg_seq)
                    .or_insert_with(|| payload.to_vec());
                need_ack = true;
            } else if wrapping_gt(seg_end, self.rcv_nxt) {
                // Sobreposição parcial com rcv_nxt
                let skip = self.rcv_nxt.wrapping_sub(seg_seq) as usize;
                self.rx_app.extend(payload[skip..].iter().copied());
                self.rcv_nxt = seg_end;
                self.drain_ooo_buffer();
                need_ack = true;
            } else {
                // Segmento duplicado antigo -> re-ACK para destravar peer
                need_ack = true;
            }
        }

        // 3. Processa FIN (corrigido: checa seq + payload.len() == rcv_nxt para FIN+payload!)
        let fin_seq = hdr.seq.wrapping_add(payload.len() as u32);
        if hdr.flags.contains(TcpFlags::FIN) && fin_seq == self.rcv_nxt {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            need_ack = true;
            match self.state {
                TcpState::Established => self.state = TcpState::CloseWait,
                TcpState::FinWait1 => {
                    if hdr.flags.contains(TcpFlags::ACK) && hdr.ack == self.snd_nxt {
                        self.state = TcpState::TimeWait;
                        self.time_wait_since_ms = Some(self.now_ms);
                    } else {
                        // Simultaneous close
                        self.state = TcpState::Closing;
                    }
                }
                TcpState::FinWait2 => {
                    self.state = TcpState::TimeWait;
                    self.time_wait_since_ms = Some(self.now_ms);
                }
                _ => {}
            }
        } else if self.state == TcpState::FinWait1
            && hdr.flags.contains(TcpFlags::ACK)
            && hdr.ack == self.snd_nxt
        {
            self.state = TcpState::FinWait2;
        } else if self.state == TcpState::Closing
            && hdr.flags.contains(TcpFlags::ACK)
            && hdr.ack == self.snd_nxt
        {
            self.state = TcpState::TimeWait;
            self.time_wait_since_ms = Some(self.now_ms);
        }

        if need_ack {
            let sack_blocks = self.compute_sack_blocks();
            self.pending_out.push_back(OutboundSeg {
                flags: TcpFlags::ACK,
                seq: self.snd_nxt,
                ack: self.rcv_nxt,
                payload: vec![],
                options: TcpOptions {
                    mss: None,
                    window_scale: None,
                    sack_permitted: false,
                    sack_blocks,
                },
            });
        }

        Ok(())
    }

    fn drain_ooo_buffer(&mut self) {
        loop {
            let next_key = self
                .ooo_buf
                .keys()
                .copied()
                .find(|&seq| wrapping_le(seq, self.rcv_nxt));
            let Some(seq) = next_key else { break };
            let data = self.ooo_buf.remove(&seq).unwrap();
            let end = seq.wrapping_add(data.len() as u32);
            if wrapping_gt(end, self.rcv_nxt) {
                let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
                self.rx_app.extend(data[skip..].iter().copied());
                self.rcv_nxt = end;
            }
        }
    }

    pub fn build_segment(&self, seg: &OutboundSeg) -> (TcpHeader, Vec<u8>) {
        let mut hdr = TcpHeader::new(
            self.tuple.local_port,
            self.tuple.remote_port,
            seg.seq,
            seg.ack,
            seg.flags,
            self.advertised_window(),
        );
        if !seg.options.is_empty() {
            hdr = hdr.with_options(seg.options.clone());
        }
        (hdr, seg.payload.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fin_with_payload_is_delivered_and_transitions_to_close_wait() {
        let mut c = TcpConn::active_open([10, 0, 0, 1], 4000, [10, 0, 0, 2], 80, 100);
        c.state = TcpState::Established;
        c.rcv_nxt = 500;
        c.snd_una = 101;
        let hdr = TcpHeader::new(80, 4000, 500, 101, TcpFlags::ACK | TcpFlags::FIN, 65535);
        c.on_segment([10, 0, 0, 2], &hdr, b"bye", 999).unwrap();
        assert_eq!(c.rx_app.iter().copied().collect::<Vec<u8>>(), b"bye");
        assert_eq!(c.state, TcpState::CloseWait);
        assert_eq!(c.rcv_nxt, 504);
    }

    #[test]
    fn ooo_reassembly_and_sack_blocks() {
        let mut c = TcpConn::active_open([10, 0, 0, 1], 4000, [10, 0, 0, 2], 80, 100);
        c.state = TcpState::Established;
        c.rcv_nxt = 1000;
        c.snd_una = 101;
        // Chega segundo segmento (1005..1010) antes do primeiro (1000..1005)
        let h2 = TcpHeader::new(80, 4000, 1005, 101, TcpFlags::ACK, 65535);
        c.on_segment([10, 0, 0, 2], &h2, b"world", 999).unwrap();
        assert!(c.rx_app.is_empty());
        let ack_seg = c.pending_out.back().unwrap();
        assert_eq!(ack_seg.options.sack_blocks, vec![(1005, 1010)]);

        // Agora chega o primeiro segmento (1000..1005) -> reassembly completa!
        let h1 = TcpHeader::new(80, 4000, 1000, 101, TcpFlags::ACK, 65535);
        c.on_segment([10, 0, 0, 2], &h1, b"hello", 999).unwrap();
        assert_eq!(c.rx_app.iter().copied().collect::<Vec<u8>>(), b"helloworld");
        assert_eq!(c.rcv_nxt, 1010);
    }

    #[test]
    fn rst_closes_connection_immediately() {
        let mut c = TcpConn::active_open([10, 0, 0, 1], 4000, [10, 0, 0, 2], 80, 100);
        let rst = TcpHeader::new(80, 4000, 0, 101, TcpFlags::RST, 0);
        c.on_segment([10, 0, 0, 2], &rst, &[], 999).unwrap();
        assert_eq!(c.state, TcpState::Closed);
    }

    #[test]
    fn wrapping_lt_sanity() {
        assert!(crate::seq::wrapping_lt(10, 20));
    }
}
