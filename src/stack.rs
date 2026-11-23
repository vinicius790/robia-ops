//! Orquestração L2–L4: ARP, ICMP echo, UDP e TCP subset sobre um [`NetDevice`].

use std::collections::{HashMap, VecDeque};

use crate::error::{Error, Result};
use crate::netdev::NetDevice;
use crate::proto::arp::{ArpOp, ArpPacket};
use crate::proto::eth::{EtherType, EthernetFrame, MAC_BROADCAST};
use crate::proto::icmp::{IcmpEcho, IcmpType};
use crate::proto::ipv4::{self, IpProtocol, Ipv4Header};
use crate::proto::tcp::{self, TcpHeader};
use crate::proto::udp::{self, UdpHeader};
use crate::tcp_conn::{FourTuple, TcpConn, TcpState};

/// Fila de datagramas UDP entregues à aplicação: (src_ip, src_port, payload).
pub type UdpDatagram = ([u8; 4], u16, Vec<u8>);

/// Stack TCP/IP user-space.
pub struct Stack {
    nic: Box<dyn NetDevice>,
    /// Se true, o dispositivo é L3 (TUN): sem Ethernet/ARP.
    l3: bool,
    pub ip: [u8; 4],
    mac: [u8; 6],
    arp_cache: HashMap<[u8; 4], [u8; 6]>,
    /// Portas UDP bound → fila de RX.
    udp_binds: HashMap<u16, VecDeque<UdpDatagram>>,
    /// Conexões TCP indexadas por 4-tuple (listeners usam remote=0).
    tcp_conns: HashMap<FourTuple, TcpConn>,
    /// Filhos Established ainda não aceitos pelo `accept`.
    tcp_backlog: VecDeque<FourTuple>,
    iss_counter: u32,
    ip_id: u16,
    /// Echo ICMP replies recebidos (para ping).
    icmp_replies: VecDeque<IcmpEcho>,
}

impl Stack {
    /// Stack L2 (Ethernet) sobre NIC em memória ou TAP.
    pub fn new(nic: Box<dyn NetDevice>, ip: [u8; 4]) -> Self {
        let mac = nic.mac();
        Self {
            nic,
            l3: false,
            ip,
            mac,
            arp_cache: HashMap::new(),
            udp_binds: HashMap::new(),
            tcp_conns: HashMap::new(),
            tcp_backlog: VecDeque::new(),
            iss_counter: 1000,
            ip_id: 1,
            icmp_replies: VecDeque::new(),
        }
    }

    /// Stack L3 (IP puro) para TUN — sem Ethernet/ARP.
    pub fn with_l3_device(nic: Box<dyn NetDevice>, ip: [u8; 4]) -> Self {
        let mut s = Self::new(nic, ip);
        s.l3 = true;
        s
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    pub fn is_l3(&self) -> bool {
        self.l3
    }

    pub fn arp_insert(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        self.arp_cache.insert(ip, mac);
    }

    pub fn arp_lookup(&self, ip: &[u8; 4]) -> Option<[u8; 6]> {
        self.arp_cache.get(ip).copied()
    }

    // ─── pump ───────────────────────────────────────────────────────────

    /// Lê e processa todos os frames disponíveis no NIC (não-bloqueante).
    pub fn poll(&mut self) -> Result<usize> {
        let mut n = 0;
        loop {
            match self.nic.recv() {
                Ok(frame) => {
                    self.handle_frame(&frame)?;
                    n += 1;
                }
                Err(Error::WouldBlock) => break,
                Err(e) => return Err(e),
            }
        }
        // Respostas TCP (SYN-ACK, ACK de dados, etc.) geradas no handle
        self.flush_tcp()?;
        Ok(n)
    }

    fn handle_frame(&mut self, frame: &[u8]) -> Result<()> {
        if self.l3 {
            return self.handle_ipv4(frame);
        }
        let eth = EthernetFrame::parse(frame)?;
        match eth.ethertype {
            EtherType::Arp => self.handle_arp(&eth.payload, eth.src),
            EtherType::Ipv4 => self.handle_ipv4(&eth.payload),
            EtherType::Other(_) => Ok(()), // descarta silenciosamente
        }
    }

    fn handle_arp(&mut self, payload: &[u8], _eth_src: [u8; 6]) -> Result<()> {
        let pkt = ArpPacket::parse(payload)?;
        // Aprende sempre o sender
        self.arp_cache.insert(pkt.sender_ip, pkt.sender_mac);
        if pkt.op == ArpOp::Request && pkt.target_ip == self.ip {
            let reply = ArpPacket::reply(self.mac, self.ip, pkt.sender_mac, pkt.sender_ip);
            self.send_eth(pkt.sender_mac, EtherType::Arp, &reply.encode())?;
        }
        Ok(())
    }

    fn handle_ipv4(&mut self, packet: &[u8]) -> Result<()> {
        let (hdr, ihl) = Ipv4Header::parse(packet)?;
        if hdr.dst != self.ip && hdr.dst != [255, 255, 255, 255] {
            return Ok(()); // não é pra nós
        }
        // Aprende ARP se L2 e veio de Ethernet — já aprendemos no ARP;
        // aqui só processamos L4.
        let body = &packet[ihl..];
        let total = hdr.total_length as usize;
        let body = if total >= ihl && total <= packet.len() {
            &packet[ihl..total]
        } else {
            body
        };
        match hdr.protocol {
            IpProtocol::Icmp => self.handle_icmp(hdr.src, body),
            IpProtocol::Udp => self.handle_udp(hdr.src, hdr.dst, body),
            IpProtocol::Tcp => self.handle_tcp(hdr.src, hdr.dst, body),
            IpProtocol::Other(_) => Ok(()),
        }
    }

    fn handle_icmp(&mut self, src: [u8; 4], body: &[u8]) -> Result<()> {
        let echo = match IcmpEcho::parse(body) {
            Ok(e) => e,
            Err(_) => return Ok(()), // ignora outros ICMP
        };
        match echo.kind {
            IcmpType::EchoRequest => {
                let reply = echo.to_reply().encode();
                self.send_ip(src, IpProtocol::Icmp, &reply)?;
            }
            IcmpType::EchoReply => {
                self.icmp_replies.push_back(echo);
            }
        }
        Ok(())
    }

    fn handle_udp(&mut self, src: [u8; 4], dst: [u8; 4], body: &[u8]) -> Result<()> {
        udp::verify_checksum(src, dst, body)?;
        let (uh, payload) = UdpHeader::parse(body)?;
        if let Some(q) = self.udp_binds.get_mut(&uh.dst_port) {
            q.push_back((src, uh.src_port, payload.to_vec()));
        }
        Ok(())
    }

    fn handle_tcp(&mut self, src: [u8; 4], dst: [u8; 4], body: &[u8]) -> Result<()> {
        tcp::verify_checksum(src, dst, body)?;
        let (hdr, payload) = TcpHeader::parse(body)?;
        if dst != self.ip {
            return Ok(());
        }

        let exact = FourTuple {
            local_ip: self.ip,
            local_port: hdr.dst_port,
            remote_ip: src,
            remote_port: hdr.src_port,
        };
        let listen_key = FourTuple {
            local_ip: self.ip,
            local_port: hdr.dst_port,
            remote_ip: [0; 4],
            remote_port: 0,
        };

        // Preferência: conexão estabelecida / SynSent / SynRcvd
        if self.tcp_conns.contains_key(&exact) {
            let iss = self.next_iss();
            let child = {
                let conn = self.tcp_conns.get_mut(&exact).unwrap();
                conn.on_segment(src, &hdr, payload, iss)?
            };
            if let Some(c) = child {
                let key = c.tuple;
                self.tcp_conns.insert(key, c);
            }
            return Ok(());
        }

        // Listener
        if self.tcp_conns.contains_key(&listen_key) {
            let iss = self.next_iss();
            let child = {
                let listener = self.tcp_conns.get_mut(&listen_key).unwrap();
                listener.on_segment(src, &hdr, payload, iss)?
            };
            if let Some(c) = child {
                let key = c.tuple;
                self.tcp_backlog.push_back(key);
                self.tcp_conns.insert(key, c);
            }
        }
        Ok(())
    }

    fn next_iss(&mut self) -> u32 {
        self.iss_counter = self.iss_counter.wrapping_add(10000);
        self.iss_counter
    }

    // ─── envio ──────────────────────────────────────────────────────────

    fn send_eth(&mut self, dst_mac: [u8; 6], et: EtherType, payload: &[u8]) -> Result<()> {
        let frame = EthernetFrame::new(dst_mac, self.mac, et, payload.to_vec());
        self.nic.send(&frame.encode())
    }

    fn send_ip(&mut self, dst: [u8; 4], proto: IpProtocol, payload: &[u8]) -> Result<()> {
        let mut pkt = ipv4::encapsulate(self.ip, dst, proto, payload);
        // Ajusta identification
        if pkt.len() >= 6 {
            self.ip_id = self.ip_id.wrapping_add(1);
            pkt[4..6].copy_from_slice(&self.ip_id.to_be_bytes());
            // Recalcula checksum IP
            pkt[10] = 0;
            pkt[11] = 0;
            let csum = crate::checksum::internet_checksum(&pkt[..20]);
            pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        }

        if self.l3 {
            return self.nic.send(&pkt);
        }

        let dst_mac = if let Some(m) = self.arp_cache.get(&dst).copied() {
            m
        } else {
            // Envia ARP request e falha — caller deve poll + retry
            let req = ArpPacket::request(self.mac, self.ip, dst);
            self.send_eth(MAC_BROADCAST, EtherType::Arp, &req.encode())?;
            return Err(Error::ArpUnresolved(dst));
        };
        self.send_eth(dst_mac, EtherType::Ipv4, &pkt)
    }

    fn send_tcp_seg(&mut self, remote_ip: [u8; 4], hdr: &TcpHeader, payload: &[u8]) -> Result<()> {
        let seg = tcp::encapsulate(self.ip, remote_ip, hdr, payload);
        self.send_ip(remote_ip, IpProtocol::Tcp, &seg)
    }

    /// Envia e drena pending de **todas** as conexões TCP.
    pub fn flush_tcp(&mut self) -> Result<()> {
        let mut batch: Vec<(FourTuple, crate::tcp_conn::OutboundSeg)> = Vec::new();
        for (k, c) in self.tcp_conns.iter_mut() {
            while let Some(seg) = c.pending_out.pop_front() {
                batch.push((*k, seg));
            }
        }
        for (tuple, seg) in batch {
            let (hdr, payload) = {
                let conn = self
                    .tcp_conns
                    .get(&tuple)
                    .ok_or(Error::Tcp("flush: conn sumiu"))?;
                conn.build_segment(&seg)
            };
            self.send_tcp_seg(tuple.remote_ip, &hdr, &payload)?;
        }
        Ok(())
    }

    // ─── ICMP ping ──────────────────────────────────────────────────────

    pub fn icmp_echo_request(
        &mut self,
        dst: [u8; 4],
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Result<()> {
        let echo = IcmpEcho::request(id, seq, payload.to_vec());
        self.send_ip(dst, IpProtocol::Icmp, &echo.encode())
    }

    pub fn icmp_pop_reply(&mut self) -> Option<IcmpEcho> {
        self.icmp_replies.pop_front()
    }

    // ─── UDP ────────────────────────────────────────────────────────────

    pub fn udp_bind(&mut self, port: u16) -> Result<()> {
        if self.udp_binds.contains_key(&port) {
            return Err(Error::Socket(format!("UDP porta {port} já bound")));
        }
        self.udp_binds.insert(port, VecDeque::new());
        Ok(())
    }

    pub fn udp_send(
        &mut self,
        src_port: u16,
        dst: [u8; 4],
        dst_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        if !self.udp_binds.contains_key(&src_port) {
            return Err(Error::Socket(format!("UDP {src_port} não bound")));
        }
        let udp = udp::encapsulate(self.ip, dst, src_port, dst_port, payload);
        self.send_ip(dst, IpProtocol::Udp, &udp)
    }

    pub fn udp_recv(&mut self, port: u16) -> Result<UdpDatagram> {
        let q = self
            .udp_binds
            .get_mut(&port)
            .ok_or_else(|| Error::Socket(format!("UDP {port} não bound")))?;
        q.pop_front().ok_or(Error::WouldBlock)
    }

    // ─── TCP API ────────────────────────────────────────────────────────

    pub fn tcp_listen(&mut self, port: u16) -> Result<()> {
        let key = FourTuple {
            local_ip: self.ip,
            local_port: port,
            remote_ip: [0; 4],
            remote_port: 0,
        };
        if self.tcp_conns.contains_key(&key) {
            return Err(Error::Socket(format!("TCP listen {port} ocupada")));
        }
        self.tcp_conns.insert(key, TcpConn::listen(self.ip, port));
        Ok(())
    }

    pub fn tcp_connect(
        &mut self,
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
    ) -> Result<FourTuple> {
        let iss = self.next_iss();
        let conn = TcpConn::active_open(self.ip, local_port, remote_ip, remote_port, iss);
        let key = conn.tuple;
        self.tcp_conns.insert(key, conn);
        self.flush_tcp()?;
        Ok(key)
    }

    pub fn tcp_accept(&mut self) -> Result<FourTuple> {
        let key = self.tcp_backlog.pop_front().ok_or(Error::WouldBlock)?;
        // Só entrega se Established
        let st = self
            .tcp_conns
            .get(&key)
            .map(|c| c.state)
            .ok_or(Error::Tcp("accept: conn sumiu"))?;
        if st != TcpState::Established {
            // Devolve ao fim e tenta depois
            self.tcp_backlog.push_back(key);
            return Err(Error::WouldBlock);
        }
        Ok(key)
    }

    pub fn tcp_send(&mut self, conn: &FourTuple, data: &[u8]) -> Result<()> {
        {
            let c = self
                .tcp_conns
                .get_mut(conn)
                .ok_or(Error::Tcp("tcp_send: conn inexistente"))?;
            c.send_data(data)?;
        }
        self.flush_tcp()
    }

    pub fn tcp_recv(&mut self, conn: &FourTuple) -> Result<Vec<u8>> {
        let c = self
            .tcp_conns
            .get_mut(conn)
            .ok_or(Error::Tcp("tcp_recv: conn inexistente"))?;
        if c.rx_app.is_empty() {
            return Err(Error::WouldBlock);
        }
        Ok(c.rx_app.drain(..).collect())
    }

    pub fn tcp_close(&mut self, conn: &FourTuple) -> Result<()> {
        {
            let c = self
                .tcp_conns
                .get_mut(conn)
                .ok_or(Error::Tcp("tcp_close: conn inexistente"))?;
            c.close()?;
        }
        self.flush_tcp()
    }

    pub fn tcp_state(&self, conn: &FourTuple) -> Option<TcpState> {
        self.tcp_conns.get(conn).map(|c| c.state)
    }

    /// Pré-popula ARP e envia; útil em testes com MemoryNic.
    pub fn seed_arp(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        self.arp_cache.insert(ip, mac);
    }
}
