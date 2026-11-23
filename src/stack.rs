//! Orquestração L2–L4 completa: Ethernet/802.1Q, ARP com aging/proxy, IPv4 com fragmentação/reassembly
//! e tabela de roteamento, ICMP (Echo + Unreachable + TimeExceeded), UDP (multicast + connected) e
//! TCP confiável (OOO + SACK + RTO + Fast Retransmit + Reno/Cubic).

use std::collections::{HashMap, HashSet, VecDeque};

use crate::error::{Error, Result};
use crate::netdev::NetDevice;
use crate::proto::arp::{ArpOp, ArpPacket};
use crate::proto::eth::{EtherType, EthernetFrame, VlanTag, MAC_BROADCAST};
use crate::proto::icmp::{IcmpEcho, IcmpError, IcmpMessage, IcmpType};
use crate::proto::ipv4::{self, IpProtocol, Ipv4Header, Ipv4Reassembler};
use crate::proto::tcp::{self, TcpHeader};
use crate::proto::udp::{self, is_multicast_ipv4, UdpHeader};
use crate::tcp_conn::{CongestionAlgo, FourTuple, TcpConn, TcpState};

/// Fila de datagramas UDP entregues à aplicação: (src_ip, src_port, payload).
pub type UdpDatagram = ([u8; 4], u16, Vec<u8>);

/// Entrada da tabela de roteamento IPv4 (longest-prefix match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteEntry {
    pub network: [u8; 4],
    pub mask: [u8; 4],
    pub next_hop: [u8; 4],
}

impl RouteEntry {
    pub fn prefix_len(&self) -> u32 {
        u32::from_be_bytes(self.mask).count_ones()
    }

    pub fn matches(&self, dst: [u8; 4]) -> bool {
        let d = u32::from_be_bytes(dst);
        let n = u32::from_be_bytes(self.network);
        let m = u32::from_be_bytes(self.mask);
        (d & m) == (n & m)
    }
}

#[derive(Debug, Clone, Copy)]
struct ArpEntry {
    mac: [u8; 6],
    inserted_ms: u64,
    static_entry: bool,
}

/// Stack TCP/IP user-space completo.
pub struct Stack {
    nic: Box<dyn NetDevice>,
    /// Se true, o dispositivo é L3 (TUN): sem Ethernet/ARP.
    l3: bool,
    pub ip: [u8; 4],
    mac: [u8; 6],
    /// Tag VLAN 802.1Q opcional para frames L2.
    vlan: Option<VlanTag>,
    /// MTU IPv4 (default 1500; payloads maiores são fragmentados automaticamente).
    mtu: usize,
    /// Relógio virtual determinístico (ms) avançado via `tick(now_ms)`.
    now_ms: u64,
    /// TTL de entradas dinâmicas no cache ARP (default 60s).
    arp_ttl_ms: u64,
    /// Se true, responde ARP requests para IPs presentes na tabela `proxy_arp_ips`.
    proxy_arp_ips: HashSet<[u8; 4]>,
    arp_cache: HashMap<[u8; 4], ArpEntry>,
    routes: Vec<RouteEntry>,
    reassembler: Ipv4Reassembler,
    /// Portas UDP bound → fila de RX.
    udp_binds: HashMap<u16, VecDeque<UdpDatagram>>,
    /// Peer conectado opcional por porta UDP (para `udp_connect`).
    udp_connected: HashMap<u16, ([u8; 4], u16)>,
    /// Grupos multicast IPv4 ingressados.
    multicast_groups: HashSet<[u8; 4]>,
    /// Conexões TCP indexadas por 4-tuple (listeners usam remote=0).
    tcp_conns: HashMap<FourTuple, TcpConn>,
    /// Filhos SynRcvd/Established ainda não aceitos pelo `accept`.
    tcp_backlog: VecDeque<FourTuple>,
    iss_counter: u32,
    ip_id: u16,
    /// Echo ICMP replies recebidos (para ping).
    icmp_replies: VecDeque<IcmpEcho>,
    /// Mensagens de erro ICMP recebidas (Port Unreachable, Time Exceeded).
    icmp_errors: VecDeque<IcmpError>,
}

impl Stack {
    /// Stack L2 (Ethernet) sobre NIC em memória, FaultyNic ou TAP.
    pub fn new(nic: Box<dyn NetDevice>, ip: [u8; 4]) -> Self {
        let mac = nic.mac();
        Self {
            nic,
            l3: false,
            ip,
            mac,
            vlan: None,
            mtu: 1500,
            now_ms: 0,
            arp_ttl_ms: 60_000,
            proxy_arp_ips: HashSet::new(),
            arp_cache: HashMap::new(),
            routes: Vec::new(),
            reassembler: Ipv4Reassembler::new(30_000),
            udp_binds: HashMap::new(),
            udp_connected: HashMap::new(),
            multicast_groups: HashSet::new(),
            tcp_conns: HashMap::new(),
            tcp_backlog: VecDeque::new(),
            iss_counter: 1000,
            ip_id: 1,
            icmp_replies: VecDeque::new(),
            icmp_errors: VecDeque::new(),
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

    pub fn set_vlan(&mut self, vlan: Option<VlanTag>) {
        self.vlan = vlan;
    }

    pub fn vlan(&self) -> Option<VlanTag> {
        self.vlan
    }

    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu.max(68);
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn set_arp_ttl_ms(&mut self, ttl_ms: u64) {
        self.arp_ttl_ms = ttl_ms;
    }

    pub fn add_proxy_arp_ip(&mut self, ip: [u8; 4]) {
        self.proxy_arp_ips.insert(ip);
    }

    pub fn add_route(&mut self, route: RouteEntry) {
        self.routes.push(route);
    }

    pub fn set_default_gateway(&mut self, gateway: [u8; 4]) {
        self.add_route(RouteEntry {
            network: [0, 0, 0, 0],
            mask: [0, 0, 0, 0],
            next_hop: gateway,
        });
    }

    pub fn resolve_next_hop(&self, dst: [u8; 4]) -> [u8; 4] {
        self.routes
            .iter()
            .filter(|r| r.matches(dst))
            .max_by_key(|r| r.prefix_len())
            .map(|r| r.next_hop)
            .unwrap_or(dst)
    }

    pub fn arp_insert(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        self.arp_cache.insert(
            ip,
            ArpEntry {
                mac,
                inserted_ms: self.now_ms,
                static_entry: false,
            },
        );
    }

    pub fn arp_lookup(&self, ip: &[u8; 4]) -> Option<[u8; 6]> {
        self.arp_cache.get(ip).map(|e| e.mac)
    }

    /// Pré-popula entrada ARP estática (não expira no aging); útil em testes determinísticos.
    pub fn seed_arp(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        self.arp_cache.insert(
            ip,
            ArpEntry {
                mac,
                inserted_ms: self.now_ms,
                static_entry: true,
            },
        );
    }

    /// Avança o relógio virtual: expira ARP dinâmico, expira fragmentos IPv4 e dispara timers TCP (RTO/TIME-WAIT).
    pub fn tick(&mut self, now_ms: u64) -> Result<usize> {
        self.now_ms = now_ms;
        // 1. Aging de entradas dinâmicas ARP
        let ttl = self.arp_ttl_ms;
        self.arp_cache
            .retain(|_, e| e.static_entry || now_ms.saturating_sub(e.inserted_ms) < ttl);
        // 2. Expiração de fragmentos IPv4 incompletos -> ICMP Time Exceeded (code 1)
        let expired_frags = self.reassembler.expire(now_ms);
        for (src_ip, excerpt) in expired_frags {
            let icmp = IcmpError::reassembly_timeout(&excerpt).encode();
            let _ = self.send_ip(src_ip, IpProtocol::Icmp, &icmp);
        }
        // 3. Timers TCP (RTO + backoff + TIME-WAIT)
        let mut retrans = 0;
        for conn in self.tcp_conns.values_mut() {
            retrans += conn.tick(now_ms);
        }
        self.flush_tcp()?;
        Ok(retrans)
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
        self.flush_tcp()?;
        Ok(n)
    }

    fn handle_frame(&mut self, frame: &[u8]) -> Result<()> {
        if self.l3 {
            return self.handle_ipv4(frame);
        }
        let eth = EthernetFrame::parse(frame)?;
        // Se VLAN está configurada neste stack, filtra VID divergente
        if let Some(expected) = self.vlan {
            match eth.vlan {
                Some(got) if got.vid == expected.vid => {}
                _ => return Ok(()),
            }
        }
        match eth.ethertype {
            EtherType::Arp => self.handle_arp(&eth.payload, eth.src),
            EtherType::Ipv4 => self.handle_ipv4(&eth.payload),
            EtherType::Other(_) => Ok(()),
        }
    }

    fn handle_arp(&mut self, payload: &[u8], _eth_src: [u8; 6]) -> Result<()> {
        let pkt = ArpPacket::parse(payload)?;
        self.arp_insert(pkt.sender_ip, pkt.sender_mac);
        let should_reply = pkt.op == ArpOp::Request
            && (pkt.target_ip == self.ip || self.proxy_arp_ips.contains(&pkt.target_ip));
        if should_reply {
            let reply = ArpPacket::reply(self.mac, pkt.target_ip, pkt.sender_mac, pkt.sender_ip);
            self.send_eth(pkt.sender_mac, EtherType::Arp, &reply.encode())?;
        }
        Ok(())
    }

    fn handle_ipv4(&mut self, packet: &[u8]) -> Result<()> {
        let (hdr, ihl) = Ipv4Header::parse(packet)?;
        if hdr.ttl == 0 {
            let err = IcmpError::ttl_exceeded(packet).encode();
            let _ = self.send_ip(hdr.src, IpProtocol::Icmp, &err);
            return Ok(());
        }
        let is_ours = hdr.dst == self.ip
            || hdr.dst == [255, 255, 255, 255]
            || (is_multicast_ipv4(hdr.dst) && self.multicast_groups.contains(&hdr.dst));
        if !is_ours {
            return Ok(());
        }

        let total = hdr.total_length as usize;
        let raw_body = &packet[ihl..total];
        let assembled_buf: Vec<u8>;
        let body: &[u8] = if hdr.is_fragmented() {
            match self.reassembler.push(&hdr, raw_body, packet, self.now_ms) {
                Some(full) => {
                    assembled_buf = full;
                    &assembled_buf
                }
                None => return Ok(()),
            }
        } else {
            raw_body
        };

        match hdr.protocol {
            IpProtocol::Icmp => self.handle_icmp(hdr.src, body),
            IpProtocol::Udp => self.handle_udp(hdr.src, hdr.dst, body, packet),
            IpProtocol::Tcp => self.handle_tcp(hdr.src, hdr.dst, body),
            IpProtocol::Other(_) => Ok(()),
        }
    }

    fn handle_icmp(&mut self, src: [u8; 4], body: &[u8]) -> Result<()> {
        let msg = match IcmpMessage::parse(body) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        match msg {
            IcmpMessage::Echo(echo) => match echo.kind {
                IcmpType::EchoRequest => {
                    let reply = echo.to_reply().encode();
                    self.send_ip(src, IpProtocol::Icmp, &reply)?;
                }
                IcmpType::EchoReply => {
                    self.icmp_replies.push_back(echo);
                }
                _ => {}
            },
            IcmpMessage::Error(err) => {
                self.icmp_errors.push_back(err);
            }
        }
        Ok(())
    }

    fn handle_udp(
        &mut self,
        src: [u8; 4],
        dst: [u8; 4],
        body: &[u8],
        raw_ip_packet: &[u8],
    ) -> Result<()> {
        udp::verify_checksum(src, dst, body)?;
        let (uh, payload) = UdpHeader::parse(body)?;
        // Se socket UDP estiver conectado, filtra pacotes de outro peer
        if let Some(&(peer_ip, peer_port)) = self.udp_connected.get(&uh.dst_port) {
            if src != peer_ip || uh.src_port != peer_port {
                return Ok(());
            }
        }
        if let Some(q) = self.udp_binds.get_mut(&uh.dst_port) {
            q.push_back((src, uh.src_port, payload.to_vec()));
        } else if dst == self.ip {
            // Porta UDP não bound em unicast -> responde ICMP Port Unreachable (RFC 792)
            let err = IcmpError::port_unreachable(raw_ip_packet).encode();
            let _ = self.send_ip(src, IpProtocol::Icmp, &err);
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
        let frame = match self.vlan {
            Some(tag) => EthernetFrame::with_vlan(dst_mac, self.mac, tag, et, payload.to_vec()),
            None => EthernetFrame::new(dst_mac, self.mac, et, payload.to_vec()),
        };
        self.nic.send(&frame.encode())
    }

    fn send_ip(&mut self, dst: [u8; 4], proto: IpProtocol, payload: &[u8]) -> Result<()> {
        self.ip_id = self.ip_id.wrapping_add(1);
        let id = self.ip_id;
        let packets = ipv4::fragment_ipv4(self.ip, dst, proto, id, 64, payload, self.mtu)?;

        if self.l3 {
            for pkt in packets {
                self.nic.send(&pkt)?;
            }
            return Ok(());
        }

        let dst_mac = if dst == [255, 255, 255, 255] {
            MAC_BROADCAST
        } else if is_multicast_ipv4(dst) {
            // RFC 1112: mapeamento Ethernet multicast 01:00:5e:xx:yy:zz
            [0x01, 0x00, 0x5e, dst[1] & 0x7f, dst[2], dst[3]]
        } else {
            let next_hop = self.resolve_next_hop(dst);
            if let Some(entry) = self.arp_cache.get(&next_hop) {
                entry.mac
            } else {
                let req = ArpPacket::request(self.mac, self.ip, next_hop);
                self.send_eth(MAC_BROADCAST, EtherType::Arp, &req.encode())?;
                return Err(Error::ArpUnresolved(next_hop));
            }
        };

        for pkt in packets {
            self.send_eth(dst_mac, EtherType::Ipv4, &pkt)?;
        }
        Ok(())
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

    // ─── ICMP ───────────────────────────────────────────────────────────

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

    pub fn icmp_pop_error(&mut self) -> Option<IcmpError> {
        self.icmp_errors.pop_front()
    }

    // ─── UDP ────────────────────────────────────────────────────────────

    pub fn udp_bind(&mut self, port: u16) -> Result<()> {
        if self.udp_binds.contains_key(&port) {
            return Err(Error::Socket(format!("UDP porta {port} já bound")));
        }
        self.udp_binds.insert(port, VecDeque::new());
        Ok(())
    }

    pub fn udp_connect(
        &mut self,
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
    ) -> Result<()> {
        if !self.udp_binds.contains_key(&local_port) {
            return Err(Error::Socket(format!("UDP {local_port} não bound")));
        }
        self.udp_connected
            .insert(local_port, (remote_ip, remote_port));
        Ok(())
    }

    pub fn udp_send_connected(&mut self, local_port: u16, payload: &[u8]) -> Result<()> {
        let &(dst, dst_port) = self
            .udp_connected
            .get(&local_port)
            .ok_or_else(|| Error::Socket(format!("UDP {local_port} não conectado")))?;
        self.udp_send(local_port, dst, dst_port, payload)
    }

    pub fn udp_join_multicast(&mut self, group: [u8; 4]) -> Result<()> {
        if !is_multicast_ipv4(group) {
            return Err(Error::Unsupported(
                "udp: endereço não é multicast 224.0.0.0/4",
            ));
        }
        self.multicast_groups.insert(group);
        Ok(())
    }

    pub fn udp_leave_multicast(&mut self, group: [u8; 4]) {
        self.multicast_groups.remove(&group);
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

    /// Aceita a primeira conexão `Established` da fila de backlog (descartando entradas fechadas).
    pub fn tcp_accept(&mut self) -> Result<FourTuple> {
        let mut scanned = 0;
        let len = self.tcp_backlog.len();
        while scanned < len {
            let Some(key) = self.tcp_backlog.pop_front() else {
                break;
            };
            scanned += 1;
            match self.tcp_conns.get(&key).map(|c| c.state) {
                Some(TcpState::Established | TcpState::CloseWait) => return Ok(key),
                Some(TcpState::Closed) | None => {
                    // Conexão abortada/fechada antes do accept: descarta do backlog
                }
                Some(_) => {
                    // Ainda em SynRcvd: mantém no backlog e continua procurando
                    self.tcp_backlog.push_back(key);
                }
            }
        }
        Err(Error::WouldBlock)
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

    pub fn tcp_set_congestion_algo(
        &mut self,
        conn: &FourTuple,
        algo: CongestionAlgo,
    ) -> Result<()> {
        let c = self
            .tcp_conns
            .get_mut(conn)
            .ok_or(Error::Tcp("tcp_set_congestion_algo: conn inexistente"))?;
        c.congestion_algo = algo;
        Ok(())
    }

    pub fn tcp_retransmissions(&self, conn: &FourTuple) -> Option<u64> {
        self.tcp_conns.get(conn).map(|c| c.retransmissions)
    }

    pub fn tcp_cwnd(&self, conn: &FourTuple) -> Option<u32> {
        self.tcp_conns.get(conn).map(|c| c.cwnd)
    }
}
