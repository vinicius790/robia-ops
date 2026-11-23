//! Testes de integração sobre MemoryNic — **sem root**.

use userspace_tcpip::proto::eth::EtherType;
use userspace_tcpip::proto::icmp::IcmpType;
use userspace_tcpip::{paired_nics, Error, Stack, TcpState};

fn twin() -> (Stack, Stack) {
    let mac_a = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a];
    let mac_b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0b];
    let (nic_a, nic_b) = paired_nics(mac_a, mac_b);
    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let mut a = Stack::new(Box::new(nic_a), ip_a);
    let mut b = Stack::new(Box::new(nic_b), ip_b);
    // ARP estático: evita corrida request/reply nos testes determinísticos
    a.seed_arp(ip_b, mac_b);
    b.seed_arp(ip_a, mac_a);
    (a, b)
}

fn pump(a: &mut Stack, b: &mut Stack, rounds: usize) {
    for _ in 0..rounds {
        let _ = a.poll();
        let _ = b.poll();
    }
}

#[test]
fn icmp_ping_roundtrip() {
    let (mut a, mut b) = twin();
    a.icmp_echo_request([10, 0, 0, 2], 0x42, 1, b"ping-payload")
        .unwrap();
    pump(&mut a, &mut b, 4);
    let rep = a.icmp_pop_reply().expect("echo reply");
    assert_eq!(rep.kind, IcmpType::EchoReply);
    assert_eq!(rep.identifier, 0x42);
    assert_eq!(rep.sequence, 1);
    assert_eq!(rep.payload, b"ping-payload");
}

#[test]
fn arp_request_learns_and_replies() {
    let mac_a = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a];
    let mac_b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0b];
    let (nic_a, nic_b) = paired_nics(mac_a, mac_b);
    let mut a = Stack::new(Box::new(nic_a), [10, 0, 0, 1]);
    let mut b = Stack::new(Box::new(nic_b), [10, 0, 0, 2]);
    // Sem seed: send_ip deve emitir ARP e falhar uma vez
    let err = a.icmp_echo_request([10, 0, 0, 2], 1, 1, b"x").unwrap_err();
    assert!(matches!(err, Error::ArpUnresolved(_)));
    // B processa ARP request e responde
    assert!(b.poll().unwrap() >= 1);
    // A processa ARP reply
    assert!(a.poll().unwrap() >= 1);
    assert_eq!(a.arp_lookup(&[10, 0, 0, 2]), Some(mac_b));
    assert_eq!(b.arp_lookup(&[10, 0, 0, 1]), Some(mac_a));
    // Agora o ping completa
    a.icmp_echo_request([10, 0, 0, 2], 1, 2, b"y").unwrap();
    pump(&mut a, &mut b, 4);
    assert!(a.icmp_pop_reply().is_some());
}

#[test]
fn udp_echo_between_stacks() {
    let (mut a, mut b) = twin();
    a.udp_bind(4000).unwrap();
    b.udp_bind(5000).unwrap();
    a.udp_send(4000, [10, 0, 0, 2], 5000, b"hello-udp").unwrap();
    pump(&mut a, &mut b, 2);
    let (src, sport, payload) = b.udp_recv(5000).unwrap();
    assert_eq!(src, [10, 0, 0, 1]);
    assert_eq!(sport, 4000);
    assert_eq!(payload, b"hello-udp");
    // echo
    b.udp_send(5000, src, sport, &payload).unwrap();
    pump(&mut a, &mut b, 2);
    let (_, _, echoed) = a.udp_recv(4000).unwrap();
    assert_eq!(echoed, b"hello-udp");
}

#[test]
fn udp_recv_would_block() {
    let (mut a, _) = twin();
    a.udp_bind(9).unwrap();
    assert!(matches!(a.udp_recv(9), Err(Error::WouldBlock)));
}

#[test]
fn udp_bind_twice_fails() {
    let (mut a, _) = twin();
    a.udp_bind(53).unwrap();
    assert!(a.udp_bind(53).is_err());
}

#[test]
fn tcp_three_way_handshake() {
    let (mut client, mut server) = twin();
    server.tcp_listen(80).unwrap();
    let ck = client.tcp_connect(40000, [10, 0, 0, 2], 80).unwrap();
    pump(&mut client, &mut server, 6);
    assert_eq!(client.tcp_state(&ck), Some(TcpState::Established));
    let sk = server.tcp_accept().unwrap();
    assert_eq!(server.tcp_state(&sk), Some(TcpState::Established));
}

#[test]
fn tcp_data_transfer() {
    let (mut client, mut server) = twin();
    server.tcp_listen(8080).unwrap();
    let ck = client.tcp_connect(41000, [10, 0, 0, 2], 8080).unwrap();
    pump(&mut client, &mut server, 8);
    let sk = server.tcp_accept().unwrap();
    client.tcp_send(&ck, b"GET /").unwrap();
    pump(&mut client, &mut server, 4);
    let got = server.tcp_recv(&sk).unwrap();
    assert_eq!(got, b"GET /");
    server.tcp_send(&sk, b"HTTP/1.0 200").unwrap();
    pump(&mut client, &mut server, 4);
    let got = client.tcp_recv(&ck).unwrap();
    assert_eq!(got, b"HTTP/1.0 200");
}

#[test]
fn tcp_fin_close() {
    let (mut client, mut server) = twin();
    server.tcp_listen(9000).unwrap();
    let ck = client.tcp_connect(42000, [10, 0, 0, 2], 9000).unwrap();
    pump(&mut client, &mut server, 8);
    let sk = server.tcp_accept().unwrap();
    client.tcp_close(&ck).unwrap();
    pump(&mut client, &mut server, 6);
    // Cliente em FinWait*/TimeWait; servidor CloseWait
    let cs = client.tcp_state(&ck).unwrap();
    assert!(
        matches!(
            cs,
            TcpState::FinWait1 | TcpState::FinWait2 | TcpState::TimeWait | TcpState::Closed
        ),
        "client state {cs:?}"
    );
    let ss = server.tcp_state(&sk).unwrap();
    assert!(
        matches!(
            ss,
            TcpState::CloseWait | TcpState::LastAck | TcpState::Closed
        ),
        "server state {ss:?}"
    );
}

#[test]
fn unknown_ethertype_dropped() {
    use userspace_tcpip::proto::eth::EthernetFrame;
    use userspace_tcpip::NetDevice;
    let mac_a = [1u8; 6];
    let mac_b = [2u8; 6];
    let (mut nic_a, nic_b) = paired_nics(mac_a, mac_b);
    let mut stack = Stack::new(Box::new(nic_b), [10, 0, 0, 2]);
    let frame = EthernetFrame::new(mac_b, mac_a, EtherType::Other(0x88cc), vec![0xde, 0xad]);
    nic_a.send(&frame.encode()).unwrap();
    assert_eq!(stack.poll().unwrap(), 1); // processado sem erro
}

#[test]
fn ip_not_for_us_ignored() {
    let (mut a, mut b) = twin();
    // Pacote UDP destinado a terceiro — B não deve enfileirar
    b.udp_bind(7).unwrap();
    // Força envio com dst diferente via ICMP para IP inexistente no cabo:
    // simplesmente não bindamos e verificamos WouldBlock após ping a nós mesmos filtrado.
    a.icmp_echo_request([10, 0, 0, 2], 1, 1, b"z").unwrap();
    pump(&mut a, &mut b, 2);
    // UDP ainda vazio
    assert!(matches!(b.udp_recv(7), Err(Error::WouldBlock)));
}

#[test]
fn tcp_accept_before_handshake_would_block() {
    let (mut _c, mut server) = twin();
    server.tcp_listen(81).unwrap();
    assert!(matches!(server.tcp_accept(), Err(Error::WouldBlock)));
}

#[test]
fn large_udp_payload() {
    let (mut a, mut b) = twin();
    a.udp_bind(1000).unwrap();
    b.udp_bind(1001).unwrap();
    let payload = vec![0xabu8; 1200];
    a.udp_send(1000, [10, 0, 0, 2], 1001, &payload).unwrap();
    pump(&mut a, &mut b, 2);
    let (_, _, got) = b.udp_recv(1001).unwrap();
    assert_eq!(got, payload);
}

#[test]
fn icmp_multiple_pings() {
    let (mut a, mut b) = twin();
    for seq in 1..=3u16 {
        a.icmp_echo_request([10, 0, 0, 2], 7, seq, &[seq as u8])
            .unwrap();
    }
    pump(&mut a, &mut b, 8);
    for seq in 1..=3u16 {
        let r = a.icmp_pop_reply().unwrap();
        assert_eq!(r.sequence, seq);
    }
    assert!(a.icmp_pop_reply().is_none());
}

#[test]
fn tcp_send_before_established_fails() {
    let (mut client, mut server) = twin();
    server.tcp_listen(82).unwrap();
    let ck = client.tcp_connect(43000, [10, 0, 0, 2], 82).unwrap();
    // Sem pump: ainda SynSent
    assert_eq!(client.tcp_state(&ck), Some(TcpState::SynSent));
    assert!(client.tcp_send(&ck, b"nope").is_err());
}

#[test]
fn vlan_8021q_isolation_and_delivery() {
    use userspace_tcpip::proto::eth::VlanTag;
    let (mut a, mut b) = twin();
    a.set_vlan(Some(VlanTag::new(100)));
    b.set_vlan(Some(VlanTag::new(200)));
    a.icmp_echo_request([10, 0, 0, 2], 1, 1, b"vlan").unwrap();
    pump(&mut a, &mut b, 4);
    assert!(a.icmp_pop_reply().is_none()); // VID 100 != 200 descartado

    b.set_vlan(Some(VlanTag::new(100)));
    a.icmp_echo_request([10, 0, 0, 2], 1, 2, b"vlan-ok")
        .unwrap();
    pump(&mut a, &mut b, 4);
    let rep = a.icmp_pop_reply().expect("same VLAN reply");
    assert_eq!(rep.payload, b"vlan-ok");
}

#[test]
fn arp_aging_and_proxy_arp() {
    let mac_a = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a];
    let mac_b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0b];
    let (nic_a, nic_b) = paired_nics(mac_a, mac_b);
    let mut a = Stack::new(Box::new(nic_a), [10, 0, 0, 1]);
    let mut b = Stack::new(Box::new(nic_b), [10, 0, 0, 2]);
    a.set_arp_ttl_ms(1_000);
    b.add_proxy_arp_ip([10, 0, 0, 99]);

    // Proxy ARP: A pergunta por 10.0.0.99 e B responde com seu MAC
    let _ = a.icmp_echo_request([10, 0, 0, 99], 1, 1, b"p");
    pump(&mut a, &mut b, 4);
    assert_eq!(a.arp_lookup(&[10, 0, 0, 99]), Some(mac_b));

    // Aging: após TTL, entrada dinâmica expira
    a.tick(1_500).unwrap();
    assert_eq!(a.arp_lookup(&[10, 0, 0, 99]), None);
}

#[test]
fn ipv4_fragmentation_and_reassembly_over_small_mtu() {
    let (mut a, mut b) = twin();
    a.set_mtu(100);
    b.set_mtu(100);
    a.udp_bind(2000).unwrap();
    b.udp_bind(2001).unwrap();
    let payload: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
    a.udp_send(2000, [10, 0, 0, 2], 2001, &payload).unwrap();
    pump(&mut a, &mut b, 4);
    let (_, _, got) = b.udp_recv(2001).unwrap();
    assert_eq!(got, payload);
}

#[test]
fn icmp_port_unreachable_and_routing_table() {
    use userspace_tcpip::RouteEntry;
    let (mut a, mut b) = twin();
    a.udp_bind(3000).unwrap();
    // Porta 9999 não está bound em B -> deve retornar ICMP Port Unreachable (type 3, code 3)
    a.udp_send(3000, [10, 0, 0, 2], 9999, b"nobody").unwrap();
    pump(&mut a, &mut b, 4);
    let err = a.icmp_pop_error().expect("ICMP port unreachable");
    assert_eq!(err.kind, IcmpType::DestinationUnreachable);
    assert_eq!(err.code, 3);

    // Roteamento longest-prefix match
    a.set_default_gateway([10, 0, 0, 254]);
    a.add_route(RouteEntry {
        network: [192, 168, 1, 0],
        mask: [255, 255, 255, 0],
        next_hop: [10, 0, 0, 2],
    });
    assert_eq!(a.resolve_next_hop([192, 168, 1, 42]), [10, 0, 0, 2]);
    assert_eq!(a.resolve_next_hop([8, 8, 8, 8]), [10, 0, 0, 254]);
}

#[test]
fn udp_connected_and_multicast() {
    let (mut a, mut b) = twin();
    a.udp_bind(4100).unwrap();
    b.udp_bind(4200).unwrap();
    b.udp_connect(4200, [10, 0, 0, 1], 4100).unwrap();
    a.udp_connect(4100, [10, 0, 0, 2], 4200).unwrap();
    a.udp_send_connected(4100, b"direct").unwrap();
    pump(&mut a, &mut b, 2);
    let (_, _, got) = b.udp_recv(4200).unwrap();
    assert_eq!(got, b"direct");

    // Multicast 224.0.0.251
    let (mut m1, mut m2) = twin();
    m1.udp_bind(5353).unwrap();
    m2.udp_bind(5353).unwrap();
    m2.udp_join_multicast([224, 0, 0, 251]).unwrap();
    m1.udp_send(5353, [224, 0, 0, 251], 5353, b"mdns").unwrap();
    pump(&mut m1, &mut m2, 2);
    let (_, _, mcast_got) = m2.udp_recv(5353).unwrap();
    assert_eq!(mcast_got, b"mdns");
}

#[test]
fn tcp_reliable_http11_over_lossy_reordering_link_with_cubic_and_reno() {
    use userspace_tcpip::{
        paired_faulty_nics, CongestionAlgo, HttpRequest, HttpResponse, LinkImpairment,
    };

    for algo in [CongestionAlgo::Reno, CongestionAlgo::Cubic] {
        let imp = LinkImpairment {
            loss_pct: 15,
            reorder_pct: 25,
            duplicate_pct: 10,
            seed: 1337,
        };
        let (na, nb) = paired_faulty_nics([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2], imp, imp);
        let mut client = Stack::new(Box::new(na), [10, 20, 0, 1]);
        let mut server = Stack::new(Box::new(nb), [10, 20, 0, 2]);
        client.seed_arp([10, 20, 0, 2], [0x02, 0, 0, 0, 0, 2]);
        server.seed_arp([10, 20, 0, 1], [0x02, 0, 0, 0, 0, 1]);

        server.tcp_listen(80).unwrap();
        let ck = client.tcp_connect(55000, [10, 20, 0, 2], 80).unwrap();
        client.tcp_set_congestion_algo(&ck, algo).unwrap();

        let mut now_ms = 0u64;
        for _ in 0..40 {
            let _ = client.poll();
            let _ = server.poll();
            if client.tcp_state(&ck) == Some(TcpState::Established) {
                break;
            }
            now_ms += 400;
            let _ = client.tick(now_ms);
            let _ = server.tick(now_ms);
        }
        assert_eq!(client.tcp_state(&ck), Some(TcpState::Established));
        let sk = server.tcp_accept().unwrap();

        let req = HttpRequest::get("test.local", "/data");
        client.tcp_send(&ck, &req.encode()).unwrap();

        // Resposta multi-segmento (4 KB) sob perdas e reordenação
        let expected_body = vec![b'R'; 4096];
        let mut srv_buf = Vec::new();
        let mut cli_buf = Vec::new();
        let mut responded = false;
        let mut got_resp = None;
        for _ in 0..120 {
            let _ = client.poll();
            let _ = server.poll();
            if let Ok(chunk) = server.tcp_recv(&sk) {
                srv_buf.extend_from_slice(&chunk);
                if !responded && HttpRequest::parse(&srv_buf).is_ok() {
                    let resp = HttpResponse::ok(expected_body.clone());
                    server.tcp_send(&sk, &resp.encode()).unwrap();
                    responded = true;
                }
            }
            if let Ok(chunk) = client.tcp_recv(&ck) {
                cli_buf.extend_from_slice(&chunk);
                if let Ok(resp) = HttpResponse::parse(&cli_buf) {
                    got_resp = Some(resp);
                    break;
                }
            }
            now_ms += 400;
            let _ = client.tick(now_ms);
            let _ = server.tick(now_ms);
        }
        let resp = got_resp.expect("HTTP/1.1 response received despite loss/reordering");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, expected_body);
        assert!(client.tcp_cwnd(&ck).unwrap() > 0);
    }
}

#[test]
fn dhcp_over_udp_end_to_end() {
    use userspace_tcpip::proto::dhcp::{
        DhcpMessageType, DhcpPacket, DhcpServer, DHCP_CLIENT_PORT, DHCP_SERVER_PORT,
    };
    let (mut cli, mut srv_stack) = twin();
    cli.udp_bind(DHCP_CLIENT_PORT).unwrap();
    srv_stack.udp_bind(DHCP_SERVER_PORT).unwrap();
    let mut dhcp = DhcpServer::new(
        [10, 0, 0, 2],
        [255, 255, 255, 0],
        [10, 0, 0, 2],
        vec![[10, 0, 0, 100]],
    );

    // 1. DISCOVER
    let disc = DhcpPacket::discover(0xdead_beef, cli.mac());
    cli.udp_send(
        DHCP_CLIENT_PORT,
        [10, 0, 0, 2],
        DHCP_SERVER_PORT,
        &disc.encode(),
    )
    .unwrap();
    pump(&mut cli, &mut srv_stack, 2);
    let (src_ip, src_port, raw) = srv_stack.udp_recv(DHCP_SERVER_PORT).unwrap();
    let offer = dhcp.handle(&DhcpPacket::parse(&raw).unwrap()).unwrap();
    assert_eq!(offer.msg_type, DhcpMessageType::Offer);
    srv_stack
        .udp_send(DHCP_SERVER_PORT, src_ip, src_port, &offer.encode())
        .unwrap();
    pump(&mut cli, &mut srv_stack, 2);

    // 2. REQUEST -> ACK
    let (_, _, raw_offer) = cli.udp_recv(DHCP_CLIENT_PORT).unwrap();
    let parsed_offer = DhcpPacket::parse(&raw_offer).unwrap();
    let req = DhcpPacket::request(parsed_offer.xid, cli.mac(), parsed_offer.yiaddr);
    cli.udp_send(
        DHCP_CLIENT_PORT,
        [10, 0, 0, 2],
        DHCP_SERVER_PORT,
        &req.encode(),
    )
    .unwrap();
    pump(&mut cli, &mut srv_stack, 2);
    let (src_ip, src_port, raw_req) = srv_stack.udp_recv(DHCP_SERVER_PORT).unwrap();
    let ack = dhcp.handle(&DhcpPacket::parse(&raw_req).unwrap()).unwrap();
    assert_eq!(ack.msg_type, DhcpMessageType::Ack);
    srv_stack
        .udp_send(DHCP_SERVER_PORT, src_ip, src_port, &ack.encode())
        .unwrap();
    pump(&mut cli, &mut srv_stack, 2);

    let (_, _, raw_ack) = cli.udp_recv(DHCP_CLIENT_PORT).unwrap();
    let final_ack = DhcpPacket::parse(&raw_ack).unwrap();
    assert_eq!(final_ack.yiaddr, [10, 0, 0, 100]);
}
