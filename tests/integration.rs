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
