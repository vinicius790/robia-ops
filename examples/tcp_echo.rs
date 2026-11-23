//! Handshake TCP + echo de uma linha (MemoryNic).

use userspace_tcpip::{paired_nics, Stack, TcpState};

fn main() {
    let (na, nb) = paired_nics([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2]);
    let mut client = Stack::new(Box::new(na), [10, 2, 0, 1]);
    let mut server = Stack::new(Box::new(nb), [10, 2, 0, 2]);
    client.seed_arp([10, 2, 0, 2], [0x02, 0, 0, 0, 0, 2]);
    server.seed_arp([10, 2, 0, 1], [0x02, 0, 0, 0, 0, 1]);

    server.tcp_listen(9000).unwrap();
    let ck = client.tcp_connect(50000, [10, 2, 0, 2], 9000).unwrap();
    for _ in 0..10 {
        let _ = client.poll();
        let _ = server.poll();
    }
    assert_eq!(client.tcp_state(&ck), Some(TcpState::Established));
    let sk = server.tcp_accept().unwrap();

    client.tcp_send(&ck, b"hello-tcp").unwrap();
    for _ in 0..4 {
        let _ = client.poll();
        let _ = server.poll();
    }
    let got = server.tcp_recv(&sk).unwrap();
    server.tcp_send(&sk, &got).unwrap();
    for _ in 0..4 {
        let _ = client.poll();
        let _ = server.poll();
    }
    let echoed = client.tcp_recv(&ck).unwrap();
    println!("tcp echo: {}", String::from_utf8_lossy(&echoed));
}
