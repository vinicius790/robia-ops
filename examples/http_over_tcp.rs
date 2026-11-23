//! HTTP/1.1 GET sobre o nosso próprio TCP confiável em um enlace com perdas e reordenação (`FaultyNic`).

use userspace_tcpip::{
    paired_faulty_nics, CongestionAlgo, HttpRequest, HttpResponse, LinkImpairment, Stack, TcpState,
};

fn main() {
    let imp = LinkImpairment {
        loss_pct: 15,
        reorder_pct: 25,
        duplicate_pct: 10,
        seed: 2026,
    };
    let (na, nb) = paired_faulty_nics([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2], imp, imp);
    let mut client = Stack::new(Box::new(na), [10, 10, 0, 1]);
    let mut server = Stack::new(Box::new(nb), [10, 10, 0, 2]);
    client.seed_arp([10, 10, 0, 2], [0x02, 0, 0, 0, 0, 2]);
    server.seed_arp([10, 10, 0, 1], [0x02, 0, 0, 0, 0, 1]);

    server.tcp_listen(80).unwrap();
    let ck = client.tcp_connect(51000, [10, 10, 0, 2], 80).unwrap();
    client
        .tcp_set_congestion_algo(&ck, CongestionAlgo::Cubic)
        .unwrap();

    let mut now_ms = 0u64;
    let mut accepted = None;
    for _ in 0..40 {
        let _ = client.poll();
        let _ = server.poll();
        if accepted.is_none() {
            if let Ok(sk) = server.tcp_accept() {
                accepted = Some(sk);
            }
        }
        if client.tcp_state(&ck) == Some(TcpState::Established) && accepted.is_some() {
            break;
        }
        now_ms += 400;
        let _ = client.tick(now_ms);
        let _ = server.tick(now_ms);
    }
    let sk = accepted.expect("server accepted");
    let req = HttpRequest::get("userspace.local", "/status");
    client.tcp_send(&ck, &req.encode()).unwrap();

    let mut srv_buf = Vec::new();
    let mut cli_buf = Vec::new();
    let mut responded = false;
    for _ in 0..60 {
        let _ = client.poll();
        let _ = server.poll();
        if let Ok(chunk) = server.tcp_recv(&sk) {
            srv_buf.extend_from_slice(&chunk);
            if !responded && HttpRequest::parse(&srv_buf).is_ok() {
                let resp = HttpResponse::ok(b"HTTP/1.1 OK over userspace-tcpip!".to_vec());
                server.tcp_send(&sk, &resp.encode()).unwrap();
                responded = true;
            }
        }
        if let Ok(chunk) = client.tcp_recv(&ck) {
            cli_buf.extend_from_slice(&chunk);
            if let Ok(resp) = HttpResponse::parse(&cli_buf) {
                println!(
                    "HTTP {} {} | body='{}' | retransmissions={}",
                    resp.status,
                    resp.reason,
                    String::from_utf8_lossy(&resp.body),
                    client.tcp_retransmissions(&ck).unwrap_or(0)
                );
                return;
            }
        }
        now_ms += 400;
        let _ = client.tick(now_ms);
        let _ = server.tick(now_ms);
    }
    panic!("HTTP/1.1 transfer did not complete");
}
