//! Echo UDP entre dois stacks (MemoryNic).

use userspace_tcpip::{paired_nics, Stack};

fn main() {
    let (na, nb) = paired_nics([0x02, 0, 0, 0, 0, 0x0a], [0x02, 0, 0, 0, 0, 0x0b]);
    let mut a = Stack::new(Box::new(na), [10, 1, 0, 1]);
    let mut b = Stack::new(Box::new(nb), [10, 1, 0, 2]);
    a.seed_arp([10, 1, 0, 2], [0x02, 0, 0, 0, 0, 0x0b]);
    b.seed_arp([10, 1, 0, 1], [0x02, 0, 0, 0, 0, 0x0a]);
    a.udp_bind(1234).unwrap();
    b.udp_bind(7).unwrap();
    a.udp_send(1234, [10, 1, 0, 2], 7, b"echo-me").unwrap();
    for _ in 0..3 {
        let _ = a.poll();
        let _ = b.poll();
    }
    let (src, sport, payload) = b.udp_recv(7).unwrap();
    b.udp_send(7, src, sport, &payload).unwrap();
    for _ in 0..3 {
        let _ = a.poll();
        let _ = b.poll();
    }
    let (_, _, got) = a.udp_recv(1234).unwrap();
    println!("echoed: {}", String::from_utf8_lossy(&got));
}
