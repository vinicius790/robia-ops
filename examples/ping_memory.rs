//! Ping ICMP entre dois stacks ligados por MemoryNic (sem root).

use userspace_tcpip::{paired_nics, Stack};

fn main() {
    let (nic_a, nic_b) = paired_nics([0x02, 0, 0, 0, 0, 0x01], [0x02, 0, 0, 0, 0, 0x02]);
    let mut a = Stack::new(Box::new(nic_a), [192, 168, 0, 1]);
    let mut b = Stack::new(Box::new(nic_b), [192, 168, 0, 2]);
    a.seed_arp([192, 168, 0, 2], [0x02, 0, 0, 0, 0, 0x02]);
    b.seed_arp([192, 168, 0, 1], [0x02, 0, 0, 0, 0, 0x01]);

    a.icmp_echo_request([192, 168, 0, 2], 1, 1, b"userspace-ping")
        .expect("send");
    for _ in 0..4 {
        let _ = a.poll();
        let _ = b.poll();
    }
    match a.icmp_pop_reply() {
        Some(r) => println!(
            "reply id={} seq={} payload={} bytes",
            r.identifier,
            r.sequence,
            r.payload.len()
        ),
        None => eprintln!("sem reply"),
    }
}
