# Stack TCP/IP no user-space — catálogo 3.2

Biblioteca Rust que implementa as camadas **Ethernet → ARP → IPv4 → ICMP → UDP → TCP (subset)** no espaço do usuário. O datapath padrão de testes é um **enlace virtual em memória** (`MemoryNic`): **zero root**, determinístico, adequado a CI. TUN real existe atrás da feature `tun` + `CAP_NET_ADMIN` — detalhes em [`CAPABILITIES.md`](./CAPABILITIES.md).

> Catálogo original pede handshake, controle de fluxo e retransmissão “na mão”, MVP ping + echo TCP via `tun0`, e versão completa com HTTP/1.1 + congestion control. **Este repo entrega o MVP pedagógico sólido** (ping ICMP, echo UDP, handshake + dados + FIN TCP) sobre NIC em memória, com caminho TUN documentado. **Não** inventa pps/RPS; **não** afirma Cubic/Reno completo nem download HTTP.

**Autor:** Geraliza Castlevania \<catalog@example.com\> · **Licença:** MIT

---

## O que este repo entrega

| Requisito do catálogo / brief | Status |
|-------------------------------|--------|
| Ethernet + ARP | ✅ parse/build + cache + reply |
| IPv4 + ICMP echo | ✅ ping request/reply |
| UDP | ✅ bind / send / recv + checksum |
| TCP subset SYN/ACK/dados | ✅ 3-way + payload + FIN lite |
| TUN/TAP **ou** link em memória | ✅ memória default; TUN via `--features tun` |
| Testes host sem root | ✅ `MemoryNic` — `cargo test` |
| ≥15 testes | ✅ 13 unit + 14 integração |
| Docs densos pt-BR | ✅ README + `docs/` + CAPABILITIES |
| MIT | ✅ |
| Sem pps inventados | ✅ |

**Fora do MVP:** fragmentação IP, RTO/fast retransmit, congestion control, HTTP/1.1, NAT/DHCP, TAP, loss injection.

---

## Arquitetura (visão rápida)

```
Aplicação (ping / UDP / TCP API)
        │
        ▼
┌─────────────────────────────────────────┐
│  Stack                                  │
│  ARP cache · ICMP · UDP binds · TCP FSM │
└───────────────┬─────────────────────────┘
                │ Ethernet frame  (L2)
                │ ou IPv4 puro    (L3 / TUN)
                ▼
┌──────────────────┐     ┌──────────────────┐
│  MemoryNic  A◄───┼─────┼───► MemoryNic  B │  ← testes sem root
└──────────────────┘     └──────────────────┘
           ou
┌──────────────────┐
│  TunDevice       │  ← feature tun + CAP_NET_ADMIN
└──────────────────┘
```

Detalhes: [`docs/ARQUITETURA.md`](docs/ARQUITETURA.md) · protocolos: [`docs/PROTOCOLOS.md`](docs/PROTOCOLOS.md) · privilégios: [`CAPABILITIES.md`](CAPABILITIES.md)

---

## Layout

```
src/
  lib.rs           # API pública
  checksum.rs      # RFC 1071 + pseudo-header
  error.rs
  proto/           # eth, arp, ipv4, icmp, udp, tcp
  netdev/          # MemoryNic + TunDevice (feature)
  tcp_conn.rs      # FSM TCP subset
  stack.rs         # orquestração L2–L4
examples/          # ping_memory, udp_echo, tcp_echo
tests/             # integração MemoryNic
docs/              # pt-BR
CAPABILITIES.md    # TUN / o que não faz
```

---

## Requisitos

- Rust estável (edição 2021; verificado com 1.85.x)
- **Sem** privilégios para build/test/examples padrão
- Linux + `CAP_NET_ADMIN` **somente** se for usar `--features tun`

## Build e testes

```bash
cd 03-02-userspace-tcpip
cargo test
cargo run --example ping_memory
cargo run --example udp_echo
cargo run --example tcp_echo
```

TUN (opcional, **não** coberto pela CI sem root):

```bash
cargo build --features tun
# veja CAPABILITIES.md para ip tuntap / rotas
```

---

## Uso mínimo (dois stacks no mesmo processo)

```rust
use userspace_tcpip::{paired_nics, Stack};

let (na, nb) = paired_nics([0x02,0,0,0,0,1], [0x02,0,0,0,0,2]);
let mut a = Stack::new(Box::new(na), [10,0,0,1]);
let mut b = Stack::new(Box::new(nb), [10,0,0,2]);
a.seed_arp([10,0,0,2], [0x02,0,0,0,0,2]);
b.seed_arp([10,0,0,1], [0x02,0,0,0,0,1]);

a.icmp_echo_request([10,0,0,2], 1, 1, b"hi").unwrap();
for _ in 0..4 { let _ = a.poll(); let _ = b.poll(); }
assert!(a.icmp_pop_reply().is_some());
```

---

## Transparência

Contadores de frames processados por `poll` existem só para controle de fluxo de teste. **Nenhum** número de pacotes/s, latência ou comparação com kernel/smoltcp é publicado neste README.

## Projeto como repositório

Este ZIP contém o projeto `03-02-userspace-tcpip`. Ao extrair, use a pasta `03-02-userspace-tcpip/`
como raiz de um repositório independente no GitHub. O tipo do projeto,
seu modo de uso e os requisitos de integração estão descritos nas seções
deste README. Nem todo projeto produz um programa executável.

## Recursos adicionados nesta expansão

O estimador RTO aceita `sample_ack` para ignorar ACKs ambíguos de retransmissões e `on_timeout` para backoff exponencial limitado a 60 segundos.
