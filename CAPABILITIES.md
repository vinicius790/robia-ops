# CAPABILITIES.md — o que este stack faz e o que **não** faz

Documento honesto sobre privilégios e cobertura de protocolo. **Não** publique números de pps/throughput inventados; meça no seu hardware se precisar.

## Matriz de datapath

| Datapath | Status | Precisa o quê? | Usado nos testes CI/host? |
|----------|--------|----------------|---------------------------|
| `MemoryNic` (enlace virtual em processo) | ✓ default | nada (user normal) | **sim** — todos os `cargo test` |
| TUN `IFF_TUN \| IFF_NO_PI` (`feature = "tun"`) | ✓ código em `netdev/tun.rs` | `CAP_NET_ADMIN` **ou** root; `/dev/net/tun`; módulo `tun` | **não** |
| TAP (Ethernet no kernel) | ✗ não implementado | CAP_NET_ADMIN | — |
| AF_PACKET / RAW socket | ✗ | CAP_NET_RAW | — |
| netmap / DPDK / XDP | ✗ | fora do escopo | — |

## O que funciona **sem root** neste repositório

1. `paired_nics(mac_a, mac_b)` cria um cabo virtual (dois `mpsc`).
2. Dois `Stack::new` trocam Ethernet/ARP/IPv4/ICMP/UDP/TCP.
3. `cargo test` e os examples `*_memory` / `udp_echo` / `tcp_echo` **não** abrem TUN.

Isso cobre o MVP pedagógico do catálogo (camadas + handshake + echo) sem privilegio.

## TUN real (feature `tun`)

```bash
# build
cargo build --features tun --release

# no host (exemplo — ajuste nomes/IPs):
sudo ip tuntap add dev ustun0 mode tun user "$USER"
sudo ip addr add 10.0.0.1/24 dev ustun0
sudo ip link set ustun0 up
# aí um binário seu chama TunDevice::open("ustun0") + Stack::with_l3_device(...)
```

Requisitos típicos:

| Item | Detalhe |
|------|---------|
| Kernel | Linux com `/dev/net/tun` (CONFIG_TUN) |
| Capacidade | `CAP_NET_ADMIN` no processo **ou** root no `ip tuntap` / `TUNSETIFF` |
| Framing | L3 puro (IP sem Ethernet) — use `Stack::with_l3_device` |
| ARP | **não** se aplica no TUN; o peer é a rota do kernel |
| Non-block | `TunDevice::open` seta `O_NONBLOCK`; `recv` → `WouldBlock` se vazio |

Sem a capability, `TunDevice::open` retorna `Error::Device` com mensagem apontando para este arquivo.

## Cobertura de protocolo (MVP)

| Camada | Implementado | Não implementado (explícito) |
|--------|--------------|------------------------------|
| Ethernet II | parse/build, broadcast | VLAN 802.1Q, LLC/SNAP |
| ARP | request/reply IPv4, cache | timeout/aging, proxy ARP |
| IPv4 | header 20 B, DF, TTL=64, checksum | opções, fragmentação/reassembly, roteamento multi-hop |
| ICMP | echo request/reply | dest-unreach, time-exceeded, etc. |
| UDP | send/recv + checksum IPv4 | conectado, multicast |
| TCP | 3-way handshake, dados + ACK, FIN lite | janela deslizante completa, RTO/retransmit, SACK, congestion (Reno/Cubic), MSS options, simultaneous open robusto |

## Avisos

- Este **não** é smoltcp/lwIP completo nem afirma conformidade de stress em produção.
- TCP é didático: segmentos em ordem, sem perda injetada no NIC em memória (o cabo virtual não dropa).
- TUN + kernel stack no “outro lado” exige cuidado com rotas/firewall — fora do escopo dos testes automatizados.
- **Sem claims de performance** no README nem aqui.

## Como elevar (fora do MVP)

Injetor de loss/reordenação no `MemoryNic`, RTO + fast retransmit, Cubic lite, cliente HTTP/1.1 sobre o TCP próprio, NAT/DHCP — alinhado à “versão completa” do catálogo 3.2.
