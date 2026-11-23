# CAPABILITIES.md — cobertura completa de protocolo e datapaths

Documento honesto sobre privilégios e cobertura de protocolo. **Não** publique números de pps/throughput inventados; meça no seu hardware se precisar.

## Matriz de datapath

| Datapath | Status | Precisa o quê? | Usado nos testes CI/host? |
|----------|--------|----------------|---------------------------|
| `MemoryNic` (enlace virtual em processo) | ✓ default | nada (user normal) | **sim** — todos os `cargo test` |
| `FaultyNic` (perda/reordenação/duplicação determinística) | ✓ default | nada (user normal) | **sim** — testes de confiabilidade TCP/HTTP |
| TUN `IFF_TUN \| IFF_NO_PI` (`feature = "tun"`) | ✓ código em `netdev/tun.rs` | `CAP_NET_ADMIN` **ou** root; `/dev/net/tun` | **não** (exige Linux + privilégio) |

## Cobertura de protocolo (Completa — zero root)

| Camada | Implementado e verificado por testes |
|--------|--------------------------------------|
| Ethernet II + VLAN 802.1Q | parse/build, broadcast, tagging/untagging IEEE 802.1Q (`TPID 0x8100`, PCP/DEI/VID) e filtragem por VID |
| ARP | request/reply IPv4, cache dinâmico com **aging/TTL** (`tick`), entradas estáticas e **Proxy ARP** |
| IPv4 | validação estrita de header/total_length/checksum, **fragmentação por MTU** e **reassembly fora de ordem** com timeout, **tabela de roteamento** (longest-prefix match + default gateway) |
| ICMP | Echo Request/Reply (8/0), **Destination Unreachable / Port Unreachable** (3/3), **Time Exceeded** (11/0 TTL e 11/1 reassembly) |
| UDP | bind/send/recv + validação segura de length/checksum, **sockets conectados** (`udp_connect`) e **multicast** (`224.0.0.0/4`) |
| TCP | 3-way handshake, **opções MSS / WScale / SACK**, **reassembly fora de ordem (OOO)**, **geração/consumo de SACK**, **janela deslizante dinâmica**, **RTO Jacobson/Karels + regra de Karn + backoff**, **Fast Retransmit (3 dup-ACKs)**, **controle de congestionamento Reno e Cubic**, RST, FIN+payload, simultaneous open/close (`Closing`) e expiração `TIME_WAIT` |
| Serviços L7/Rede | **HTTP/1.1** client/server sobre o nosso TCP (`src/http.rs`, `examples/http_over_tcp.rs`), **DHCPv4** DORA (`src/proto/dhcp.rs`) e **NAT44/NAPT** stateful (`src/nat.rs`) |

## Notas de privilégio

- TUN real (`--features tun`) depende de kernel Linux + `/dev/net/tun` + `CAP_NET_ADMIN`.
- Todos os testes automatizados rodam **100% sem root** via `MemoryNic` e `FaultyNic` com PRNG determinístico.
- **Sem claims de performance inventados** no README nem aqui.
