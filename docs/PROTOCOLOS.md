# Protocolos — referência rápida (pt-BR)

Valores e layouts usados neste MVP. Não substitui os RFCs; aponta o subconjunto implementado.

## Ethernet II

| Campo | Bytes | Notas |
|-------|-------|-------|
| DST MAC | 6 | `ff:ff:ff:ff:ff:ff` = broadcast |
| SRC MAC | 6 | |
| EtherType | 2 | `0x0800` IPv4, `0x0806` ARP |
| Payload | … | sem FCS neste stack (o NIC virtual não calcula CRC) |

## ARP (Ethernet/IPv4)

28 bytes fixos: HTYPE=1, PTYPE=0x0800, HLEN=6, PLEN=4, OPER=1|2, sender/target HA/PA.

## IPv4

Cabeçalho mínimo 20 bytes (`IHL=5`). `flags_frag` default `0x4000` (DF). Checksum só do header. Payload cortado por `total_length` quando coerente.

Protocolos despachados: 1 ICMP, 6 TCP, 17 UDP; demais ignorados.

## ICMP echo

Type 8 request / 0 reply, code 0, identifier + sequence + payload opcional. Checksum do datagrama ICMP inteiro.

## UDP

Header 8 bytes. Length = 8 + payload. Checksum com pseudo-header IPv4; se o resultado da conta for 0, transmite-se `0xFFFF` (RFC 768). No RX, checksum 0 é aceito (opcional em IPv4).

## TCP subset

Header mínimo 20 bytes, sem opções (`data_offset=5`).

Flags usadas: SYN, ACK, PSH, FIN (RST parseado mas não gerado ativamente no caminho feliz).

Checksum obrigatório com pseudo-header.

Contagem de sequência: payload + 1 se SYN + 1 se FIN (`seq_consumed`).

### O que o RFC tem e este MVP não

- Opções (MSS, Window Scale, SACK permitted)
- Retransmissão por RTO / fast retransmit
- Congestion avoidance (Reno, Cubic, …)
- Receiver window efetiva além do campo fixo 65535
- TIME-WAIT de 2MSL real (estado existe; sem timer)

## Pseudo-header IPv4 (UDP/TCP)

```
src IP (4) + dst IP (4) + zero (1) + protocol (1) + length L4 (2)
```

Somado em ones’ complement junto com o segmento L4 (campo checksum zerado na emissão).

## Vetores de teste

Unidade: checksum vazio → `0xFFFF`; padding de byte ímpar; roundtrip eth/arp/ip/icmp/udp/tcp; detecção de checksum IP corrompido.

Integração: ping, ARP learning, UDP echo, handshake, transferência, FIN, ethertype desconhecido, bind duplicado, WouldBlock.
