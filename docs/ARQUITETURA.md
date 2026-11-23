# Arquitetura — userspace-tcpip (catálogo 3.2)

## Objetivo

Expor, em código legível, o caminho de um datagrama desde o buffer da aplicação até o bit no “fio” (aqui: canal em memória ou TUN), passando por encapsulamento L2/L3/L4 e pela máquina de estados TCP mínima.

## Componentes

### `NetDevice`

Trait com `send` / `recv` não-bloqueante (`Error::WouldBlock` se vazio) e `mac()`.

- **`MemoryNic`**: par criado por `paired_nics`. Cada `send` enfileira no `mpsc` do peer. Ideal para testes e examples.
- **`TunDevice`** (`feature = "tun"`): lê/escreve IPv4 cru em `/dev/net/tun`. O `Stack` entra em modo L3 (`with_l3_device`) e **pula** Ethernet/ARP.

### `Stack`

Estado por interface lógica:

| Campo | Papel |
|-------|--------|
| `ip` / `mac` | Identidade L3/L2 |
| `arp_cache` | IP → MAC aprendido (request/reply ou `seed_arp`) |
| `udp_binds` | porta → fila de datagramas |
| `tcp_conns` | mapa `FourTuple` → `TcpConn` (listeners com remote=0) |
| `tcp_backlog` | chaves prontas/quase prontas para `accept` |
| `icmp_replies` | echoes respondidos (lado do pingador) |

`poll()` drena o NIC, despacha por EtherType/Protocol, e chama `flush_tcp()` para emitir SYN-ACK/ACK/FIN pendentes gerados pela FSM.

### FSM TCP (`tcp_conn.rs`)

Estados usados: `Listen`, `SynSent`, `SynRcvd`, `Established`, `FinWait1/2`, `CloseWait`, `LastAck`, `TimeWait`, `Closed`.

Fluxo ativo:

1. `tcp_connect` → `SynSent` + segmento SYN enfileirado  
2. peer `Listen` recebe SYN → cria filho `SynRcvd` + SYN-ACK  
3. cliente recebe SYN+ACK → `Established` + ACK  
4. filho vê ACK → `Established` → `tcp_accept` devolve a tupla  

Dados: apenas segmentos **em ordem** (`seq == rcv_nxt`); ACK imediato; `PSH|ACK` no envio de aplicação. **Sem** retransmissão nem congestion window.

## Encapsulamento

```
UDP/TCP/ICMP payload
    → header L4 (+ checksum com pseudo-header IPv4 quando couber)
    → IPv4 (IHL=5, DF, TTL=64, checksum header)
    → [Ethernet II + EtherType]   // se !l3
    → NetDevice::send
```

Checksum: módulo `checksum` (ones’ complement RFC 1071). IPv4 e ICMP validam no parse; UDP aceita checksum 0 (opcional em IPv4) ou valor correto; TCP exige checksum válido.

## ARP

Em L2, `send_ip` sem entrada no cache:

1. emite `ARP Request` broadcast;
2. retorna `Error::ArpUnresolved`;
3. o peer, se for o alvo, responde `Reply` e ambos aprendem.

Testes determinísticos usam `seed_arp` nos dois lados para evitar a corrida. O teste `arp_request_learns_and_replies` exercita o caminho completo sem seed.

## Modelo de execução

API **síncrona e single-threaded** por stack: a aplicação alterna `poll` nos peers (ou num loop único). Não há runtime async interno — Tokio não é dependência. Isso simplifica o raciocínio sobre ordem de segmentos nos testes.

## Limites conscientes

- Um IP por `Stack` (sem aliasing).
- Sem fila de reordenação TCP; loss no cabo virtual = 0.
- TUN não configura endereço/rota: isso é do operador (`ip addr`, `ip route`).
- Não há métricas de performance exportadas.

## Relação com netcode de jogo

O catálogo cita esta peça como base para entender netcode. O caminho mental é o mesmo de um tick de transporte: serializar → confiabilidade (aqui: TCP didático) → IP → enlace. Para jogos, o próximo passo natural no catálogo é o item de netcode (snapshot/input), não congestion control de datacenter.
