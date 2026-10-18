# R3 (plano) — atacante MITM com sessões SOME/IP-SD (Sec. IV-A)

> **Plano apenas — nada implementado.** Objetivo: fazer o `ecu6` estabelecer
> sessões SD com servidor e cliente como o atacante MITM da Sec. IV-A do artigo.

## 1. Estado atual (o que existe)

- `ecu6` = MITM na **net1** por ARP spoofing (`--poison 192.168.1.2:192.168.1.1` e
  `192.168.1.1:192.168.1.2`), relay em *userspace* (`ip_forward=0`), MAC6 = MAC do
  atacante, IP `192.168.1.50`.
- `tools/attacker/attacker.py` **não participa em SD**: o ramo
  `udp.sport==30490 and udp.dport==30490` só **encaminha** Offer/Subscribe/SubAck
  reais (e `--drop-sd-subscribe` descarta o Subscribe do cliente). Existe apenas o
  *parser* `sd_subscribed_services()` — não há *builder* de SD.
- `config/attacker/ids_attacker.json` já corre `vsomeipd` com `routingmanagerd`
  (id 0x1000) + `ids-attacker-client` (id **0x1002**), SD ligado (`ttl=3`,
  `cyclic_offer_delay=2000`), mas **sem app que faça offer/subscribe**.
- **Observado (D1b):** 0 pacotes SD com o MAC do atacante nos 11 ataques; o CS
  (nº de remetentes/serviço) não arma nos ataques NE/Res.

## 2. Objetivo (Sec. IV-A)

O atacante passa a ser um **participante SD de primeira classe**: subscreve os
*eventgroups* do servidor (SubscribeEventgroup) **e** oferece ao cliente os
serviços (OfferService/SubAck), de modo que as mensagens SOME/IP subsequentes
(requests/notifications/responses adulteradas) fiquem associadas à **identidade
do atacante** (IP/MAC/`session-id` próprios) — não a uma cópia do servidor.

Consequência para o IDS: o nº de remetentes distintos por serviço **cresce** →
o gatilho de CS (V-C 1) arma mesmo nos ataques NE/Res (hoje só `ARR-Req-a1`).

## 3. Mudanças propostas

### 3.1 `tools/attacker/attacker.py`

1. **Builders SD novos** (hoje só há parser): `build_sd_offer(entries, opts)`,
   `build_sd_subscribe(...)`, `build_sd_suback(...)`, `build_sd_stop_*` (TTL=0),
   com *entry* de 16 B (type, index, num_options, service, instance, major,
   TTL 3 B, minor/eventgroup) e *option* IPv4-Endpoint.
2. **Novo modo `--sd-role {relay,subscribe,offer,both}`**:
   - `subscribe`: emite SubscribeEventgroup **com src = MAC6 / IP 192.168.1.50**
     para os serviços alvo, **renovando** a cada `ttl/2` (~1,5 s) e
     `StopSubscribe` no shutdown;
   - `offer`: emite OfferService (src = MAC6) ao cliente, responde SubAck, e
     passa a **servir** os requests (em vez de os terminar/encaminhar);
   - `both`: as duas, como na Sec. IV-A.
3. **Duas vias de emissão** (escolher uma):
   - **(i) raw/scapy** (recomendada): construir os frames SD no próprio
     `attacker.py`, sem tocar no `vsomeipd` do atacante. Controla-se TTL e
     timing, e evita conflito com o `routingmanagerd` real.
   - **(ii) vsomeip nativo**: dar ao `ids-attacker-client` (0x1002) serviços/
     eventgroups em `ids_attacker.json` e usar `app_->subscribe/offer_service`.
     Mais "limpo" mas o SD sai do `vsomeipd` (timing/IDs difíceis de fixar) e
     pode colidir com a rota do servidor.
4. **Reescrita MITM (variante de topologia mínima, sem 2.ª iface):** em vez de
   gerar SD do zero, **reescrever** o Subscribe do cliente (src → MAC6/
   192.168.1.50) antes de o encaminhar ao servidor, e o Offer do servidor
   (src → MAC6) antes de o encaminhar ao cliente. O servidor vê um *subscriber*
   legítimo novo; o cliente vê um *offerer* legítimo novo. Custo baixo, mas
   **quebra a subscrição real do cliente** (é preciso manter o relay das
   notificações para o cliente não "notar").
5. `--drop-sd-subscribe` passa a coexistir: em `--sd-role subscribe`, em vez de
   **descartar** o Subscribe do cliente, **substitui-o** pelo do atacante.
6. **Label:** a regra da ferramenta **não muda** — `pcap_to_csv.py
   --attacker-mac <MAC6>` continua a dar `label=1` a `Ether.src==MAC6`. Só que
   agora passam a existir **pacotes SD com label=1**.

### 3.2 `ecu6` (compose / config / topologia)

- `config/attacker/ids_attacker.json`: se via (ii), declarar `services` /
  `eventgroups` / `clients` do atacante; se via (i) ou reescrita, **não mexer**.
- `docker-compose.attacker.yml`: estruturalmente igual. **Decisão de topologia**
  a tomar: o servidor está em **net2** (`192.168.2.4`). Para *subscrever ao
  servidor* o atacante precisa de chegar à net2. Opções:
  - (α) dar **2.ª iface** ao ecu6 na net2 (`192.168.2.50`) — simples, mas altera
    a topologia da Fig. 4 (o atacante passa a estar nas duas redes);
  - (β) **manter só net1** e usar a reescrita (§3.1-4): o Subscribe chega ao
    servidor "através" do MITM na net1. Recomendada (preserva a topologia).
- `scripts/gen_attack_dataset.sh`:
  - a **primagem ARP** (§3.3 de `attack_model.md`) e o **FDB estático** têm de
    cobrir os novos pares SD (atacante↔cliente, atacante↔servidor);
  - a regra raw anti-spoof (`2 7` com ecu6 up) mantém-se;
  - **gate novo**: `sd_from_attacker_mac > 0` (hoje seria 0).

### 3.3 Rótulo, dedup e volume (Fase 3)

- **Regra de rótulo (MAC):** inalterada na definição, mas o *conjunto* muda — os
  frames SD do atacante passam a `label=1`. A **dedup lógica** (§4.3) exclui SD
  (`svc=0xFFFF`) → **risco de dupla contagem** de SD (capturas em 6 pontos);
  é preciso uma chave própria para SD (5-tuple + entry-hash) ou manter a
  exclusão e contar SD só no ponto de origem.
- **Volume:** por serviço e por direção, ~`duração/(ttl/2)` renovacões
  (≈ 14 / 90 / 100 pacotes para runs de 21 / 135 / 154 s a ttl=3). Pequeno face
  aos actuais 44–241 SD, mas **é anomalia (`label=1`) nova** → muda o numerador
  dos gates ±10 % (Tabela III, §5.2 de `attack_datasets.md`).
- **Recalibração:** todos os 11 (a)-variantes passam a ter de **re-validar**
  razão (anomalia/total), contagem de anomalia e total, e possivelmente
  re-escalar `--terminate-*`/`--tamper-notify` para manter a razão-alvo. O
  conjunto (b)/(c) (não implementado) herda o mesmo mecanismo.

## 4. Impacto esperado

| aspeto | efeito |
|---|---|
| SD com MAC do atacante | 0 → dezenas por serviço (renovação + stop) |
| CS (remetentes/serviço) | `ARR-Req-a1` arma; **NE/Res passam a armar** (atacante é remetente próprio) |
| V-C 1+3 | deixa de ser sempre 0 — passa a haver candidatos a marcar por intervalo |
| 25 datasets (11 implementados) | volumes e razões deslocam-se; **gates da Fase 3 têm de ser recalibrados** |
| rótulo (MAC) | regra igual, mas SD passa a ter `label=1`; dedup de SD a rever |
| Fase 4 (features) | aparece `is_sd=1 & label=1` (hoje nunca acontece) e mais streams SD |
| Fase 5 | CS arma em mais datasets; o caminho retroativo V-C1+3 fica exercitado |

## 5. Riscos

1. **Subscrição real do cliente** quebra se o Subscribe for substituído e as
   notificações não forem relayadas → timings e volumes fora do alvo.
2. **Dedup de SD**: sem chave própria, dupla contagem de SD entre os 6 pontos
   de captura → gates de volume inflados.
3. **Conflito de `routingmanagerd`** se se usar vsomeip nativo no atacante
   (dois SD a anunciar/servir o mesmo serviço → corridas).
4. **Topologia**: a 2.ª iface (α) altera a Fig. 4 e o modelo de poisoning;
   a reescrita (β) exige cuidado com checksums/IP-ID e com o FDB.
5. **Recalibração em cascata** dos 11(+14 futuros) alvos da Tabela III, com
   margem ±10 %; risco de iteração longa (já foi necessário na Fase 3, §4.5).
6. **Realismo do dataset**: o atacante "legítimo" no SD torna o cenário mais
   fácil para o IDS (é esse o objetivo), mas afasta-se do que foi validado até
   aqui — todos os números de Fase 5 mudam.

## 6. Esforço estimado

| tarefa | estimativa |
|---|---|
| builders SD + modos + renovação/stop em `attacker.py` | 1–2 dias |
| compose/config/topologia (α ou β) + primagem/FDB | 0,5–1 dia |
| gate novo + recalibração dos 11 alvos + validador | 1–2 dias |
| regenerar 11 datasets e re-validar | ~1 dia (tempo de run) |
| re-correr Fase 4 (features) + Fase 5 (avaliação) | ~0,5 dia |
| **total** | **~4–6 dias** |

## 7. Alternativa mais barata (marcar, não implementar agora)

Se o objetivo for **só** exercitar o gatilho de CS sem refazer a topologia,
pode-se manter o SD real e injetar **apenas** `OfferService`/`SubscribeEventgroup`
do atacante (§3.1-2, via raw/scapy) sem reescrever os do cliente/servidor. É
mais rápido (~1–2 dias) mas não reproduz a Sec. IV-A (o atacante não fica com a
sessão de dados, só com a de SD) — decisão do utilizador.
