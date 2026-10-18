# Relatório Completo — Fases 1 a 5 do projeto someip-ids

Documento-geral do projeto **someip-ids**: reprodução local do ambiente e do
IDS do artigo *"SOME/IP Intrusion Detection System Using Real-Time and
Retroactive Anomaly Detection"* (Koyama et al., IEEE VTC2022-Spring) — geração
dos datasets *Normal* (Fase 2) e de *ataque* (Fase 3), extração das features de
transição de estado (Fase 4) e os algoritmos de deteção real-time/retroativo
(Fase 5).

- Passo a passo do zero ao resultado final: [`../README.md`](../README.md)
- Detalhe técnico da Fase 2 (evidências completas): [`relatorio_fase2.md`](relatorio_fase2.md)
- Fase 3: tabela aprovada [`attack_datasets.md`](attack_datasets.md) ·
  modelo, premissas e bugs [`attack_model.md`](attack_model.md)
- Fase 4 (features de transição, Tabela IV): [`feature_model.md`](feature_model.md)
- Fase 5 (IDS + avaliação): [`ids_model.md`](ids_model.md) ·
  relatório final [`relatorio_fase5.md`](relatorio_fase5.md) ·
  plano do R3 (não implementado) [`attacker_sd_plan.md`](attacker_sd_plan.md)
- Comandos: `./scripts/smoke_test.sh` (Fase 1) · `./scripts/gen_dataset.sh`
  (Fase 2) · `./scripts/gen_attack_dataset.sh` (Fase 3) ·
  `python3 tools/extract_features.py` (Fase 4) ·
  `python3 tools/evaluate_ids.py` (Fase 5)

---

## Parte I — Fase 1: Laboratório SOME/IP

### 1.1 Objetivo

Montar, em Docker, o ambiente descrito no artigo: **5 ECUs Linux** com
**vsomeip 3.7.6** (build do repositório oficial), duas sub-redes com
roteadores, captura `tcpdump` por ECU, e um smoke test que valida o tráfego
SOME/IP de ponta a ponta com `scapy`. Serviu também para **fixar os IDs,
portas e formatos de payload** reutilizados na Fase 2.

### 1.2 Entregáveis (commit `3ca4192` + melhorias `fca4200`, `e524796` — 2026-09-27)

| Ficheiro | Papel |
|---|---|
| `docker-compose.yml` | 5 ECUs, duas bridges (`net1`/`net2`), IPs fixos |
| `Dockerfile` | build do vsomeip 3.7.6 + apps C++ |
| `scripts/entrypoint.sh` | sysctls, rotas estáticas, rota multicast SD, TTL, `smcroute` |
| `scripts/smoke_test.sh` | orquestração + exceções `raw` + critérios C1..C5 |
| `config/ecu1/ids.json`, `config/ecu5/ids.json` | config vsomeip do cliente/servidor |
| `src/ids.hpp` | IDs/portas/payloads fixados (contrato entre fases) |
| `src/ids_server.cpp`, `src/ids_client.cpp` | apps SOME/IP de teste |
| `tools/verify_pcap.py` | validação C1..C5 dos pcaps (scapy) |
| `config/README.md`, `README.md` | decisões de configuração documentadas |

### 1.3 Topologia

```
ecu1 192.168.1.2 (cliente SOME/IP)
  └─ net1 192.168.1.0/24 ─ ecu2 192.168.1.1/192.168.2.1 (roteador + relay SD)
                              └─ net2 192.168.2.0/24
                                   ├─ ecu3 192.168.2.2 (caminho de volta)
                                   ├─ ecu4 192.168.2.3
                                   └─ ecu5 192.168.2.4 (servidor SOME/IP)

ida:  ecu1 → ecu2 → ecu5     volta: ecu5 → ecu3 → ecu2 → ecu1   (assimétrico)
```

### 1.4 Serviços e IDs (fixados em `src/ids.hpp` + `config/README.md`)

| Item | Valor |
|---|---|
| Serviço A — Request/Response | `0x1234.0001`, método ECHO `0x0001`, porta UDP **30509** |
| Serviço B — Notifications | `0x1235.0001`, evento `0x8001`, eventgroup `0x0001`, porta UDP **30510** |
| SOME/IP-SD | porta **30490**, multicast `224.224.224.245` |
| Apps | routing `0x1000`, cliente `0x1001` (ecu1), servidor `0x1002` (ecu5) |
| Payloads Fase 1 | REQUEST 16 B (seq BE) · RESPONSE 32 B · NOTIFICATION 12 B (contador) |

Os IDs são fictícios mas **contrato entre fases**: a Fase 2 reutiliza
`0x1234/ECHO` sem alterações e o `0x1235` com método novo (`0x0002`).

### 1.5 Problemas resolvidos na Fase 1

1. **Anti-spoofing do Docker ≥ 26 (aqui 29.6.1)** — o daemon insere no
   `raw PREROUTING` do host, por IP de container:
   `-A PREROUTING -d <IP>/32 ! -i <BRIDGE> -j DROP`. Com tráfego roteado
   entre sub-redes o frame chega pela bridge errada → pacotes descartados
   antes do conntrack (ping 100 % de perda).
   **Correção:** 2 regras `ACCEPT` espelhadas *antes* das DROP (pares
   `192.168.2.4`↔net2 e `192.168.1.2`↔net1), aplicadas/removidas pelo
   smoke test, com estado em `.state/host_raw_exceptions.json`, varredura de
   regras órfãs (a bridge muda de nome a cada recriação da rede) e
   verificação de **2 ACCEPT + 6 DROP**. Alternativa `bridge-nf-call-iptables=0`
   descartada (sysctl global, desliga o netfilter de todo o Docker).
2. **SD descartado por filtro de sub-rede** — com `netmask /24` o vsomeip
   descartava silenciosamente OFFERs multicast de outra sub-rede
   (`is_same_subnet_unlocked`). Solução: `netmask 255.255.0.0` nas configs
   (só afeta o filtro SD, não o roteamento).
3. **SD externo não arrancava** — `sd_route_set_` exige rota com `RTA_DST` +
   `RTA_OIF` para o grupo multicast; rota `default` não serve. Solução:
   `ip route replace 224.224.224.245/32 dev <eth>` no entrypoint (3c).
4. **TTL do multicast SD = 1** (vsomeip não seta `IP_MULTICAST_TTL`) → não
   sobrevivia ao salto de relay. Solução: `iptables -t mangle -PREROUTING
   -d 224.224.224.245 -j TTL --ttl-set 4` no ecu2 + `smcroute` para relay
   entre as duas redes.

### 1.6 Validação (smoke test — C1..C5)

Última execução registada (`logs/verify_pcap.log`):

```
ficheiro      pkts  SOME/IP   SD   tipos
ecu1.pcap       27       27   18   NOTIFICATION:3, REQUEST:3, RESPONSE:3
ecu2.pcap       54       54   36   (x2 por passar nas duas interfaces)
ecu3.pcap       29       29   17   NOTIFICATION:6, RESPONSE:6
ecu4.pcap       11       11   11   -
ecu5.pcap       27       27   18   NOTIFICATION:3, REQUEST:3, RESPONSE:3

[PASS] C1 existe trafego SOME/IP-SD (100 pacotes SD)
[PASS] C2 ecu1 recebeu SOME/IP-SD vindo de 192.168.2.4 (SD roteado via ecu2) (13)
[PASS] C3 SOME/IP REQUEST  192.168.1.2 -> 192.168.2.4
[PASS] C4 SOME/IP RESPONSE 192.168.2.4 -> 192.168.1.2
[PASS] C5 SOME/IP NOTIFICATION do evento 0x8001 do servico 0x1235
RESULTADO: OK (todas as 5 verificacoes passaram)
[ids_client] PASS responses=3 notifications=3
```

Observação importante registada já na Fase 1: **ecu2 conta cada pacote 2×**
(euma interface em cada bridge) e **ecu3 vê também a cópia de ida/volta** —
a semente dos achados de deduplicação da Fase 2.

---

## Parte II — Fase 2: Datasets Normal (RR, NEpc, NEc)

> Detalhe completo com todas as evidências em [`relatorio_fase2.md`](relatorio_fase2.md).

### 2.1 Objetivo e alvos do artigo

Gerar três datasets de tráfego **normal** (label 0), UDP SOME/IP, com
contagens próximas dos alvos do artigo:

| Dataset | Alvo | Conteúdo |
|---|---|---|
| `normal_rr` | 6 455 | ECHO Request/Response (ciclo 100 ms), eventgroup quase silencioso (notif ~30 s) |
| `normal_nepc` | 255 128 | + notificações periódicas (10 ms) + SetMode a cada 50 ciclos |
| `normal_nec` | 1 722 011 | + notificações *on-change*, SetMode a cada 100 ciclos |

Serviços adicionais aos da Fase 1: NEpc `0x1235`/**método `0x0002`** (porta
30510, ID reutilizado da Fase 1 com método novo) e NEc `0x1236`/**método
`0x0003`** (porta 30511). Todos partilham evento `0x8001`/eventgroup `0x0001`.
Documentação alinhada em `docs/payload_model.md` (secção 8 = tabela única
ID/porta + nota de reutilização da Fase 1).

### 2.2 Pipeline (`scripts/gen_dataset.sh`)

1. regressão `raw PREROUTING` **2 ACCEPT + 6 DROP** (antes do up, depois do
   up e depois do run — `die` se falhar);
2. `docker compose -f docker-compose.yml -f docker-compose.datasets.yml up -d --build`;
3. `tcpdump` **por interface** (nada de `-i any`; ecu2 eth0/eth1 separados;
   filtro: 30490/30509/30510/30511);
4. `ids_dataset_server` (ecu5) + `ids_dataset_client` (ecu1), logs em
   `/logs/ds/{server,client}.log`; flags por dataset (RR em paralelo em todos);
5. paragem limpa (apps terminam sozinhas ao fim de `--duration`);
6. `merge_captures.py` → dedup → `datasets/normal/<nome>.pcap`;
7. `pcap_to_csv.py` → `.csv`; `validate_dataset.py` → `MANIFEST.json`.

Suporta `--scale 0.05` para runs reduzidos (alvo efetivo = alvo × escala).

### 2.3 Achados técnicos principais (evidência em `relatorio_fase2.md` §3)

| # | Achado | Conclusão com evidência |
|---|---|---|
| 4 | **Datagramas UDP com várias SOME/IP concatenadas** (vsomeip) | parser antigo lia só a 1ª → falsa perda. Servidor enviou 998/998 = cliente recebeu 998/998. Corrigido em `pcap_to_csv.py` e `validate_dataset.py` (laço multi-mensagem). |
| 9 | **Duplicação em ecu3** | 9 458 pares TTL 64→63, 0 byte-idênticos, delta p50 9 µs — ecu3 é o router do *return path* e captura ingress+egress na mesma eth0. Causa identificada = artefato de roteamento; `pkt_key()` sem TTL colapsa corretamente (dups pós-merge = 0 em todos os runs). |
| 10 | **Breaks de session ID = reordenação, não perda** | 26/26 inversões de resposta já existiam na saída do ecu5 (a montante de ecu3); pares ECHO↔SetMode em endpoints UDP diferentes; delta p50 1 682 µs; requisições: 0 inversões; **perda real = 0**. |
| — | Contadores de session **globais por aplicação**, wraparound `0xFFFF→0x0001`, NG por RNG determinístico (`seed+svc+session`) | chave de continuidade `(src,dst,msgtype,is_sd)`. |

### 2.4 Gate de validação (metodologia)

**Gate = taxa observada + margem pequena** (nunca ordem de grandeza acima):

| Gate | Limite | Base |
|---|---|---|
| breaks de session (dados) | **≤ 1.14 %** | 0.639 % observado (NEpc reduced) + 0.5 p.p. |
| perda real (sessões ausentes) | **≤ 0.50 %** | 0.000 % observado + 0.5 p.p. |
| contagem vs alvo efetivo | ±10 % | alvo × `--scale` |
| truncados / dups pós-merge | = 0 | crítico |
| SD | informativo + cross-check por interface | 39/39 ofertas e 37/37 subscrições em todas as interfaces |

O relatório separa **reordenação** de **perda real** e reporta breaks por
message type (REQUEST/RESPONSE/NOTIFICATION).

**Escopo do gate (decisão registrada — item 1):** o limite de 1,14 % é
aplicado sobre a taxa **agregada** (todas as mensagens de dados somadas),
de propósito — a base 0,639 % do NEpc reduced também era agregada. A taxa
só em RESPOSTAS é estruturalmente mais alta em todos os runs (2,42 %
reduced; 1,605 % NEpc full; 1,654 % NEc full) por causa da reordenação
cross-service (endpoints UDP por serviço — benigna: 0 requisições
perdidas/reordenadas em todos os runs). Por isso **não existe hoje gate
separado por tipo para RESPONSE**: calibrar um limiar por-tipo exigiria a
taxa de resposta observada como base e mudaria a semântica do gate. Evidência
e raciocínio completos: `relatorio_fase2.md` §4 e §8.

### 2.5 Resultados

**Runs reduzidos (`--scale 0.05`)** — validação do método:

| | RR | NEpc | NEc |
|---|---|---|---|
| total / alvo | 323 / 323 (0.0 %) | 12 755 / 12 756 (0.0 %) | 83 924 / 86 101 (−2.5 %) |
| breaks | 0 | 81 (0.639 %) | 63 (0.075 %) |
| perda real | 0 | 0 | 0 |
| truncados / dups | 0 / 0 | 0 / 0 | 0 / 0 |
| resultado | **OK** | **OK** | **OK** |

**Runs FULL:**

| | `normal_rr` | `normal_nepc` | `normal_nec` |
|---|---|---|---|
| duração | 310 s | 1 280 s | 7 100 s |
| total / alvo | 6 656 / 6 455 (**+3.1 %**) | **255 084 / 255 128 (0.02 %)** | **1 653 598 / 1 722 011 (−4.0 %)** |
| breaks (rate) | 0 (0.000 %) | 1 047 (0.412 %) | 3 040 (0.185 %) |
| breakdown | 0/0/0 | resp 1.605 %, notif 0.010 %, req **0** | resp 1.654 %, notif 0.049 %, req **0** |
| perda real | 0 | 0 | **0** (`session_id_missing=1` = falso positivo do `0x0000` reservado — ver 2.7) |
| truncados / dups | 0 / 0 | 0 / 0 | 0 / 0 |
| NG vs p_ng | 4.9 % (0.05) | 2.0 % (0.02) | 1.0 % (0.01) |
| dups removidas | 26 794 | 1 145 158 | 7 973 753 |
| taxa / ficheiro | 21.5 pkt/s / 560 KB | 199.3 pkt/s / 22 MB | 233 pkt/s / **141 MB** |
| raw 2/6 antes/depois | ✅ | ✅ | ✅ (antes e após up + após run) |
| resultado | **PASS** | **PASS** | **PASS** |

### 2.6 Correções de código na Fase 2

- `g_opt = opt` (ambas as apps) · `<cstdlib>` · logs stdout redirecionados ·
  `pgrep/pkill -f '^ids_dataset_*'`
- contadores de diagnóstico (`g_requests_handled`, `g_responses_sent`,
  `g_setmode_applied`…) com dump opcional `DS_SESSION_LOG=1`
- **NEc SetMode ignorava `setmode_every_cycles`** (hardcoded 200 vs YAML 100)
  → passou a usar a flag; verificado em campo no run reduced (70 SetMode NEc
  e 70 NEpc = 1/5 s cada)
- build verificado com `g++ -std=c++20 -Wall -Wextra` na imagem: **0 warnings**

### 2.7 Verificações pós-entrega (itens 1–4 — checagens read-only)

- **Item 1:** escopo do gate agregado documentado (§2.4 acima e
  `relatorio_fase2.md` §4).
- **Item 2 — desvios de volume:** RR **+3,1 %** = volume de SD com
  renovações (316 dos 477 SD, renovação ~1,96 s com TTL 3 s; req/resp
  ficaram −30 por startup 0,62 s + timer +0,27 ms/ciclo); NEc **−4,0 %** =
  95,5 % de deriva determinística do `cv_.wait_for` (+0,45 ms/chamada →
  notificação 10,450 ms vs 10 000), 2,4 % de mensagens concatenadas,
  2,1 % de composição do alvo do artigo (não verificável). Ambos dentro de
  ±10 %; detalhe e tabela em `relatorio_fase2.md` §8.1.
- **Item 3 — a "1 sessão perdida" do NEc:** os logs do tcpdump **existem**
  (`logs/ds/*.pcap.log`) e mostram **0 dropped by kernel** nas 6 interfaces
  → captura regra-se; o `missing=1` é falso positivo do `0x0000` reservado
  no wrap com reordenação → **perda real = 0** (`relatorio_fase2.md` §8.2).
- **Item 4 — smoke test pós-Fase 2:** `./scripts/smoke_test.sh` →
  **C1..C5 PASS**, `ids_client` exit 0, `SMOKE TEST: SUCESSO` — a Fase 2 não
  quebrou a Fase 1 (`relatorio_fase2.md` §8.3).

---

## Parte III — O que leva ao mundo real

Do projeto, para uma rede veicular real, levam-se **5 coisas**:

1. **O IDS** (detetor + motor de inference);
2. **As features** — payload-agnosticas: continuidade de session ID, taxas por
   serviço, distribuição de message types, SD behavior (é o que
   generaliza entre synthético e real);
3. **A pipeline** — `merge_captures.py` / `pcap_to_csv.py` /
   `validate_dataset.py` funcionam sobre capturas reais (modo baseline em vez
   de `TARGETS`);
4. **O método de gate** — taxa observada + margem, breakdown por tipo,
   separação reordenação/perda (evita baseline sujo → falsos positivos);
5. **O conhecimento dos fenómenos** (relatorio_fase2.md §6): reordenação
   cross-service, duplicação em roteamento, concatenação SOME/IP em datagrama,
   wraparound de sessão, NG até 5 %, SD com relay/TTL — tudo isto **não é
   anomalia**.

**Não levam:** o dataset sintético como produto final (só pré-treino), a
topologia de 5 containers (só laboratório), o payload fictício.

**Para gerar baseline real:** captura *passiva* em bancada HIL/ECUs reais ou
tap de oficina (antes de SecOC/IPsec), cobrindo ciclos de operação (arranque,
condução, parado, sleep/wake, diagnóstico), anonimizar payloads, correr a
nossa pipeline em modo baseline; ataques (label 1) só injetados em bancada.

---

## Parte IV — Fase 3: Datasets de ataque (variante (a), MITM)

> Tabela aprovada: [`attack_datasets.md`](attack_datasets.md) ·
> modelo, premissas e bugs: [`attack_model.md`](attack_model.md) ·
> gerador: `./scripts/gen_attack_dataset.sh <id> [--scale N]`

### 4.1 Objetivo

Gerar os **25 datasets de anomalia** da Tabela II do artigo (label 1 =
tráfego de ataque) sobre as três bases normais da Fase 2, com volumes e
proporções da Tabela III em interpretação **(A)** (total da linha dividido
proporcionalmente entre os sets da linha). Gates de aceite: **±10 %** em
total, anomalia e razão, por set.

### 4.2 Escopo executado — 11 dos 25 sets

Executada a **variante (a) MITM** (Figs. 1a/2a/3a): `ARR-Req-a1`,
`ARR-Res-a1`, `ANEpc-a1..a8`, `ANEc-a1`. As restantes **14 sets** (variantes
(b) e (c)) exigem o atacante como *endpoint* SOME/IP (servidor/cliente falso
+ SD subscribe) e ficam **registadas como trabalho futuro** (§4.6).

### 4.3 Pipeline

- **ecu6** — container atacante (`docker-compose.attacker.yml` +
  `tools/attacker/attacker.py`): ARP poisoning dos pares ecu1↔ecu2 na net1;
  primitivas `--terminate-requests/-responses`, `--inject-requests`,
  `--tamper-notify`, `--fab-style`; stats em `logs/ds/*_attacker_stats.json`.
- **Premissas** (`attack_model.md` §3): FDB estático na net1; learning off na
  porta do atacante; primagem ARP `ip neigh replace … nud permanent`
  (sem ela `arp_accept=0` + corrida real-vs-atacante escapam o 1.º segundo);
  dedup lógica no merge; regra raw `2 ACCEPT + 7 DROP` com ecu6 up
  (`expected_raw()`); teardown com `ip neigh del` explícito.
- **Rótulo:** `label = 1 ⟺ Ether.src = MAC do atacante`
  (`pcap_to_csv.py --attacker-mac`); relay transparente mantém label 0.
- **Merge:** 6 capturas (ecu1, ecu2 eth0/eth1, ecu3, ecu4, ecu5) →
  `merge_captures.py --attacker-mac` com chave lógica SOME/IP
  `(5-tuple, svc, mtd, client, session, mtype)` e **preferência label1** em
  conflito de chave exata (correção da race label0/label1 — §4.5).
- **Validação:** `validate_dataset.py --attack` com `TARGETS_ATTACK`
  (25 sets) → `datasets/attack/MANIFEST.json`.

### 4.4 Resultados — 11/11 PASS (2026-10-04)

| | ARR-Req-a1 | ARR-Res-a1 | ANEpc-a1..a8 | ANEc-a1 |
|---|---|---|---|---|
| total / alvo | 3 272 / 3 291 (+0,6 %) | 3 310 / 3 291 (+0,6 %) | 4 111–4 133 / 4 077–4 078 (+0,8…+1,4 %) | 5 364 / 5 385 (+0,4 %) |
| anomalia / alvo | 738 / 772 (−4,4 %) | 745 / 773 (−3,6 %) | 1 686–1 744 / 1 732–1 733 (−2,7…+0,7 %) | 2 357 / 2 313 (+1,9 %) |
| razão (alvo) | 22,6 % (23,5 %) | 22,5 % (23,5 %) | 40,9–42,2 % (42,5 %) | 43,9 % (43,0 %) |
| truncados / dups | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |

- **Corpus:** 44 932 pacotes (alvo 44 585, **+0,78 %**); 17 598 anomalias
  (alvo 17 716, **−0,67 %**); razão global 39,17 % vs 39,74 % (−1,43 %).
- **Máx |Δ|** em qualquer gate: **4,4 %** (folga >2× face ao limite de 10 %).
- Integridade: `truncated=0` e `duplicate=0` em **todos**; máx.
  `session_id_break_rate` 0,290 % (gate 1,14 %); raw `2 7` em todos os runs.
- Artefactos: `datasets/attack/{id}.pcap|.csv` (fora do git, `.gitignore`) +
  `MANIFEST.json` (versionado).

> **Nota — datagramas vs. mensagens.** O `datasets/attack/MANIFEST.json` conta
> **datagramas** de rede (pacotes UDP observados na captura, via
> `validate_dataset.py`); já os CSVs (`datasets/*/*.csv` e, a jusante,
> `features/*.csv`) contam **mensagens** SOME/IP — uma linha por mensagem.
> Como um datagrama pode transportar mais de uma mensagem SOME/IP concatenada,
> os dois totais podem divergir ligeiramente (nos 11 sets atuais a relação é
> praticamente 1:1; ex.: `ARR-Req-a1` tem 3 276 datagramas no MANIFEST e 3 277
> linhas de dados no CSV). A pipeline nunca assume que os dois números são
> iguais.

### 4.5 Bugs corrigidos (detalhe em `attack_model.md` §4)

1. **Poison determinístico** — srp 2→0,5 s + primagem `neigh permanent`
   (`arp_accept=0`; corrida real-vs-atacante); teardown com `neigh del`
   (`flush all` não remove `permanent`).
2. **Dupla-contagem origem↔cópia** — a cópia re-emitida tem IP-ID/payload
   diferentes → chave lógica SOME/IP no merge (SD excluída).
3. **Race label0/label1** — a ordem dos ficheiros depende de eth0/eth1 ↔
   net1/net2 (alterna por recriação do container); em conflito de chave
   exata a vista **label1 substitui** a label0 (sem isto o ARR-Req-a1
   contava 46 anomalias em vez de 92).
4. **Calibração por taxa medida, não estimada** — SD cresce ~1,5 pkt/s (não
   é burst fixa) e o reduced de 5–6 s subestima taxas full em ~6–8 % (ramp de
   subscribe) → recalibrações finais: ARR-Req 135 s/t=0,29 · ANEpc 21 s/t=0,86
   · ANEc 23 s/t=0,54 (correções em `a4cec37` e `43c6671`).

### 4.6 Pendências da Fase 3

- **14 sets (b)/(c)** — exigem atacante como *endpoint* SOME/IP (servidor
  falso com notificações, cliente falso, SD subscribe) + decisão de rótulo
  para respostas a pedidos do atacante — **trabalho futuro** (escopo a decidir);
- bug de *wrap* de Session-ID (`missing=1` fantasma) mantido **documentado**
  sem ação (`relatorio_fase2.md` §8.2) — a revisitar na Fase 4.

---

## Parte V — Fase 4: Features de transição (Tabela IV)

> Modelo e decisões: [`feature_model.md`](feature_model.md) ·
> extração: `python3 tools/extract_features.py` ·
> validação: `python3 tools/validate_features.py` (commit `d892ab3`)

### 5.1 Objetivo

Reproduzir a **Tabela IV** do artigo: representar cada mensagem SOME/IP pela
*transição de estado* relativa à mensagem anterior **da mesma stream**, sem
treinar nenhum modelo. A transição é a unidade que o IDS da Fase 5 (Figs. 7/8)
consome.

### 5.2 O que se extrai

- **`stream_key`** = (Service ID, *message type*, remetente); o *remetente* é
  `src_ip` ou `src_ip`+`client_id` (identidades E2);
- **`dt_prev_req` / `dt_prev_res`** — intervalo desde o request/response
  anterior da mesma stream, mais as médias móveis de janela `W = 10`
  (`dt_prev_req_avg`, `dt_prev_res_avg`);
- **bins de discretização** `dt_prev_req_bin` / `dt_prev_res_bin` (3 níveis),
  obtidos por limiares `b1`/`b2` **aprendidos só nos datasets normais**;
- **`dp_prev_req` / `dp_prev_res`** (+ variantes `_l1`) — diferença de payload
  (estado de payload, E3/E3b; desligado por omissão);
- **`n_cs`** (# de Client-Subscribes) e **`os`** (campo opcional).

Os limiares são *anchors* `(min, mediana, max)` por `(svc|tipo)`, com
`b1 = (min+med)/2` e `b2 = (med+max)/2`. Por omissão são aprendidos com **100 %
dos normais** (Fase 4 original); com `--learn-holdout 0.3` são aprendidos **só
nos primeiros 70 %** de cada normal (experimento **E1b**, Parte VI).

### 5.3 Saídas e artefatos

- `features/<nome>.csv` — colunas originais + features + `label` inalterado;
- `features/thresholds.json` — limiares + metadados (`learn_holdout`, etc.);
- `features/MANIFEST.json` — contagens por dataset;
- todos **fora do git** (`.gitignore` inclui `features/*.csv`) e regeneráveis
  de forma determinística a partir dos CSVs de `datasets/`.

### 5.4 Decisão relevante

`os` é excluído das chaves `NOTIFICATION` de `0x1235`/`0x1236` (a variação de
`os` aí é ruído de campo, não anomalia). Detalhe em `feature_model.md`.

---

## Parte VI — Fase 5: IDS real-time + retroativo (Koyama §V-B/§V-C)

> Decisões, protocolos e resultados: [`ids_model.md`](ids_model.md) ·
> fecho consolidado: [`relatorio_fase5.md`](relatorio_fase5.md)
> (commits `edbd32c` + `bc80bc6`)

### 6.1 Algoritmos

- **Algoritmo 1 (real-time)** — `tools/ids_realtime.py`. Máquina de estados por
  `stream_key`: uma transição (tupla discretizada) vista no treino é normal;
  uma transição ausente do modelo (ou um *flag* de CS) dispara alerta. A tupla
  **não** inclui `n_cs`, que é verificado no fluxo separado da Fig. 8.
- **Algoritmo 2 (retroativo)** — `tools/ids_retroactive.py`. Agrupa os pacotes
  em *sessões* e marca a sessão inteira quando deteta a divergência de
  comportamento **V-C2** (o intervalo request/response da sessão desvia da
  média) e **V-C3** (novas sessões), com marcação retroativa a partir de uma
  janela `T` (no artigo, `T` = TTL do SD ≈ 3 s).

Orquestração/avaliação: `tools/evaluate_ids.py` (treina nos primeiros 70 %,
mede o FPR no 30 % retido dos normais e corre os 11 ataques) e
`tools/diagnose_ids.py` (breakdown por `stream_key`/categoria).

### 6.2 Protocolo de avaliação (congelado)

- **E1** — *holdout* temporal 70/30 dentro de cada normal;
- **E2** — identidade `ip`, `ip_client` ou `mac` (oráculo);
- **D2** — janela retroativa `T = 3 s` (**a priori** = TTL do SD medido);
  1/5/30 s são só sensibilidade;
- **E3/E3b** — estado de payload; **E4**, **D1/M1**, **R1/R2** — ablations;
- **R3** — atacante sem SD (CS arms) — **não implementado** (plano em
  `attacker_sd_plan.md`);
- **S1** — smoke do injetor de SD.

### 6.3 Configurações congeladas

| config | protocolo | `T` | diretório |
|---|---|---|---|
| `baseline_v1` | antigo (oráculo/MAC, *leaky*) — histórico | 3 s | `results/baseline_v1/` |
| `baseline_v2` | E1 + sem MAC, literal | TTL | `results/baseline_v2/` |
| **`baseline_v3`** | **E1 + sem MAC (principal)** | **3 s** | `results/baseline_v3/` |

`baseline_v3` é a configuração **principal**: o Algoritmo 1 é bit-idêntico ao
de `baseline_v2` (a janela só afeta o Algoritmo 2) e adota `T = 3 s` *a
priori*, sem escolher `T` para melhorar números.

### 6.4 Resultado principal (`baseline_v3`)

- `ip`: TPR 0,9477 · FPR (3 normais isolados) 0,0546 · 22 % tempo-real;
- `ip_client`: TPR 0,4866 · FPR 0,0030 · 14 % tempo-real;
- **0** de 11 padrões com TPR = 1 **e** FPR = 0 (o artigo reporta 5 de 9).

A maior parte dos verdadeiros-positivos vem por **contágio** (a marcação
retroativa da sessão arrasta pacotes normais rotulados como ataque), não por
deteção direta; a comparação com os alvos do artigo (TPR ≈ 0,91,
FPR ≈ 0,052) é feita com ressalvas em `relatorio_fase5.md`.

### 6.5 E1b — limiares reaprendidos só no treino (2026-10-17)

Variante isolada de `baseline_v3`: os limiares de discretização da Fase 4 são
reaprendidos **só nos primeiros 70 %** de cada normal (`--learn-holdout 0.3`),
em vez de em 100 %; tudo o resto é igual (`T = 3 s`, sem payload). A tabela
`baseline_v3` vs `E1b` (por pacote, TPR direto vs contágio, por categoria) está
em [`relatorio_fase5.md`](relatorio_fase5.md) §E1b; artefatos em
`results/exp_E1b/` (Control = limiares 100 %, E1b = 70 %) e `features_e1b/`.

---

## Parte VII — Estado atual e próximos passos

### Checklist

- [x] Fase 1 — laboratório + smoke test C1..C5 (3 commits, 2026-09-27)
- [x] Fase 2 itens 1–5 (warnings, ecu3, gate, docs+fix NEC, NEc reduced)
- [x] `normal_rr` full — **PASS** (6 656 / 6 455, +3.1 %)
- [x] `normal_nepc` full — **PASS** (255 084 / 255 128, 0.02 %)
- [x] `normal_nec` full — **PASS** (1 653 598 / 1 722 011, −4.0 %; perda 0 —
      `missing=1` é falso positivo do `0x0000`, ver 2.7)
- [x] Verificações pós-entrega (itens 1–4): gate agregado documentado,
      desvios explicados, perda NEc = 0, smoke C1..C5 PASS (exit 0)
- [x] Commit da Fase 2 (`e633f9f`) + rename `docs/documentacao.md`
      (`e689dc7`) — pushados para `origin/main`
- [x] Fase 3 — 11 datasets de ataque (variante (a), MITM) — **11/11 PASS**
      (2026-10-04, ver Parte IV)
- [ ] Fase 3 (pendente) — 14 sets das variantes (b)/(c) — exige atacante
      como endpoint SOME/IP (trabalho futuro, §4.6)
- [x] Fase 4 — features de transição (Tabela IV) dos datasets; limiares
      aprendidos nos normais; `feature_model.md` (commit `d892ab3`).
      (numeração: a "Fase 3 = features + IDS" dos relatórios antigos passou a
      ser a Fase 4; a Fase 3 são os datasets de ataque)
- [x] Fase 5 — IDS (Algoritmos 1 e 2): pipeline + avaliação E1..E4, D1/M1, D2,
      R1/R2, E3/E3b, S1; config principal `baseline_v3`; `ids_model.md` +
      `relatorio_fase5.md` (commit `edbd32c`)
- [x] Fase 5 — **E1b**: limiares de discretização reaprendidos só no treino
      (70 %); `relatorio_fase5.md` §E1b (Parte VI §6.5)
- [ ] Fase 5 (pendente) — **R3** (atacante sem SD / CS arms) e os 14 sets
      (b)/(c): decisão de escopo do utilizador (`attacker_sd_plan.md`)

### Estado do git

- **Fase 1:** commitada (3 commits, pushados).
- **Fase 2:** commitada (`e633f9f` — apps de dataset, tools, configs,
  docs) + `e689dc7` (rename para `docs/documentacao.md`) — ambos pushados.
- **Fase 3:** 6 commits (`1b011b3` pipeline · `32b234c` docs+calibrações ·
  `a4cec37`/`43c6671` recalibrações · `f917551` MANIFEST · `a6142b7` infra)
  — **pushados para `origin/main`** (`a6142b7`, verificado por
  `git ls-remote`).
- **Fase 4:** commitada (`d892ab3` — `extract_features.py`,
  `validate_features.py`, `feature_model.md`, limiares/MANIFEST) — pushada.
- **Fase 5:** commitada (`edbd32c` — IDS + avaliação + docs) e `bc80bc6`
  (`.gitignore` do PDF do artigo) — **pushadas para `origin/main`**
  (`main == origin/main == bc80bc6`, fast-forward, sem rewrite de história).
- **Working tree:** o `E1b` (Parte VI §6.5) acrescenta `--learn-holdout` a
  `extract_features.py`, o comparador `experiment_e1b_report.py` e
  `results/exp_E1b/` — commit **local**, sem push. `datasets/**.pcap|.csv` e
  `features/*.csv` ficam de fora do git (`.gitignore`), `MANIFEST.json` é
  versionado; o PDF do artigo fica de fora (untracked, ignorado).

### Comandos

```bash
./scripts/smoke_test.sh              # Fase 1: sobe e valida C1..C5
./scripts/smoke_test.sh --down       # termina e limpa (regras raw incluídas)

./scripts/gen_dataset.sh normal_nepc [--scale 0.05]   # Fase 2: dataset
python3 tools/validate_dataset.py datasets/normal/normal_nepc.pcap \
    --dataset normal_nepc --scale 1.0                 # validação à mão

./scripts/gen_attack_dataset.sh ANEc-a1 [--scale 0.10]  # Fase 3: ataque
python3 tools/validate_dataset.py --attack --dataset ANEc-a1 --scale 1.0 \
    --attacker-mac <MAC_do_ecu6> datasets/attack/ANEc-a1.pcap   # à mão

python3 tools/extract_features.py                        # Fase 4: features
python3 tools/extract_features.py --learn-holdout 0.3    # Fase 4: E1b (70 %)
python3 tools/validate_features.py                       # Fase 4: validação

python3 tools/evaluate_ids.py \                          # Fase 5: avaliação
    --features-dir features --identity ip --holdout 0.3 \
    --retro-window 3 --results-dir results/baseline_v3/ip \
    --out results/baseline_v3/ip/report.json
```
