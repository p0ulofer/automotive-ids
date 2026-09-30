# Relatório Completo — Fases 1 e 2 do projeto someip-ids

Documento-geral do projeto **someip-ids**: reprodução local do ambiente do
artigo *"SOME/IP Intrusion Detection System Using Real-Time and Retroactive
Anomaly Detection"* (Koyama et al., IEEE VTC2022-Spring) e geração dos
datasets *Normal* que alimentarão o IDS (Fase 3).

- Detalhe técnico da Fase 2 (evidências completas): [`relatorio_fase2.md`](relatorio_fase2.md)
- Comandos: `./scripts/smoke_test.sh` (Fase 1) · `./scripts/gen_dataset.sh` (Fase 2)

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

## Parte III — O que leva ao mundo real (Fase 3)

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

## Parte IV — Estado atual e próximos passos

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
- [ ] Fase 3 — features + IDS sobre os três datasets

### Estado do git

- **Fase 1:** commitada (3 commits, pushados).
- **Fase 2:** commitada (`e633f9f` — apps de dataset, tools, configs,
  docs) + `e689dc7` (rename para `docs/documentacao.md`) — ambos pushados.
- **Working tree:** limpa; datasets `.pcap`/`.csv` ficam de fora do git
  (`.gitignore`), `MANIFEST.json` versionado.

### Comandos

```bash
./scripts/smoke_test.sh              # Fase 1: sobe e valida C1..C5
./scripts/smoke_test.sh --down       # termina e limpa (regras raw incluídas)

./scripts/gen_dataset.sh normal_nepc [--scale 0.05]   # Fase 2: dataset
python3 tools/validate_dataset.py datasets/normal/normal_nepc.pcap \
    --dataset normal_nepc --scale 1.0                 # validação à mão
```
