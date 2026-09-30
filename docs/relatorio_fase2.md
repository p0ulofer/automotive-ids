# Relatório Fase 2 — Geração e Validação dos Datasets Normal (someip-ids)

Relatório do trabalho realizado na Fase 2 do projeto **someip-ids**: geração,
correção e validação rigorosa dos três datasets *Normal* (RR, NEpc, NEc)
previstos no artigo de referência (Koyama et al., VTC2022-Spring), que servirão
de base ao IDS a desenvolver na Fase 3.

---

## 1. Objetivo

Gerar três datasets de tráfego SOME/IP **normal** (label 0) em ambiente
emulado, com contagens próximas dos alvos do artigo e validação **evidência-
based** (nada aceito "por padrão"):

| Dataset | Alvo (artigo) | Composição |
|---|---|---|
| `normal_rr` | 6 455 pacotes | Serviço ECHO Request/Response, eventgroup quase silencioso |
| `normal_nepc` | 255 128 pacotes | + notificações periódicas + SetMode |
| `normal_nec` | 1 722 011 pacotes | + notificações *on-change* |

Cada run gera `datasets/normal/<nome>.pcap`, `.csv` e atualiza
`datasets/normal/MANIFEST.json`.

---

## 2. Ambiente

- **Imagem:** vsomeip 3.7.6, 5 ECUs em containers Docker (`ecu1`..`ecu5`)
- **Topologia** (duas redes + roteamento):

```
net1 192.168.1.0/24          net2 192.168.2.0/24
ecu1 192.168.1.2 (cliente)   ecu5 192.168.2.4 (servidor)
      |                             ^
      v                             |
ecu2 192.168.1.1 (router net1/net2) |
      |                             |
      +--------> ecu3 192.168.2.2 <--+   (ecu5 rota 192.168.1.0/24 via ecu3)
ecu4 192.168.2.3 (observador mcast)
```

- **Forward path:** ecu1 → ecu2 → ecu5. **Return path:** ecu5 → ecu3 → ecu2 → ecu1
- **Serviços** (UDP, `config/ecu5/ids_dataset.json`):

| Dataset | Serviço | Método | Evento | Porta |
|---|---|---|---|---|
| Normal_RR | 0x1234 | ECHO 0x0001 | — | 30509 |
| Normal_NEpc | 0x1235 (ID reutilizado da Fase 1) | SetMode 0x0002 | 0x8001 | 30510 |
| Normal_NEc | 0x1236 | SetMode 0x0003 | 0x8001 | 30511 |
| SD (todos) | 0xFFFF | — | — | 30490, mcast 224.224.224.245 |

- **Cadências** (`config/datasets/*.yaml`): RR cycle 100 ms / notify 500 ms;
  NEpc cycle 20 ms / notify 10 ms / SetMode a cada 50 ciclos;
  NEc cycle 50 ms / notify 10 ms / SetMode a cada 100 ciclos.
- **Regressão raw** (perimetro anti-ataque Fase 1): `iptables -t raw PREROUTING`
  deve ter exatamente **2 ACCEPT + 6 DROP** com o ambiente em baixo; o script
  verifica antes, depois do `up` e depois do run (`die` se falhar).

---

## 3. Correções e achados técnicos

### 3.1 Achado 4 — Datagramas UDP com VÁRIAS mensagens SOME/IP (bug do parser)

**Sintoma:** SetMode aparecia com "missing responses" em runs-mini (1504
requests vs 1503 responses).

**Causa:** o vsomeip **concatena várias mensagens SOME/IP num único datagrama**
UDP (ex.: notificação 32 B + resposta 20 B = 52 B). O parser antigo lia apenas
a primeira mensagem e descartava o resto — falsa perda.

**Evidência:** server enviou 998/998, client recebeu 998/998, o wire tinha os
998 — **zero perda de rede**.

**Correção:** laço multi-mensagem em `tools/pcap_to_csv.py` **e**
`tools/validate_dataset.py`:

```python
while pos + 8 <= len(raw):
    length = struct.unpack(">I", raw[pos+4:pos+8])[0]  # length do header
    msg_size = 8 + length                               # tamanho TOTAL
    if length < 8 or pos + msg_size > len(raw): break  # padding / truncado
    ...
```

### 3.2 Achado 9 — Duplicação de pacotes em ecu3 (artefato de roteamento)

**Sintoma:** `ecu3_eth0.pcap` tinha ~2× os pacotes das outras interfaces.

**Evidência coletada:**

| Métrica | Valor |
|---|---|
| pacotes capturados | 18 956 |
| chaves únicas (5-tuple + IP ID + sha256 payload) | 9 498 |
| chaves com exatamente 2 ocorrências | 9 458 |
| ocorrências únicas | 40 (todas SD) |
| pares **byte-idênticos** | **0** — diferem APENAS no offset IP 8 (TTL 64→63) e 10-11 (checksum IP) |
| delta temporal entre cópias | p50 = 9 µs, p95 = 21 µs, máx = 334 µs; **0** fora de ±5 ms |
| tamanhos | 48 B × 3183, 60 B × 6201, 72 B × 4 |

**Causa (explicada pela topologia):** ecu3 é o primeiro salto do *return path*
(ecu5 → ecu3 → ecu2). A sua eth0 captura **duas cópias do mesmo datagrama**:
a de entrada (TTL 64, vinda de ecu5) e a de saída (TTL 63, encaminhada para
ecu2 — mesma sub-rede). TTLs observados em ecu3: `{64: 9458, 63: 9458, 1: 39,
3: 1}`. Requisições (client → server) nunca atravessam ecu3 (excepto SD).

**Não é colisão da chave de dedup:** `pkt_key()` do `merge_captures.py`
ignora TTL/checksum de propósito → as duas cópias colapsam numa só. Verificado:
**dups pós-merge = 0** em todos os runs.

### 3.3 Achado 10 — Reordenação cross-service NÃO é perda

**Sintoma:** o validador acusava breaks de session ID em respostas e
notificações.

**Análise aprofundada (NEpc reduced):**

- gaps das respostas: `{2: 52, 65535: 26}` → exatamente **26 inversões de
  pares adjacentes, zero sessões em falta** (padrão `N → N+2 → N+1 → N+4`)
- **perda real (sessões ausentes de verdade): 0**
- todas as inversões são pares **ECHO(0x1234) ↔ SetMode(0x1235)** — serviços
  em portas diferentes (30509 vs 30510); o 1 break de notificação é
  RR(0x1234) ↔ NEpc(0x1235)
- **26/26 das inversões já existiam na SAÍDA do ecu5** (a montante de ecu3!);
  requisições: **0 inversões** (chegam ordenadas ao ecu5)
- delta no ecu5: a resposta N+1 sai em média **1 682 µs antes** da resposta N
  (p50; min 71 µs, max 3 093 µs)
- overlap com duplicações do ecu3: trivial (100% dos pacotes do servidor são
  duplicados lá), mas **overlap causal = 0** — a inversão nasce dentro do ecu5
  (filas/endpoints por serviço do vsomeip), antes de ecu3 existir no caminho

**Conclusão:** o fenómeno é **reordenação cross-service por endpoints UDP
separados** — comportamento normal de qualquer stack, não perda, não bug de
parser. Um IDS nunca deve classificá-lo como anomalia.

### 3.4 Contadores de session ID — semântica confirmada

- Contadores são **globais por aplicação**, não por serviço/método
  (ECHO e SetMode intercalam no mesmo contador do cliente; respostas ecoam o
  contador do cliente; notificações do servidor usam contador global próprio)
- Flutuções de fluxo corretas: chave de continuidade =
  `(src, dst, message_type, is_sd)` — SD separado dos dados
- Wraparound `0xFFFF → 0x0000/0x0001` tratado como transição válida
- Return codes NG vêm de RNG **determinístico** (`seed + service + session`)

### 3.5 Outras correções de código

| O quê | Onde |
|---|---|
| `g_opt = opt` em falta | `src/ids_dataset_{server,client}.cpp` |
| `<cstdlib>` para `std::getenv/abs` | ambos os `.cpp` |
| Logs redirecionados (`/logs/ds/{server,client}.log`) | `scripts/gen_dataset.sh` |
| `pgrep/pkill -f '^ids_dataset_*'` (`-x` nunca casa >15 chars) | `scripts/gen_dataset.sh` |
| Contadores de diagnóstico (`g_requests_handled`, `g_responses_sent`, `g_setmode_applied`, `g_sent_log`, `g_resp_log`), dump opcional com `DS_SESSION_LOG=1` | ambos os `.cpp` |
| **NEc SetMode ignorava `setmode_every_cycles`** (hardcoded 200; YAML manda 100) → passou a usar a flag com fallback 200; NEpc usa flag com fallback 50 | `src/ids_dataset_client.cpp` |
| Captura por interface (nada de `-i any`), filtro nas 4 portas SOME/IP | `scripts/gen_dataset.sh` |

---

## 4. Metodologia de validação (gate rigoroso)

Princípio adotado: **gate = taxa real observada + margem pequena**
(nunca uma ordem de grandeza acima).

### Gates atuais (`tools/validate_dataset.py`)

| Gate | Valor | Base |
|---|---|---|
| breaks de session (dados) | **≤ 1.14 %** | 0.639 % observado no NEpc reduced (81/12 678) + 0.5 p.p. |
| perda real (sessões ausentes) | **≤ 0.50 %** | 0.000 % observado + 0.5 p.p. |
| contagem vs alvo efetivo | **±10 %** | alvo × `--scale` |
| truncados / dups pós-merge | **= 0** | crítico, sem margem |
| SD | informativo | perdas de SD validadas à parte por contagem por interface |

O validador reporta **breaks por message type** e separa explicitamente
*reordenação* (mensagens presentes noutra ordem) de *perda real* (sessões
ausentes). Exit code 0 = todos os gates OK.

**Escopo do gate de breaks (decisão registrada — item 1):** o limite de
1,14 % é aplicado sobre a taxa **agregada** — REQUEST + RESPONSE +
NOTIFICATION de dados somados — e assim foi **de propósito** desde a
calibração (a base 0,639 % do NEpc reduced também era a taxa agregada).
A taxa **especificamente em RESPOSTAS** é estruturalmente mais alta do que
o agregado em todos os runs: 2,42 % no NEpc reduced (78/3 220), 1,605 % no
NEpc full (1 035/64 486) e 1,654 % no NEc full (2 374/143 561). A causa é
a reordenação cross-service do achado 10 (§3.3): endpoints UDP separados
por serviço no vsomeip fazem respostas de serviços diferentes chegarem
trocadas no receptor, sem qualquer perda (todas as sessões "em falta" num
lado existem noutra posição; requisições reordenadas/perdidas = 0 em todos
os runs). Esse comportamento já foi validado como benigno — **por isso hoje
não existe gate separado por tipo de mensagem para RESPONSE**: um limiar
por-tipo teria de ser calibrado sobre a taxa específica de resposta (não
sobre a agregada) e mudaria a semântica do gate. Registra-se aqui que,
enquanto o agregado ≤ 1,14 % e a perda real = 0, a concentração de breaks
em respostas é comportamento esperado da topologia, não regressão. Se
futuramente se quiser um gate por-tipo, calibrar primeiro a taxa de
resposta observada num baseline real (ver §8).

### Cross-checks de SD (item 3c — NEpc reduced)

| Interface | Ofertas mcast do servidor | Subscrições do cliente |
|---|---|---|
| ecu5 (origem) | 39 | 37 |
| ecu2_eth1 (net2) | 39 | 37 |
| ecu3 | 39 | 37 |
| ecu4 | 39 | — |
| ecu2_eth0 (pós-relay smcroute) | 39 | 37 |
| ecu1 | 39 | 37 |

**Zero perda de SD em qualquer interface** (relay multicast confirmado).

---

## 5. Resultados

### 5.1 Runs reduzidos (`--scale 0.05`) — validação de método

| Métrica | RR reduced | NEpc reduced | NEc reduced |
|---|---|---|---|
| total / alvo efetivo | 323 / 323 (**0.0 %**) | 12 755 / 12 756 (**0.0 %**) | 83 924 / 86 101 (−2.5 %) |
| breaks (rate) | 0 (0.000 %) | 81 (**0.639 %**) | 63 (0.075 %) |
| breakdown | — | resp 78/3220 (2.42 %), notif 3/6238 (0.048 %) | resp 63/7197 (0.875 %) |
| perda real | 0 | 0 | 0 |
| truncados / dups | 0 / 0 | 0 / 0 | 0 / 0 |
| NG | 9/146 (6.2 %) | 73/3220 (2.3 %) | 70/7197 (1.0 %) |
| dups removidas (merge) | 0 | 57 261 | 404 862 |
| resultado | **OK** | **OK** | **OK** |

Composição NEc reduced confirmada: ECHO 7 057 (1/100 ms), SetMode NEpc 70 e
NEc 70 (ambos 1/5 s — fix do `setmode_every` verificado em campo), notificações
NEpc = NEc = 34 526, RR 11, client recebeu 69 063/69 063 (**perda 0**).

### 5.2 Runs FULL (item 6 — regressão raw 2/6 antes E depois de cada run)

| Métrica | `normal_rr` ✅ | `normal_nepc` ✅ | `normal_nec` ✅ |
|---|---|---|---|
| duração | 310 s | 1 280 s | 7 100 s |
| total / alvo | 6 656 / 6 455 (**+3.1 %**) | **255 084 / 255 128 (0.02 %)** | **1 653 598 / 1 722 011 (−4.0 %)** |
| breaks (rate) | 0 (0.000 %) | 1 047 (0.412 %) | 3 040 (0.185 %) |
| breakdown | req 0, resp 0, notif 0 | req 0, **resp 1035/64486 (1.605 %)**, notif 12/124921 (0.010 %) | req 0, **resp 2374/143561 (1.654 %)**, notif 666/1357442 (0.049 %) |
| perda real | 0 | 0 | **0** (validador reporta `missing=1` — falso positivo do `0x0000` reservado, ver §8.2) |
| truncados / dups pós-merge | 0 / 0 | 0 / 0 | 0 / 0 |
| NG (vs p_ng) | 152/3085 = 4.9 % (0.05) | 1293/64486 = 2.0 % (0.02) | 1426/143561 = 1.0 % (0.01) |
| SD / dados | 477 / 6 180 | 1 938 / 253 893 | 10 667 / 1 644 564 |
| wraparounds | 0 | 1 | 23 |
| dups removidas | 26 794 | 1 145 158 | 7 973 753 |
| taxa | 21.5 pkt/s | 199.3 pkt/s | 233 pkt/s |
| ficheiro | 560 KB | 22 MB | **141 MB** |
| resultado | **OK** | **OK** | **OK** |

Notas dos runs full:
- RR: 10 notificações (cadência rara ~30 s por design — `rr_every`), 0 breaks.
- NEpc: os 1 047 breaks são **0 requisições + apenas reordenação**
  (1 682 µs p50 no ecu5, ver §3.3) — perda real = 0.
- NEpc/NEc: composição por serviço bate certo (ex.: 0x1234 = 2×ECHO + notifs RR;
  NEc: 0x1235 = 0x1236 = 681 422 exatos, SetMode 1/5 s nos dois).
- NEc: a "1 sessão perdida" que o validador reporta (`session_id_missing=1`)
  **não é perda** — é o valor reservado `0x0000` contabilizado num gap de
  wrap com reordenação no boundary; **perda real = 0** (investigação
  completa na §8.2, incluindo os contadores do tcpdump).
- NEc: ecu1 ficou 7 pacotes atrasado na paragem do tcpdump; o merge **ressuscitou
  os 7** a partir de ecu2_eth0 (total final 1 653 598 em todos os lados) —
  prova do valor de capturar em todas as interfaces.
- NEc: 23 wraparounds de session (notificações globais > 65 535 × 23).

---

## 6. Fenómenos reais documentados (para o IDS da Fase 3)

Conhecimento que **evita falsos positivos** num IDS em rede real:

1. **Reordenação cross-service** é normal (endpoints UDP por serviço) —
   verificar ordem por fluxo `(src,dst,msgtype)` e distinguir de perda.
2. **Duplicação em roteamento** (ingress+egress na mesma interface) —
   dedup por `(5-tuple, IP ID, payload)`, ignorando TTL.
3. **Concatenação de mensagens SOME/IP em datagramas UDP** — nunca assumir
   1 msg = 1 datagrama.
4. **Session IDs globais por aplicação** com wraparound `0xFFFF→0x0001`.
5. **Return codes NG** (até ~5 %) são comportamento configurado, não anomalia.
6. **SD multicast** com relay (TTL alterado 1→3) e repetições no arranque.
7. Gate de baseline derivado da **taxa observada + margem**, com breakdown por
   tipo de mensagem (req/resp/notif/SD) — nunca um limiar "redondo".

---

## 7. Ficheiros alterados

| Ficheiro | Alterações |
|---|---|
| `src/ids_dataset_server.cpp` | `g_opt`, `<cstdlib>`, contadores + `DS_SESSION_LOG` |
| `src/ids_dataset_client.cpp` | `g_opt`, `<cstdlib>`, contadores + logs, **fix SetMode NEc** (`setmode_every`) |
| `tools/pcap_to_csv.py` | laço multi-mensagem SOME/IP por datagrama |
| `tools/validate_dataset.py` | laço multi-mensagem; chave `(src,dst,msgtype,is_sd)`; gates 1.14 %/0.5 %; breakdown por msgtype; contagem de perda real; campos novos no MANIFEST |
| `tools/merge_captures.py` | `pkt_key` sem TTL (dedup de roteamento); merge ordenado por tempo |
| `scripts/gen_dataset.sh` | logs stdout, `pgrep -f`, captura por interface, verificações raw 2/6 (antes/depois up e run) |
| `docs/payload_model.md` | IDs/métodos/ports corrigidos, tabela ID/porta única, reutilização Fase 1, regras K e NG reais, tamanhos de payload |
| `datasets/normal/MANIFEST.json` | gerado/atualizado pelo validador |

Build verificado com `g++ -std=c++20 -Wall -Wextra` dentro da imagem:
**0 warnings, 0 errors**.

---

## 8. Verificações adicionais (pedido de esclarecimento — itens 1–4)

Item 1 documentado no §4 (parágrafo "Escopo do gate de breaks"). Itens 2–4
abaixo. Todas as checagens foram read-only sobre dados/logs já existentes;
nenhum dataset foi regenerado nem alterado.

### 8.1 Desvios de volume dentro da tolerância (item 2)

Ambos os runs estão dentro do critério **±10 %**, mas a causa de cada desvio
passa a ser registada (medida sobre o CSV/pcap já gerado + configs YAML):

**`normal_rr` — +3,1 % (+201 pacotes sobre o alvo 6 455).**
Composição medida: REQUEST 3 085 · RESPONSE 3 085 · NOTIF RR 10 · SD 477
(160 ofertas + 158 subscrições + 158 SubAck + 1 Find; 6 657 mensagens em
6 656 pacotes — 1 datagrama levava 2 mensagens, achado 4).

- *Para baixo:* requisições ficaram −15 vs nominal 3 100 (310 s / 100 ms) —
  1º REQUEST a t+0,62 s (janela de disponibilidade via Find/Subscribe SD) e
  cadência medida mediana 100,27 ms (overhead do `cv_.wait_for` = +0,27 ms
  por ciclo) → 3 086 esperados, bate com os 3 085 observados.
- *Para cima (causa dominante):* **volume de SD**. Das 477 mensagens SD,
  316 são renovações de subscrição + acks a cada ~1,96 s (TTL 3 s). O alvo
  6 455 implica ~245 SD (6 455 − 6 200 req/resp nominais − 10 notifs); o
  nosso modelo de SD (renovações incluídas) dá ~477 → +232.
- Saldos exatos: +232 (SD medido 477 vs ~245 implícitos no alvo) − 24
  (startup + timer: req/resp −15 cada) − 6 (rajada inicial do SD: 477 medido
  vs ~471 nominal) − 1 (datagrama concatenado) = **+201** = 6 656 − 6 455 ✓
- O overhead fixo do script **não** explica o sinal positivo: a janela de
  captura começa antes dos apps, o que só *abaixa* contagens (−0,23 %).
- *Limite do que é verificável:* a composição exata do alvo do artigo não
  está no repositório — a causa mais provável (contagem de SD com
  renovações vs sem) não é demonstrável a 100 % com os dados existentes.

**`normal_nec` — −4,0 % (−68 413 sobre o alvo 1 722 011; gate usa pacotes:
−3,97 %).** Reconciliação exata do défice (68 413 pacotes):

| Componente | Quantidade | % do défice | Evidência |
|---|---|---|---|
| **Deriva determinística do timer** | **65 345** | **95,5 %** | períodos medidos no CSV (abaixo) |
| Mensagens concatenadas em datagramas | 1 633 | 2,4 % | 1 653 598 pacotes vs 1 655 231 mensagens (achado 4) |
| Composição do alvo vs nossa configuração | 1 435 | 2,1 % | alvo detalhado do artigo não consta do repositório |

A deriva é **`cv_.wait_for(período)` dorme ≥ período + overhead de
processamento ≈ 0,44–0,49 ms por chamada** (medido, não inferido):

| Cadência | nominal | medido (mediana) | desvio | défice de contagem |
|---|---|---|---|---|
| notificação NEpc/NEc | 10 000 ms | **10 450 ms** | +4,50 % | −62 784 (2 × 31 392) |
| ECHO request/response | 50 000 ms | **50 434 ms** | +0,87 % | −1 253 req −1 279 resp |
| SetMode (cada serviço) | 5 000 ms | **5 046 ms** | +0,93 % | −26 (2 × 13) |
| notificação RR | 30 000 ms | **31 455 ms** | +4,85 % | −11 |
| SD | 2 000 ms (ofertas/renovações) | ≈ nominal | — | +8 (rajada inicial) |
| **soma** | | | | **≈ −65 345** ✓ |

Não é jitter aleatório: é overhead por chamada que acumula
**linearmente** com a duração (310 s → pouca coisa; 7 100 s → −4 %). O
overhead fixo do script contribui −0,19 s (−0,003 %) — irrelevante. O
mesmo mecanismo explica a notificação RR a 31,455 s em vez de 30 s
(3 000 esperas × 0,485 ms).

### 8.2 A "1 sessão perdida" do NEc — perda de rede ou captura? (item 3)

**Os logs existem.** O tcpdump imprime os contadores finais mesmo sem
`-v`; o `gen_dataset.sh` redireciona o stdout de cada captura para
`logs/ds/*.pcap.log` e esses ficheiros são do **run full do NEc** (último
run). Extraídos sem correr nada:

| Interface | packets captured | received by filter | **dropped by kernel** |
|---|---|---|---|
| ecu1_eth0 | 1 653 591 | 1 653 598 | **0** |
| ecu2_eth0 | 1 653 598 | 1 653 598 | **0** |
| ecu2_eth1 | 1 653 598 | 1 653 598 | **0** |
| ecu5_eth0 | 1 653 598 | 1 653 598 | **0** |
| ecu3_eth0 | 3 009 410 | 3 009 410 | **0** |
| ecu4_eth0 | 3 556 | 3 556 | **0** |

(ecu1: 7 pacotes passaram ao filtro mas não chegaram a ser escritos —
corrida de saída do tcpdump; os 7 foram resgatados do ecu2_eth0 pelo merge,
conforme já documentado.)

→ **Limitação de captura regra-se.** E a causa da "sessão em falta" ficou
também identificada: replicando a lógica exata do validador sobre o pcap,
REQUEST dá missing 0, NOTIFICATION missing 0, e o único valor em falta na
RESPONSE é **`0x0000`** — a sessão **reservada** (vsomeip salta
`0xFFFF→0x0001`), no wrap a ≈ t+3 239 s, onde a reordenação cross-method
pôs `0xFFFF` antes de `0xFFFE`: o gap `0xFFFE→0x0001` "espera" `0xFFFF`
(presente ✓) e `0x0000` (nunca emitido → contado como missing). É o
próprio fenómeno do achado 10 a interagir com o caso de wrap do
`check_session_continuity` (a docstring do validador já diz que `0x0000` é
reservado, mas o branch de wrap só cobre `0xFFFF→0x0000/0x0001` adjacentes).

**Conclusão: perda real = 0 (0 em 1,64 M de mensagens).** O
`session_id_missing: 1` do MANIFEST é artefato de contabilidade, não perda
de rede. Para runs futuros: manter a captura dos contadores finais do
tcpdump (já garantido por `logs/ds/*.pcap.log`); correção sugerida para o
validador — ignorar `0x0000` nos gaps forward — **não aplicada** nesta
rodada (só registro).

### 8.3 Smoke test pós-Fase 2 (item 4)

`./scripts/smoke_test.sh` (sem `--down` prévio, sem `gen_dataset.sh`, com o
ambiente já de pé) — reconstruiu a imagem e subiu as 5 ECUs:

```
[PASS] C1 existe trafego SOME/IP-SD            (86 pacotes SD)
[PASS] C2 ecu1 recebe SD de 192.168.2.4        (12 pacotes, roteado via ecu2)
[PASS] C3 REQUEST  192.168.1.2 -> 192.168.2.4  (0x1234 metodo 0x0001)
[PASS] C4 RESPONSE 192.168.2.4 -> 192.168.1.2  (0x1234 metodo 0x0001)
[PASS] C5 NOTIFICATION do evento 0x8001 do servico 0x1235
RESULTADO: OK (todas as 5 verificacoes passaram)
```

- `ids_client`: `respostas=3 notificacoes=3 sucesso=sim` → **exit code 0**
- script: **SMOKE TEST: SUCESSO**, exit code **0**
- o rebuild recompilou os 4 binários (incluindo `ids_dataset_*` da Fase 2)
  sem erros → **a Fase 2 não quebrou nada da Fase 1**
- datasets intocados (o smoke usa os pcaps da Fase 1 em `pcaps/`)

---

## 9. Estado atual e próximos passos

- [x] Itens 1–5 (warnings, ecu3, gate, docs/fix NEC, NEc reduced)
- [x] `normal_rr` full (310 s) — **PASS**
- [x] `normal_nepc` full (1 280 s) — **PASS**
- [x] `normal_nec` full (7 100 s) — **PASS** (1 653 598 / 1 722 011 = −4.0 %,
      breaks 0.185 %, perda 0 — `missing=1` é falso positivo, ver §8.2,
      raw 2/6 antes/depois)
- [x] Verificações pós-entrega (itens 1–4): gate agregado documentado (§4),
      desvios explicados (§8.1), perda NEc = 0 (§8.2), smoke C1..C5 PASS (§8.3)
- [x] Commit da Fase 2 no git (`e633f9f` + rename `e689dc7`, pushados)
- [ ] Próxima fase: features + IDS (Fase 3) sobre os três datasets validados

Comando para regenerar qualquer run:
```bash
./scripts/gen_dataset.sh <normal_rr|normal_nepc|normal_nec> [--scale 0.05]
```
