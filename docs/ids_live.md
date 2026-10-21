# Fase 6 — IDS em modo online (ao vivo)

`tools/ids_live.py` processa tráfego **em tempo real** e classifica cada pacote
SOME/IP com os mesmos dois algoritmos do modo offline: Algoritmo 1 (Sec. V-B)
e Algoritmo 2 com janela retroactiva **T = 3 s** (Sec. V-C, `baseline_v3`).

Regras de ouro desta fase:

1. **Nada congelado foi alterado.** `results/baseline_v3/`, `datasets/*`,
   `features/*` e `docs/relatorio_fase5.md` continuam exactamente como estavam.
   Esta fase é aditiva: só acrescenta `tools/feature_logic.py`,
   `tools/ids_live.py`, `tools/validate_ids_live.py`, este documento, a secção
   §11 de `ids_model.md` e a pasta `results/ids_live_validation/`.
2. **Só inferência, nunca treino.** O modelo de transições, os limiares de
   discretização e as chaves com `os` excluído são carregados da inicialização a
   partir dos artefactos congelados:
   - `results/baseline_v3/ip/realtime_model_use_ip_h30.json` (Algoritmo 1);
   - `features/thresholds.json` (limiares da Fase 4, reaprendidos em **nenhum**
     momento);
   - `features/MANIFEST.json` (exclusões de `os`, via `excluded_os_keys` do
     modelo).
3. **Configuração validada:** identidade `ip` (sem MAC, sem `ip_client`), variante
   `avg_cold-start = use`, **sem** `payload-state`/E3, janela T = 3 s, sessão por
   timeout de 10 s. É exactamente o `baseline_v3` identidade `ip`.
4. **Não reimplementar lógica de features.** Ver §2.

---

## 1. Arquitetura

```
              ┌───────────────────────────────────────────────────────────┐
  scapy ────▶ │ packet_to_rows()      tools/pcap_to_csv.py (partilhado)   │
  AsyncSniffer│  SOME/IP + SD -> dict com os MESMOS campos do CSV offline │
  (--interface│                                                    │ rows │
   ou --pcap) └────────────────────────────────────────────────────────────┘
                                                                     ▼
     ┌───────────────────────────────────────────────────────────────────────┐
     │ tools/feature_logic.py  (partilhado com extract_features.py)          │
     │   Extractor.process(row) -> {dt_prev_*, _avg, _bin, dp_*, n_cs, os}   │
     │   estado incremental por stream_key (Deque W=10, ultimo t, sessao,     │
     │   ultimo payload)                                                     │
     └───────────────────────────────────────────────────────────────────────┘
                                    │  features (formato de CSV)
                                    ▼
     ┌───────────────────────────────────────────────────────────────────────┐
     │ Algoritmo 1 (em memoria)                                              │
     │   tupla de estado discretizada -> tabela de transicoes do modelo       │
     │   -> alert_transition (imediato: print [ALERT] + coluna)               │
     │   -> cs_armed (num de remetentes por servico > maximo aprendido)       │
     └───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
     ┌───────────────────────────────────────────────────────────────────────┐
     │ Algoritmo 2 (fila de decisao)                                         │
     │   sessao = (Service ID, identidade=ip), timeout 10 s                  │
     │   V-C 2   : hit em T = 3 s  -> contamina a sessao nessa janela        │
     │   V-C 1+3 : fim de sessao + CS armado + intervalo medio fora do       │
     │            anchor -> marca a sessao inteira                           │
     │   o veredito so' e' escrito quando ja' nao pode mudar                 │
     └───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
        results/<out>/realtime_<nome>.csv   (Algoritmo 1, uma linha por pacote)
        results/<out>/retro_<nome>.csv      (veredito final, uma linha por pacote)
```

### Componentes e papéis

| ficheiro | papel |
|---|---|
| `tools/feature_logic.py` | **partilhado**: `Extractor`, `StreamState`, `type_label`, `in_order_session`, `dp_l1`/`dp_cat`, `fmt`. Usado por `extract_features.py` (offline) e por `ids_live.py` (online). |
| `tools/pcap_to_csv.py` | **partilhado**: `packet_to_rows(pkt)` descodifica SOME/IP/SD e devolve dicts de linha **no formato do CSV offline**. Usado por `pcap_to_csv` (batch) e por `ids_live` (ao vivo). |
| `tools/ids_live.py` | motor online: fila de decisão, Algoritmo 1, Algoritmo 2, saídas. **Não tem nenhuma linha de treino.** |
| `tools/validate_ids_live.py` | valida equivalência pacote-a-pacote online vs. `results/baseline_v3/ip/`. |

### Porque é que a descodificação também é partilhada

Um bug real apanhado durante esta fase, que é exactamente o "bug silencioso"
que se quer evitar: `packet_to_rows` devolvia `is_sd` como `int` (1), enquanto o
pipeline offline lê `is_sd == "1"` (**string**, porque vem de `csv.DictReader`).
Resultado: `type_label()` classificava os pacotes SD como `NOTIFICATION`, as
`stream_key` divergiam e **3 em cada 100 pacotes** ficavam mal classificados —
silenciosamente. A normalização para `str` em `packet_to_rows` + o teste de
equivalência (`validate_ids_live.py`) é o que apanha este tipo de regressão.

---

## 2. Estado incremental por `stream_key`

O `Extractor` mantém, por `stream_key = (Service ID, tipo, remetente)`, tudo o
que as features precisam — **nada é reprocessado a cada pacote**:

| estado | para que serve |
|---|---|
| `last_t` | `dt_prev_res` (delta contra o pacote anterior da mesma stream) |
| `last_session` | feature `os` (Session-ID em ordem estrita, com *wraparound* `0xFFFF→0/1`) |
| `last_payload` | `dp_prev_res` (categórico + L1) |
| `dt_res_deque` (W=10) | `dt_prev_res_avg` |
| `dt_req_deque` (W=10) | `dt_prev_req_avg` |
| `last_req_svc` / `last_req_sender` | `dt_prev_req` / `dp_prev_req` |
| `open_keys[serviço]` | `n_cs` |

O Algoritmo 2 tem o seu próprio estado incremental, por **sessão**:

| estado | para que serve |
|---|---|
| `sessions[sessão].by_type` | média de `dt_prev_res` por tipo (V-C 1+3) |
| `sessions[sessão].hits` | instantes dos hits do Algoritmo 1 (V-C 2, janela T) |
| `current_counter` / `last_ts_by_base` | chave de sessão `svc|remetente#n` + timeout 10 s |
| `service_cs_exceeded` | já houve `cs_armed` nesse serviço (condição V-C 1+3) |
| `expiry_heap` | fecha sessões quando o timeout de 10 s expira |

---

## 3. Latência de decisão (T = 3 s + fim de sessão)

**O veredito final de um pacote não é emitido no instante em que o pacote chega.**
Há dois atrasos inerentes ao desenho, ambos documentados aqui para não serem
confundidos com lentidão de implementação:

### 3.1 Latência de 3 s — V-C 2 (janela retroactiva)

O Algoritmo 2 pode reclassificar pacotes **recentes**: um hit a instante `h`
marca todos os pacotes da mesma sessão com `|ts − h| ≤ T`. Nesse intervalo, um
pacote ainda pode passar de `final_anomaly = 0` para `1`.

Portanto um pacote só é "fechado" quando já não pode ser contaminado por nenhum
hit futuro, ou seja, quando:

```
ts_do_pacote + T(=3 s) <= tempo_atual
```

### 3.2 Latência de até 10 s — V-C 1+3 (fim de sessão)

O gatilho V-C 1+3 avalia a **média do intervalo** da sessão contra os anchors de
`dt_prev_res`. Só é possível calcular essa média quando a sessão está **fechada**,
o que exige `--session-timeout` (10 s) de inactividade após o último pacote da
sessão. Acresce que a condição "CS armado" pode tornar-se verdadeira mais tarde:
enquanto não se sabe, uma sessão com desvio fica **em espera** (não final).

| gatilho | latência máxima até o veredito ficar final |
|---|---|
| hit direto do Algoritmo 1 | escrita na coluna `alert_transition` **imediatamente**; o `final_anomaly` (que é 1 de qualquer modo) segue a mesma fila do resto |
| V-C 2 (janela T) | **T = 3 s**, mas na prática ficou dominada pela 2.ª linha |
| V-C 1+3 (fim de sessão) | **até 10 s** após o último pacote da sessão (timeout), ou até o fim do stream se a sessão nunca fechar |
| sessão cujo desvio depende de um CS futuro | até ao momento em que o serviço excede os CSs, ou ao fim do stream |

> **Resumo para operação:** os alertas do Algoritmo 1 (`[ALERT] ...`) aparecem
> **ao vivo, no instante do pacote**; os vereditos finais do Algoritmo 2
> (`retro_*.csv`) são escritos com a latência da tabela acima. Isto é uma
> propriedade do algoritmo retroactivo (ele re-olha para trás), não uma limitação
> do modo online.

### 3.3 Como a implementação garante isto

`LiveIDS.flush_ready(now, force=False)` escreve o veredito de uma linha quando a
**sua sessão** está **fechada** e **resolvida** (não desviante, ou já
envenenada, ou com o serviço já excedido) e `ts + T ≤ now`. `force=True` (fim de
stream) fecha tudo e descarrega o resto. Enquanto o pacote não está pronto, o
veredito **não é escrito** — é a "segura" deliberada.

A partir da revisão que separou os papéis (§5.3), a escrita é **por sessão**:
cada sessão descarrega as suas linhas assim que o seu veredito é definitivo, sem
esperar por nenhuma outra sessão e sem ordem global. Uma sessão que fica
aberta (stream periódico) ou em espera já não bloqueia o veredito das outras.

> Nota de rigor: a janela T **não** é a fonte da latência. O veredito de uma
> linha fica definitivo quando a **sessão fecha** (é aí que se sabe a lista
> completa de hits e a média do V-C 1+3 — a marca retroativa é *por sessão*).
> O `ts + T ≤ now` é uma condição **conservadora** que se mantém por
> compatibilidade com a leitura "janela retroactiva de 3 s"; na prática o factor
> limitante é o fecho da sessão (10 s de inactividade) e, no máximo, +3 s.

---

## 4. Cold start (esperado, não é bug)

Ao iniciar, o motor não tem histórico nenhum. Os primeiros pacotes de cada
`stream_key` são tratados como "primeiro pacote", tal como já documentado no modo
offline (`feature_model.md` / `ids_model.md` §1.5):

- `dt_prev_res`, `dt_prev_req`, `dp_*` = **N/A** (sem pacote de referência);
- `dt_prev_*_avg` = **N/A** (janela W = 10 vazia);
- `os` = **N/A**;
- o pacote **não é checkable**, logo **não gera** `alert_transition` (o fluxo da
  Fig. 8 trata-o como início de sessão);
- `avg_full = 0` até a janela da stream estar cheia (11.º pacote);
- `n_cs = 1` na primeira stream de cada serviço.

Isto é **idêntico** ao comportamento do `extract_features.py` no primeiro
pacote de cada CSV, pelo que a equivalência validada em §6 inclui estes pacotes
(não há "diferença de cold start" a explicar: o offline também começa de zero).

No modo online a única diferença real é que o histórico **não vem de um CSV
anterior**: o motor arranca de facto do zero. Por isso o replay determinístico
sempre começa no 1.º pacote do pcap.

---

## 5. Limites de tempo e memória (operação longa)

Pergunta feita antes do commit: *uma sessão em espera no V-C 1+3 — fechada, mas
cujo serviço nunca excede os CSs, portanto a condição de CS nunca se torna
verdadeira — fica retida para sempre?* **Não.**

### 5.1 Existe um teto rígido para sessões em espera? — SIM

| | |
|---|---|
| **valor** | **300 s** após o fecho da sessão |
| **opção** | `--session-hold-timeout <segundos>`; **`0` desliga o teto** (semântica exacta do offline, sem limite) |
| **implementação** | `tools/ids_live.py`: constante `DEFAULT_SESSION_HOLD_TIMEOUT = 300.0`; `LiveIDS._close_session()` calcula `hold_deadline = closed_at + teto` e faz `heapq.heappush(hold_heap, …)`; `LiveIDS._expire_holds()` (chamado a cada linha por `_advance()`) liberta as sessões passadas do prazo; o ramo `or s["hold_expired"]` de `LiveIDS.flush_ready()` desbloqueia a escrita |
| **o que acontece no fim do prazo** | a sessão é **finalizada sem o gatilho V-C 1+3**: fica `hold_expired=True`, **não** recebe `interval_poisoned`, sai de `waiting_cs`, as suas linhas são escritas no `retro_*.csv` (`session_deviates=1`, `poisoned_by` vazio) e o estado é libertado |
| **como se observa** | `summary()["sessions_hold_expired"]` → `stats_<nome>.json`; aviso em stderr: `AVISO: N sessoes em espera fechadas por teto de 300s (V-C 1+3 nao disparou)` |
| **prova** | auto-teste dirigido no relatório: `hold_cap_selftest` (10/10 passos) — fecha uma sessão com a média fora do anchor, confirma que entra em espera, que **não** expira antes do prazo, que **expira** no prazo, que sai da espera sem envenenamento, que é escrita e que o estado é removido |

Sem o teto, a sessão ficaria em espera para sempre e o motor retê-la-ia até ao
fim do processo — exactamente o vazamento a evitar. Com o teto, o que muda em
relação ao offline é apenas: *se dentro de 300 s o serviço nunca exceder os CSs,
o V-C 1+3 nunca dispara para essa sessão* — que é de qualquer modo o resultado
final que o offline escreveria no fim da captura. Isto é, o teto **não** muda
nenhum veredito enquanto a condição de CS ainda possa cumprir-se dentro do prazo.

### 5.2 A ordem global do `retro_*.csv` **não** é requisito de operação

Pergunta: a ordenação estrita por `idx` no `retro_*.csv` é uma exigência real
(alguém consome o ficheiro a exigir ordem global) ou é só uma conveniência do
comparador de validação?

**Resposta: é uma conveniência do comparador — um artefacto do modo batch.**
Evidência (código, não opinião):

| facto | onde |
|---|---|
| o offline escreve o retro CSV numa **passagem final** sobre o ficheiro de detecção: uma linha retro por linha de entrada, pela mesma ordem | `tools/ids_retroactive.py`, `apply_retroactive()`: `for pos, r in enumerate(rows)` no fim da função |
| a marcação retroativa é **por sessão**: os hits são os da própria sessão (`hits[skey]`) e o V-C 1+3 é um estado por sessão (`interval_poisoned`) | mesmo ficheiro: `hits = defaultdict(list)`, `interval_poisoned = set()` |
| logo, o veredito de uma linha depende **só da sua sessão**, nunca da ordem global das linhas | `apply_retroactive()`: `skey = session_of[pos]`; `retro = any(abs(ts - h) <= T for h in hits[skey])` |
| o único componente que exige ordem global é o **comparador** (diff linha-a-linha contra o baseline congelado) | `tools/validate_ids_live.py` |

Em operação, um `retro_*.csv` é um **registo de decisões**: a ordem natural é a
ordem em que as decisões ficam definitivas. Cada linha traz `idx` e `timestamp`,
por isso quem precisar de ordem global reordena — e o comparador passa a fazer
exactamente isso (§6.1).

**O que mudou por causa disto (separação dos dois papéis):**

| | antes | agora |
|---|---|---|
| caminho ao vivo (`ids_live.py`) | fila global por `idx`: uma sessão aberta/em espera no início da fila retinha **tudo** o que vinha atrás (*head-of-line blocking*) | **emissão por sessão**: cada sessão escreve as suas linhas assim que o seu veredito é definitivo; as linhas de uma sessão ficam contíguas; **sem ordem global** |
| harness de validação (`validate_ids_live.py`) | comparava posicionalmente | **ordena as duas tabelas por `idx` antes de comparar** — é o harness que reintroduz a ordem, não o caminho ao vivo |
| conteúdo de cada linha | — | **inalterado** (a marca é por sessão): os 5 datasets continuam a dar **0/0** |

### 5.3 Memória: o que fica retido e como é limitado

| mecanismo | estado |
|---|---|
| fila global por `idx` | **eliminada** — não havia necessidade (§5.2) |
| linhas pendentes | vivem **na sessão** (`s["pending"]`), em forma compacta (tuple de 11 campos, com as strings repetidas partilhadas via `self._intern`): ~0,3–1 KB/linha em vez de ~2,1 KB (dict de 23 campos) |
| sessão já escrita | removida de `self.sessions` assim que todas as suas linhas saem (`sessions_pruned`) |
| sessão **em espera** (V-C 1+3 pendente de CS) | teto rígido `--session-hold-timeout` = 300 s (§5.1) |
| sessão **ainda aberta** (stream que nunca fica inactivo) | **corte por idade** `--session-max-age` (novo): a sessão é fechada como o EOF faria |

Medições (`normal_nepc`, holdout de 384 s, 76 750 linhas; replay determinístico,
`/usr/bin/time -v`):

| configuração | pico RSS | buffer máximo | linhas escritas em fluxo | `session_key` / `session_mean_dt_res` |
|---|---|---|---|---|
| antes (fila global + dicts por linha) | 240 MB | 76 750 | 0 | — |
| agora, `--session-max-age 0` (default = semântica exacta do offline) | 152 MB | 76 750 | 0 | idêntico ao baseline (0 diffs) |
| agora, `--session-max-age 60` | **90 MB** | **12 003** | **71 996** | só estas 2 colunas diferem |

Sobre a última linha: com `--session-max-age 60` o `realtime_*.csv` é
**idêntico** ao baseline (0 diffs) e o `retro_*.csv` muda na **fronteira do
corte** — ver §6.4, onde a variante está formalizada no relatório (e onde se
vê que a devolução **não** é zero: cortar uma sessão parte a janela
retroactiva V-C 2).

Notas importantes:

- **o buffer em disco (opção "espevar para disco") não é necessário**: com a
  emissão por sessão e o corte por idade, o conjunto pendente fica limitado e
  nada precisa de ir para disco;
- o **default** de `--session-max-age` é `0` (= sem corte) porque é o modo que
  preserva a equivalência exacta com o `baseline_v3`; o `ids_live.py` imprime
  um aviso quando corre sem esse limite. Para operação longa, usar
  `--session-max-age 60` (ou maior): a memória fica limitada ao tráfego dos
  últimos 60 s;
- o `--session-timeout` (10 s) **não** serve para isto: reduzi-lo muda a
  semântica do V-C 1+3 (e a partição das sessões) e invalidaria a equivalência
  validada;
- latência combinada: com `--session-max-age 60`, uma sessão desviante cujo
  serviço nunca excede os CSs só é finalizada ao fim de `60 s (corte) + 300 s
  (teto de espera) = 360 s` — até lá fica em memória; é o preço de não deixar
  estado retido;
- uma sessão que nunca fica inactiva também nunca é avaliada pelo V-C 1+3 (é
  por isso que, no conjunto `baseline_v3`, `session-interval` só dispara em 2
  linhas de `ARR-Req-a1`). O `--session-max-age` dá-lhe um fim, como o EOF dava
  no offline;
- `docs/relatorio_fase5.md` e o `baseline_v3` não são afetados por nada disto: o
  offline processa CSVs finitos.

---

## 6. Validação de equivalência (obrigatória)

### 6.1 Como se corre

```bash
# 3 ataques (ANEpc-a1, ARR-Res-a1, ANEc-a1) + 2 normais + auto-teste do teto
python3 tools/validate_ids_live.py \
    --normal normal_rr --normal normal_nepc \
    --out results/ids_live_validation/report.json
```

`--attack` é repetível; sem argumentos valida `ANEpc-a1`, `ARR-Res-a1` e
`ANEc-a1` mais `normal_rr`. O script:

1. corre `ids_live.py --pcap <dataset>.pcap` (replay **determinístico**: usa os
   timestamps originais do pcap, não dorme, não há jitter de agendamento);
2. compara `realtime_*.csv` e `retro_*.csv` **linha-a-linha e coluna-a-coluna**
   com `results/baseline_v3/ip/retro_use_ip_h30_*.csv`, **ordenando as duas
   tabelas por `idx` antes** (o `retro_*.csv` do modo online vai por ordem de
   decisão, sem ordem global — ver §5.2; é o harness que reintroduz a ordem).
   Se o número de linhas difere (dataset substituído), compara o prefixo
   comum e marca `rows_equal=false` — nunca dá "0 diffs" sem ter comparado;
3. confere que as métricas agregadas são iguais e regista os contadores de
   memória (`stats_*.json`);
4. corre o **auto-teste do teto de sessões em espera** (§5.1) —
   `hold_cap_selftest`, que tem de dar 10/10 passos;
5. corre a **variante de operação `--session-max-age 60`** (§6.4) e regista a
   caracterização do desvio na secção `session_max_age` do relatório
   (`--max-age 0` desliga; `--skip-max-age` não corre).

Critério de passagem: **zero** diferenças nas colunas de classificação
(`idx, timestamp, label, service_id, type_label, stream_key, dt_prev_res,
alert_transition, cs_armed, session_key, session_mean_dt_res, session_deviates,
poisoned_by, retro_anomaly, final_anomaly, ...`).

Excluídas do critério (metadados, contam à parte):
- `src_mac` — os CSVs normais da Fase 2 **não têm** coluna MAC (o offline grava
  `''`); o online grava o MAC real do pacote. O MAC não entra na identidade
  (`identity=ip`) nem na tupla de estado. Ver §6.3.
- `label` — verdade de terreno, usada só para as métricas.

### 6.2 Resultado (Estágio A — replay determinístico)

`results/ids_live_validation/report.json` (`"ok": true`,
`hold_cap_selftest.ok = true`):

| dataset | tipo | linhas | realtime diffs estritas | retro diffs estritas | métricas iguais | sessões / no teto | veredicto |
|---|---|---|---|---|---|---|---|
| `ANEpc-a1` | ataque (21 s) | 4 135 | **0** | **0** | sim (TPR 1,0000 · FPR 0,1230) | 6 / 0 | **equivalente** |
| `ARR-Res-a1` | ataque ARR, lado *Response* (154 s) | 3 310 | **0** | **0** | sim (TPR 0,1356 · FPR 0,0519) | 4 / 0 | **equivalente** |
| `ANEc-a1` | ataque ANE (23 s) | 5 368 | **0** | **0** | sim (TPR 0,9512 · FPR 0,6652) | 8 / 0 | **equivalente** |
| `normal_rr` | normal, holdout 30 % (93 s) | 1 998 | **0** | **0** | sim (FPR 0,0015) | 4 / 0 | **equivalente** |
| `normal_nepc` | normal, holdout 30 % (384 s) | 76 750 | **0** | **0** | sim (FPR 0,0039) | 6 / 0 | **equivalente** |
| *auto-teste* | teto de sessões em espera (§5.1) | — | — | — | — | 10/10 passos | **ok** |

- **0 / 0** em três datasets de ataque (inclui um ARR e um ANE, como pedido) e
  dois normais — 91 561 linhas comparadas, nenhuma divergência de classificação.
- o `retro_*.csv` do modo online vai **por ordem de decisão** (sessão fechada),
  não por ordem global de `idx`; o comparador ordena por `idx` antes de
  comparar (§5.2). O **conteúdo** de cada linha é o do baseline — os mesmos
  números, célula a célula.
- `ANEpc-a1`: o `realtime_*.csv` é **byte-idêntico** ao congelado (`cmp` sem
  diferenças, incluindo `label` e `src_mac`); o `retro_*.csv` é idêntico
  célula a célula depois de ordenado por `idx` (§5.2).
- `normal_rr` e `normal_nepc`: idênticos depois de remover a coluna `src_mac`
  (ver §6.3); todas as restantes 17 colunas batem em todas as linhas.
- `sessions_hold_expired = 0` em todos: o teto de 300 s **não disparou** em
  nenhum dos testes — logo não alterou nenhum veredito destas execuções. O
  caminho está provado pelo `hold_cap_selftest` (§5.1).
- `retro_rows_streamed = 0` em todos: nestas capturas **nenhuma sessão fecha
  durante o stream** (as streams são periódicas, < 10 s) — logo a memória só
  se liberta no fim. Com `--session-max-age 60` a descarga passa a ser
  contínua (71 996 de 76 750 linhas em `normal_nepc`, §5.3).
- **Zero pacotes de cold start divergentes**: o offline e o online começam ambos
  do zero, logo não há diferença residual a explicar.

#### Porque é `ANEpc-a1` e não `ARR-Req-a1`? (e o que dá, medido)

`ARR-Req-a1` é o exemplo sugerido, mas o pcap em disco **já não é o da execução
congelada** (foi substituído por um `--scale 0.10` e depois re-gerado; ver
`docs/nota_divergencia_arrreqa1.md`): são 3 277 linhas SOME/IP contra as 3 272 do
`baseline_v3`, e os timestamps são de outra run (`1792291183` vs `1791151871`).
Reproduzir esse pcap contradir-se-ia com o próprio ponto do teste (comparar com um
resultado congelado que usou outro pcap).

A divergência não ficou por dizer: foi **corrida e quantificada** em
`results/ids_live_validation/report_arrreqa1.json` (relatório separado, `ok:
false`), com a semântica "linhas diferentes → só se compara o prefixo comum pelo
`idx`, e isso **não** conta como equivalência":

| `ARR-Req-a1` (pcap actual) vs. `baseline_v3` | |
|---|---|
| linhas | 3 277 (online) vs 3 272 (congelado) → `rows_equal=false` |
| diffs estritas no prefixo comum (3 272 linhas) | **19 050** (realtime) · **21 907** (retro) |
| colunas mais divergentes | `timestamp` 3 272/3 272 (todas), `dt_prev_res` 3 267, `state` 1 894, `stream_key` 1 617, `session_key` 1 610 |
| causa | dataset substituído — outro pcap, outra ordem/pacotes. **Não** é divergência de código: nos 5 datasets intactos o mesmo teste dá 0/0. |

Os outros 13 datasets de ataque são **bit-a-bit** iguais à execução congelada;
`ANEpc-a1` (21 s, 1 744 pacotes de ataque, TPR final 1,000) foi o escolhido por
ser curto e sensível. O lado ARR fica coberto por `ARR-Res-a1` (dataset intacto,
0/0).

Para os normais, o `baseline_v3` só guarda os **últimos 30 %** (holdout E1):
`normal_rr` com `--emit-from-index 4659` e `normal_nepc` com
`--emit-from-index 179081`. O motor aquece o estado de features nessas linhas
(independentes do detetor, não escritas) e só depois emite, reproduzindo
exactamente o `row_filter` do modo offline.

### 6.3 Diferença de metadados documentada (não é classificação)

| dataset | coluna | baseline | online | motivo |
|---|---|---|---|---|
| `normal_rr` | `src_mac` (1 998 linhas × 2 ficheiros) | `''` | MAC real | o CSV de origem da Fase 2 (`datasets/normal/normal_rr.csv`) não tem coluna MAC; o `detect` offline le `row.get("src_mac", "")`. Não afecta `identity=ip`, `state`, `cs_*` nem o retroactivo. |
| `normal_nepc` | `src_mac` (76 750 linhas × 2 ficheiros) | `''` | MAC real | idem (`datasets/normal/normal_nepc.csv`) |

Quantificado: **78 748 linhas × 1 coluna de metadados × 2 ficheiros**, 0 linhas
de classificação afectadas. Nos 3 datasets de ataque as colunas de metadados
batem a 100 % (os seus CSVs de origem têm `src_mac` e `label`).

### 6.4 Variante de operação: `--session-max-age 60` (formalizada)

O default do `ids_live.py` é `--session-max-age 0` (= sem corte = equivalência
exacta com o `baseline_v3`, os 5/5 acima). Para quem deixa o IDS a correr
horas seguidas, a recomendação é `--session-max-age 60`, que **limita a
memória** (§5.3). Essa variante é agora **validada com o mesmo padrão de
evidência** dos restantes casos: `validate_ids_live.py --max-age 60` corre o
motor com o corte activo e grava o resultado em `report.json`
(secção `session_max_age`).

**Critério:** o `realtime_*.csv` tem de ser **idêntico** ao baseline (o
Algoritmo 1 não conhece sessões) e nenhuma coluna do Algoritmo 1 pode mudar no
`retro_*.csv`; as colunas do Algoritmo 2 podem mudar **na fronteira do corte**,
e a metadata da partição das sessões muda por definição — ambas são
quantificadas.

| dataset | realtime | retro: colunas do A1 | retro: colunas do A2 (fronteira) | metadata de sessão | métricas | veredicto |
|---|---|---|---|---|---|---|
| `ANEpc-a1` (21 s) | **0** | **0** | **0** | 0 | iguais | **ok** (a captura é mais curta que o corte) |
| `ARR-Res-a1` (154 s) | **0** | **0** | **488** (51 linhas × 4 colunas) | `session_mean_dt_res` 3 309 · `session_key` 2 011 | TPR 0,1356→0,1007 · FPR 0,0519→0,0421 | **ok**, com desvio caracterizado |
| `ANEc-a1` (23 s) | **0** | **0** | **0** | 0 | iguais | **ok** |
| `normal_rr` (93 s) | **0** | **0** | **0** | `session_mean_dt_res` 1 998 · `session_key` 708 | iguais | **ok** |
| `normal_nepc` (384 s) | **0** | **0** | **0** | `session_mean_dt_res` 76 750 · `session_key` 64 754 | iguais | **ok** |

**Mecanismo do desvio (verificado linha a linha):** cortar uma sessão **parte a
janela retroactiva V-C 2**. Em `ARR-Res-a1` os hits do atacante chegam a cada
~60 s e o corte cai ~0,45 s depois de um hit: as 51 linhas do atacante que
seguem (cada 100 ms) estavam marcadas `realtime-window` no baseline (o hit
estava na mesma sessão) e deixam de estar (o hit ficou do outro lado da
fronteira). É um efeito **localizado na fronteira** (linhas a menos de
T = 3 s do corte) e **direccionado**: só se perdem marcas, nunca se ganham
(`tp_final` −26, `fp_final` −25).

Resumo do trade-off:

| | `--session-max-age 0` (default) | `--session-max-age 60` (operação longa) |
|---|---|---|
| equivalência com o `baseline_v3` | **exacta** (0/0 em 91 561 linhas) | não exacta: desvio do A2 na fronteira do corte (0 linhas em 4 dos 5 datasets, 51 linhas em `ARR-Res-a1`) |
| memória | cresce com as sessões abertas (152 MB em `normal_nepc`) | **limitada** (90 MB; 12 003 linhas em memória) |
| descarga do retro | só no fim do stream | contínua (71 996 de 76 750 linhas) |
| V-C 1+3 em streams que nunca ficam inactivos | nunca dispara | passa a poder disparar (como o EOF faria) |

### 6.5 Porque o replay real (ao vivo) é um passo seguinte — **feito, ver §8**

O teste acima isola a **lógica** (o que é que se classifica). O replay pela rede
(`sendp`/`tcpreplay` + `--interface`) acrescenta uma variável nova, o **jitter de
agendamento**: os `dt_prev_*` são medidos no relógio de captura e oscilam à
volta dos microssegundos. Como as features são *discretizadas* (`b1`, `b2`), um
`dt` a um microssegundo do limite pode cair no bin errado. Esse teste não pode
dar 0/0 por construção — a métrica passa a ser "quantas linhas divergem e porquê".

É o que o **Estágio B** (§8) mede: 10 linhas de `state` divergentes em 4 135
(0,24 %), 3 alertas extra e 314 linhas reclassificadas pelo Algoritmo 2.

---

## 7. Como usar

### 7.1 Replay determinístico (validação, sem rede)

```bash
# ataque
python3 tools/ids_live.py \
    --pcap datasets/attack/ANEpc-a1.pcap \
    --labels-csv datasets/attack/ANEpc-a1.csv \
    --out-dir results/ids_live_validation/ANEpc-a1 --quiet-alerts

# normal (holdout E1 do baseline_v3: emitir a partir do índice 4659)
python3 tools/ids_live.py \
    --pcap datasets/normal/normal_rr.pcap \
    --emit-from-index 4659 \
    --out-dir results/ids_live_validation/normal_rr --quiet-alerts
```

### 7.2 Captura ao vivo (no ecu4, observador)

```bash
# dentro do contentor ecu4 (precisa de NET_RAW/NET_ADMIN -> ja' vem no compose)
python3 tools/ids_live.py --interface eth0 \
    --model results/baseline_v3/ip/realtime_model_use_ip_h30.json \
    --thresholds features/thresholds.json \
    --session-max-age 60 \
    --out-dir results/ids_live/run1
```

Enquanto corre, os alertas do Algoritmo 1 aparecem imediatamente:

```
[ALERT] ts=1791151872.017524 svc=0x1234 type=REQUEST stream=0x1234|REQUEST|192.168.1.50 state=...
```

e `retro_run1.csv` é descarregado **à medida que cada sessão fecha** (por
ordem de decisão, sem ordem global — §5.2). `Ctrl-C` fecha o stream e
descarrega o resto.

> `--session-max-age 60` é o que mantém a **memória limitada** em operação
> longa (uma stream periódica nunca fica inactiva, logo a sua sessão nunca
> fecharia sozinha). Sem este parâmetro o motor avisa e a memória cresce com o
> tráfego — ver §5.3.

### 7.3 Demo com tráfego gerado

```bash
# terminal 1 — escuta no ecu4 (ver 7.2)
# terminal 2 — gera o dataset de ataque (lab com 5 ECUs)
./scripts/gen_attack_dataset.sh ANEpc-a1
```

Os `[ALERT]` do Algoritmo 1 devem aparecer durante a execução; ao fim de ~10 s
do fim da captura os vereditos finais entram em `retro_run1.csv`.

### 7.4 Opções relevantes

| opção | default | nota |
|---|---|---|
| `--pcap` / `--interface` | — | obrigatório: fonte de pacotes |
| `--model` | `results/baseline_v3/ip/realtime_model_use_ip_h30.json` | congelado |
| `--thresholds` | o do modelo, senão `features/thresholds.json` | congelado |
| `--retro-window` | `3.0` | T do V-C 2 |
| `--session-timeout` | `10.0` | inactividade que fecha a sessão |
| `--session-hold-timeout` | `300.0` | **teto rígido** das sessões em espera (V-C 1+3); `0` = sem teto (semântica do offline). Ver §5.1 |
| `--session-max-age` | `0` (desligado) | idade máxima de uma sessão: uma sessão mais antiga é **cortada** como o EOF faria, o que **limita a memória** em streams que nunca ficam inactivos. `0` = sem corte (semântica exacta do offline). Ver §5.3 |
| `--emit-from-index N` | `0` | só emite a partir do índice N; antes só aquece features (holdout E1) |
| `--labels-csv` | — | só p/ replay; verdade de terreno, **nunca** é entrada do detetor |
| `--dump-features` | — | grava as features calculadas (debug) |
| `--quiet-alerts` | — | não imprime `[ALERT]` |

Saídas em `--out-dir`: `realtime_<nome>.csv`, `retro_<nome>.csv` e
`stats_<nome>.json` (contadores de memória/tempo: sessões, `sessions_pruned`,
`sessions_hold_expired`, `retro_rows_streamed`, `max_records_buffered`,
`session_hold_timeout_s`).

---

## 8. Estágio B — replay ao vivo pela rede (jitter)

O Estágio A prova a **equivalência** (replay determinístico, 0/0). O Estágio B
mede o que acontece quando o tráfego passa por uma **stack de rede real**:
os timestamps são os de *captura*, não os do dataset, e o jitter de
agendamento entra nas features.

### 8.1 Montagem

```
emissor  -- reenvia o pcap com o TEMPORISMO ORIGINAL (socket AF_PACKET,
            sleeping até ao instante previsto de cada pacote)
   |  veth directo (eth9)  -- sem a stack IP do host no caminho
receptor  -- tools/ids_live.py --interface eth9   (o IDS em modo online)
```

```bash
./scripts/stage_b_live_replay.sh ANEpc-a1     # ou ARR-Res-a1, ANEc-a1, ...
```

O script cria dois contentores, liga-os por um par **veth** (o mesmo kernel, o
mesmo caminho de RX), reenvia o pcap e depois corre
`tools/compare_live_replay.py`, que confronta o resultado com o `baseline_v3`.

**Duas armadilhas do teste ao vivo** (encontradas e documentadas aqui porque
mascariam o resultado):

1. **O host reencaminha as tramas** (`net.ipv4.ip_forward=1`): as tramas cujo IP
   de destino está na sub-rede da bridge voltam a entrar no contentor — o
   receptor via **cada trama duas vezes** (3060 mensagens extra em
   `ANEpc-a1`). Daí o link veth directo: a stack IP do host fica fora do
   caminho.
2. **Os timestamps do pcap estão no passado** (o dataset é de October): o replay
   tem de rebasear a linha temporal (`t0 + (ts − ts_início)`), senão envia
   tudo de seguida, sem qualquer cadência.

### 8.2 Resultado (`ANEpc-a1`, 4 135 mensagens, 21 s)

| grandeza | valor |
|---|---|
| jitter do emissor (real − previsto) | mediana 0,000 ms · p95 0,585 ms · máx 18,2 ms |
| deriva da linha temporal no receptor (relativa) | mediana 0,260 ms |
| jitter no receptor (variação do atraso) | mediana **0,082 ms** · p95 **0,527 ms** · máx 18,0 ms |
| `dt_prev_res` diferente do congelado | 4 109 / 4 126 linhas (mediana **0,096 ms**, p95 0,617 ms, máx 17,9 ms) |
| `dt_prev_res_bin` / `dt_prev_req_bin` mudados | **1** / **9** linhas |

E o efeito na classificação:

| camada | divergência | Baseline → ao vivo |
|---|---|---|
| Algoritmo 1 — `state` (tupla discretizada) | **10** linhas (0,24 %) | — |
| Algoritmo 1 — `in_model` | **3** linhas | 26 → 29 alertas |
| Algoritmo 2 — `final_anomaly` | **314** linhas (7,6 %) | — |
| métricas | TPR **1,000 → 1,000** | FPR **0,123 → 0,254** |

**Mecanismo (verificado):** o jitter de ~0,1 ms medido pelo receptor muda o
`dt_prev_res`; em 10 linhas esse valor cruza um limiar de discretização e o
`state` muda; em 3 dessas linhas a transição deixa de existir no modelo
(`in_model = 0`) e nasce um **alerta extra** (26 → 29). O Algoritmo 2 amplifica:
cada hit novo contamina a janela de T = 3 s da sessão → **314 linhas** mudam de
veredito. Como as 3 linhas afetadas são de tráfego normal, a FPR sobe de
0,123 para 0,254 (a TPR não muda — o ataque continua 100 % detectado).

**Segundo dataset (reprodutibilidade)** — `ARR-Res-a1` (3 310 mensagens, 154 s,
mesma montagem):

| grandeza | `ANEpc-a1` | `ARR-Res-a1` |
|---|---|---|
| jitter de captura (mediana / p95 / máx) | 0,082 / 0,527 / 18,0 ms | 0,114 / 0,375 / 28,9 ms |
| `dt_prev_res` diferente (mediana) | 0,096 ms | 0,067 ms |
| `state` divergente | 10 / 4 135 (0,24 %) | 2 / 3 310 (0,06 %) |
| alertas do Algoritmo 1 | 26 → 29 | 7 → 9 |
| linhas reclassificadas pelo V-C 2 | 314 (7,6 %) | 40 (1,2 %) |
| TPR | 1,000 → 1,000 | 0,1356 → 0,1356 |
| FPR | 0,123 → 0,254 | 0,052 → 0,067 |

O padrão é consistente: **0,06–0,24 % das linhas mudam de estado
discretizado**, 2–3 alertas extra, e a amplificação do V-C 2 propaga isso para
1–8 % das linhas. A TPR **nunca** se altera (o ataque continua detectado na
totalidade); a FPR sobe, e tanto mais quanto mais perto dos limiares de
discretização estiver o tráfego.

Conclusões do Estágio B:

- o caminho ao vivo **não** é bit-idêntico ao offline, e **não deve ser**: a
  única forma de o seria um relógio virtual, que é precisamente o que se
  queria evitar medir;
- a divergência é **pequena e explicada**: 0,24 % das linhas mudam de estado
  discretizado, por causa de ~0,1 ms de jitter de captura;
- a **amplificação do V-C 2** (já medida na Fase 5) transforma 3 alertas
  extras em 314 linhas reclassificadas — é o factor de risco real do modo
  online, muito maior do que o jitter em si;
- implicação prática: as features **discretizadas** são sensíveis à escala do
  submilissegundo, pelo que a margem operacional do modelo é da ordem de
  0,1 ms; se a rede introduzir mais ruído (filas, CPU ocupada), a taxa de
  alertas falsos sobe.

### 8.3 Reprodução

```bash
./scripts/stage_b_live_replay.sh ANEpc-a1
# artefatos: results/ids_live_stageB/ANEpc-a1/
#   replay_sender.json   (jitter do emissor)
#   ids_live.log         (log do IDS em modo online)
#   realtime_/retro_     (saidas do IDS)
#   features.csv         (features calculadas ao vivo)
#   compare_ANEpc-a1.json (desvio quantificado vs baseline_v3)
```

---

## 9. Estado da validação

| passo | estado |
|---|---|
| `feature_logic.py` partilhado + regressão (14 datasets, CSVs bit-idênticos aos de `features/`) | **feito** |
| `packet_to_rows` partilhado (linha a linha idêntica ao `pcap_to_csv` batch) | **feito** |
| Equivalência online vs `baseline_v3` — ataque `ANEpc-a1` | **0 / 4 135 diffs** (realtime byte-idêntico; retro idêntico por `idx`) |
| Equivalência — ataque ARR `ARR-Res-a1` | **0 / 3 310 diffs** |
| Equivalência — ataque ANE `ANEc-a1` | **0 / 5 368 diffs** |
| Equivalência — normal `normal_rr` (holdout) | **0 / 1 998 diffs** (só `src_mac` de metadados) |
| Equivalência — normal `normal_nepc` (holdout, 384 s) | **0 / 76 750 diffs** (só `src_mac` de metadados) |
| `ARR-Req-a1` (dataset substituído) — divergência **quantificada e justificada** | `report_arrreqa1.json` (`ok:false`; 19 050 / 21 907 diffs no prefixo; causa: outro pcap) |
| Teto de sessões em espera (`--session-hold-timeout`, 300 s) | **implementado** (§5.1) + auto-teste 10/10 no relatório |
| Ordem global por `idx` no `retro_*.csv` | **não é requisito de operação** (§5.2) → emissão **por sessão** implementada; o comparador é que ordena por `idx`; conteúdo das linhas inalterado (0/0) |
| Libertação de memória (linhas compactas na sessão, poda de sessões, contadores O(1)) | **feito** (§5.3) |
| Buffer de sessão **ainda aberta** limitado | **sim**, com `--session-max-age` (corte como o EOF): 240 MB → 90 MB e 71 996/76 750 linhas escritas em fluxo (§5.3). Default `0` = semântica exacta |
| Variante `--session-max-age 60` **formalizada** no relatório | `report.json` → `session_max_age`: A1 **0 diffs** em todos; desvio do A2 na fronteira do corte (0 linhas em 4/5 datasets, **51 linhas em `ARR-Res-a1`** — mecanismo em §6.4) |
| Replay ao vivo pela rede (`sendp`/Docker, `--interface`) + quantificação do jitter | **feito (Estágio B, §8)**: jitter de captura mediana 0,082 ms · `state` diverge em 10/4 135 linhas · 3 alertas extra · 314 linhas reclassificadas pelo V-C 2 · TPR 1,000→1,000, FPR 0,123→0,254 |

Relatórios máquina:

- `results/ids_live_validation/report.json` — 5 datasets + auto-teste do teto (`ok: true`);
- `results/ids_live_validation/report_arrreqa1.json` — divergência documentada de `ARR-Req-a1` (`ok: false`, à propósito).
