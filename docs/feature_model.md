# Feature Model - State Transition Features (Tabela IV)

This document defines the per-packet features extracted by
`tools/extract_features.py` (Fase 4), following the state-transition feature
set of Koyama et al., *"Study on Intrusion Detection Method Considering
Communication States for Automotive Ethernet Network"* (VTC2022-Spring),
Table IV / Section V-B. No model is trained in this phase; the output feeds
Fase 5 (classifier + evaluation).

Inputs: the CSVs produced by Fase 2/3 (`datasets/normal/*.csv`,
`datasets/attack/*.csv`). Output: `features/<nome>.csv` (original columns
+ 13 feature columns + `label`), plus the discretization thresholds in
`features/thresholds.json` and per-dataset counts in `features/MANIFEST.json`.

## 1. Stream key (transition state)

Each transition is tracked per **stream key**:

```
stream_key = (service_id, type_label, src_ip)
```

where `type_label` is:

- `SD:Offer`, `SD:Find`, `SD:Subscribe`, `SD:SubAck` for SOME/IP-SD messages
  (`is_sd=1`; multiple entry types in one message are joined by `+` in
  sorted order - not observed in the current datasets, which are homogeneous);
- the `message_type_name` (`REQUEST`, `RESPONSE`, `NOTIFICATION`) otherwise.

Instance ID is constant (`0x0001`) across all datasets and is omitted.
`stream_key` is also emitted as a feature column (metadata for Fase 5).

Observed keys in the normal datasets (per-capture packet counts vary):

| Service | Keys |
|---------|------|
| 0x1234 (ECHO) | REQUEST (client 192.168.1.2), RESPONSE + NOTIFICATION (server 192.168.2.4) |
| 0x1235/0x1236 (SetMode) | REQUEST (client), RESPONSE + NOTIFICATION (server) |
| 0xFFFF (SD) | SD:Offer + SD:SubAck (server), SD:Subscribe + SD:Find (client; Find = 1 startup packet) |

## 2. Features

For each packet, 12 numeric/categorical features are appended. `W = 10`
(window length for the moving averages; not specified by the paper, fixed
here and recorded in `thresholds.json`).

| Column | Definition | Reference packet |
|--------|------------|------------------|
| `dt_prev_req` | time delta (s) to the previous REQUEST | same `(service, sender)` for REQUEST rows; same `service` (any sender) for RESPONSE/NOTIFICATION/SD rows |
| `dt_prev_res` | time delta (s) to the previous packet of the same stream_key | previous packet in the same stream |
| `dt_prev_req_avg` | moving mean of the last `W` non-null `dt_prev_req` values of the same stream | current value excluded |
| `dt_prev_res_avg` | moving mean of the last `W` non-null `dt_prev_res` values of the same stream | current value excluded |
| `dt_prev_req_bin` | discretized `dt_prev_req`: `short` / `medium` / `long` | thresholds per `(service, type_label)`, learned on normal only |
| `dt_prev_res_bin` | discretized `dt_prev_res`: `short` / `medium` / `long` | same |
| `dp_prev_req` | payload difference vs previous REQUEST: 0 = unchanged, 1 = changed, in the **continuous fields** of the current packet (see section 4) | same refs as `dt_prev_req` |
| `dp_prev_res` | payload difference vs previous packet of the stream: 0/1, continuous fields | same as `dt_prev_res` |
| `dp_prev_req_l1` | L1 (byte-wise) payload distance vs the REQUEST reference | same refs as `dt_prev_req`; bytes compared = overlap of the two payloads (lengths may differ) |
| `dp_prev_res_l1` | L1 payload distance vs the previous packet of the stream | same as `dt_prev_res` |
| `n_cs` | number of session streams currently open for this service (cumulative count of distinct stream keys seen so far for the service) | never null |
| `os` | Session-ID in strict order: 1 if `session == prev + 1` or wraparound `0xFFFF -> {0x0000, 0x0001}`; 0 otherwise (forward gap, backward jump, repeated ID) | null on the first packet of a stream |

Notes:

- **Redundancy (documented, kept):** for REQUEST rows, `dt_prev_res`
  compares against the previous REQUEST of the same stream and `dt_prev_req`
  against the previous REQUEST of the same sender+service; in practice the
  two references coincide for single-sender request streams
  (`dt_prev_req == dt_prev_res` on those rows in the current datasets).
  For RESPONSE rows, `dt_prev_res` measures the client->server request
  spacing (responses follow requests one-to-one), while `dt_prev_req` is the
  request->response latency.
- **First packet of a stream:** all reference-based features (`dt_*`,
  `dp_*`, `os`, bins, averages) are empty (CSV empty field = NA). Fase 5
  must drop NA rows before training. SD rows never have a REQUEST reference
  (0xFFFF is never the target of a REQUEST), so `dt_prev_req`,
  `dp_prev_req*` and their averages/bins are always NA for SD.
- **Session restarts:** a backward Session-ID jump marks a session start but
  does **not** increment `n_cs` (the old stream is superseded; ends are not
  observable in the merged capture). No restarts occur in the current 14
  datasets; `os` would flag them as 0.
- **Shared session counters (benign):** the vsomeip applications share one
  Session-ID counter per message type across services, so per-service streams
  show benign forward gaps. Measured `os = 0` rates on the normal datasets:

  | Dataset | 0x1234 | 0x1235 | 0x1236 | 0xFFFF |
  |---------|--------|--------|--------|--------|
  | normal_rr   | 0.00% | - | - | 0.00% |
  | normal_nepc | 2.03% | 2.01% | - | 0.00% |
  | normal_nec  | 1.08% | 100% (notif) | 100% (notif) | 0.02% |

  In `normal_nec`, the server interleaves notifications of 0x1234/0x1235/0x1236
  on a single counter, so the 0x1235/0x1236 NOTIFICATION streams violate
  strict per-stream order **100% of the time**; `os` is uninformative for
  those keys there (baseline saturated), while the same keys violate ~0% in
  `normal_nepc` - contradictory baselines.

  **Decision (pre-Fase 5, see section 6):** the `os` feature is excluded for
  the stream keys `0x1235|NOTIFICATION|192.168.2.4` and
  `0x1236|NOTIFICATION|192.168.2.4` in **all** datasets. Fase 5 must ignore
  `os` on those keys (the remaining features of those packets stay usable);
  remodeling the shared counter (reopening Fase 2) was rejected.
- **`n_cs` baselines (normal):** max 3 per SOME/IP service (1 request +
  1 response + 1 notification stream) and 4 for 0xFFFF (4 SD types). An
  attacker opening a new stream raises the plateau (ARR-Req: client
  192.168.1.50 REQUEST stream -> 0x1234 goes 3 -> 4). Spoofing attacks that
  reuse an existing stream (ANEpc/ANEc copy Session-IDs) and payload/time
  attacks that reuse the server stream (ARR-Res) do **not** change `n_cs`.

## 3. Time discretization (bins)

For each `(service, type_label)` and each of `dt_prev_req` / `dt_prev_res`,
anchors `(min, median, max)` are learned from the **pooled normal datasets**
only (`normal_rr`, `normal_nepc`, `normal_nec`). Bin boundaries are the
midpoints `b1 = (min+median)/2`, `b2 = (median+max)/2`; a value is assigned
to the closest anchor (equivalently: `<= b1` short, `<= b2` medium, else
long). Values outside the learned key (e.g. `SD:Find`, which has a single
startup packet per capture and therefore no deltas) get an empty bin.

Learned thresholds (`features/thresholds.json`, values in seconds):

### `dt_prev_req` (anchors learned per service|type_label)

| Key | n | min | median | max | b1 | b2 |
|-----|---|-----|--------|-----|----|----|
| 0x1234\|NOTIFICATION | 277 | 0.000047 | 0.02320 | 0.08114 | 0.01162 | 0.05217 |
| 0x1234\|REQUEST | 207051 | 0.000042 | 0.05026 | 0.18141 | 0.02515 | 0.11583 |
| 0x1234\|RESPONSE | 207054 | 0.003046 | 0.005978 | 0.02182 | 0.004512 | 0.01390 |
| 0x1235\|NOTIFICATION | 802957 | 9.5e-07 | 2.0574 | 5.0690 | 1.0287 | 3.5632 |
| 0x1235\|REQUEST | 2669 | 1.0088 | 5.0266 | 5.0703 | 3.0177 | 5.0484 |
| 0x1235\|RESPONSE | 2671 | 0.002352 | 0.005643 | 0.007898 | 0.003997 | 0.006770 |
| 0x1236\|NOTIFICATION | 678158 | 1.9e-06 | 2.5213 | 5.0690 | 1.2607 | 3.7952 |
| 0x1236\|REQUEST | 1406 | 5.0180 | 5.0463 | 5.0703 | 5.0322 | 5.0583 |
| 0x1236\|RESPONSE | 1407 | 0.002370 | 0.006148 | 0.01048 | 0.004259 | 0.008315 |

### `dt_prev_res`

| Key | n | min | median | max | b1 | b2 |
|-----|---|-----|--------|-----|----|----|
| 0x1234\|NOTIFICATION | 274 | 30.0093 | 31.4434 | 31.5892 | 30.7264 | 31.5163 |
| 0x1234\|REQUEST | 207051 | 0.000042 | 0.05026 | 0.18141 | 0.02515 | 0.11583 |
| 0x1234\|RESPONSE | 207051 | 0.000092 | 0.05011 | 0.18181 | 0.02510 | 0.11596 |
| 0x1235\|NOTIFICATION | 803486 | 0.000090 | 0.01041 | 0.08661 | 0.005249 | 0.04851 |
| 0x1235\|REQUEST | 2669 | 1.0088 | 5.0266 | 5.0703 | 3.0177 | 5.0484 |
| 0x1235\|RESPONSE | 2669 | 1.0065 | 5.0266 | 5.0726 | 3.0165 | 5.0496 |
| 0x1236\|NOTIFICATION | 678607 | 0.000080 | 0.01045 | 0.08659 | 0.005266 | 0.04852 |
| 0x1236\|REQUEST | 1406 | 5.0180 | 5.0463 | 5.0703 | 5.0322 | 5.0583 |
| 0x1236\|RESPONSE | 1406 | 5.0171 | 5.0463 | 5.0726 | 5.0317 | 5.0594 |
| 0xFFFF\|SD:Offer | 4362 | 0.000023 | 2.0002 | 2.6606 | 1.0001 | 2.3304 |
| 0xFFFF\|SD:SubAck | 4354 | 0.000032 | 2.0002 | 2.6604 | 1.0001 | 2.3303 |
| 0xFFFF\|SD:Subscribe | 4354 | 0.000013 | 2.0002 | 2.6605 | 1.0001 | 2.3304 |

(0x1234|REQUEST and 0x1234|RESPONSE share near-identical request spacing
because responses are paired 1:1 with requests. `0xFFFF|SD:Find` has no
entry: the single startup Find packet produces no delta.)

## 4. Payload discretization (dp)

`dp_*_l1` is always the byte-wise L1 distance over the overlapping prefix of
the two payloads (signed bytes treated as unsigned magnitudes). The
categorical `dp_*` compares only the **continuous** bytes of the *current*
packet (per `docs/payload_model.md` §1-2); enum/reserved bytes are ignored
so that legal enum transitions do not count as payload changes:

| Current packet kind | Bytes compared (continuous) |
|---------------------|-----------------------------|
| NOTIFICATION, 16 B  | 0-3 (Speed, SteeringAngle) |
| REQUEST, 16 B (ECHO)| 0-3 (sequence counter) |
| REQUEST, 2 B (SetMode) | none -> fallback: whole overlap |
| RESPONSE, 4 B | byte 0 (echoed counter) |

Known limitation: on the ECHO/SetMode streams the continuous fields change
every cycle (counters, sinusoids), so `dp_cat` saturates at ~1 (all
"changed") in normal traffic; the informative signal is in `*_l1`
magnitudes (e.g. normal notif-vs-request overlap ~400-500 vs attacker
request-vs-request median L1 = 32 in ARR-Req-a1). Attacks that preserve the
payload exactly (ARR-Res fab-style=knows, ANEpc/ANEc with copied signal
values) yield L1 = 0; timing/order/CSs features are then the only hope.

## 5. Reproduction

```bash
# pilot
python3 tools/extract_features.py --only normal_rr --only ARR-Req-a1

# all (learns thresholds from the 3 normal CSVs, then extracts all 14)
python3 tools/extract_features.py

# sanity check (no model): label0 vs label1 KS / category rates / n_cs
python3 tools/validate_features.py
```

`features/*.csv` are git-ignored (large); `features/MANIFEST.json` and
`features/thresholds.json` are tracked.

## 6. Known limitations & Fase 5 decisions

Decisions recorded **before** training (Fase 5). Machine-readable copy:
`exclusions` block of `features/MANIFEST.json`.

| # | Limitation | Decision |
|---|------------|----------|
| 1 | `os` baseline saturated (100% violations) on `0x1235\|NOTIFICATION\|192.168.2.4` and `0x1236\|NOTIFICATION\|192.168.2.4` in `normal_nec` (shared Session-ID counter across services), vs ~0% in `normal_nepc` | **Exclude the `os` feature for these 2 stream keys in all datasets** (keep rows, drop only the feature on those keys). Global counter remodeling rejected (would reopen Fase 2). |
| 2 | `dp_cat` saturates at ~1 on ECHO/SetMode streams (counters/sinusoids change every cycle); no signal in `normal_rr` REQUEST/NOTIFICATION rows | Keep `dp_cat` but rely on `*_l1` for those keys (documented §4) |
| 3 | ARR-Res-a1 signal depends on attacker response delay (100ms -> 8ms); a timing-matched attacker would collapse the `dt` flags (payload-identical `dp_cat` = 0% vs 66% would remain) | Report both in Fase 5 evaluation; do not claim timing-independent detection |
| 4 | `SD:Find` has a single startup packet per capture -> no thresholds, empty bins | Accept empty bin (NA) |
| 5 | Forward gaps are benign in shared-counter streams (baseline: 1-3% of 0x1234/0x1235 REQ/RESP rows in NEpc/NEc) | Compare against the learned per-key normal baseline, never against an ideal 0% |

## 7. E3 - per-signal payload state (Fase 5 extension)

Motivation: with the V-C 2 window (see `ids_model.md` sec. 10, `baseline_v3`),
the final TPR depends on the **direct** Algorithm-1 detection, which is only
~2.9% of attack packets in the frozen baseline. The signals lost are concentrated
in the payload-identical attacks (ANEpc/ANEc, `dp_*` = 0). Section 2 above only
discretizes **timing/order** (Tabela IV); E3 extends the state tuple with the
**per-signal payload state** so that a notification whose CAN-style signals are
out of their learned behaviour becomes a new state.

Where: implemented in Fase 5 (`tools/ids_realtime.py`, `--payload-state`),
decoding `payload_hex` (already a column of `features/*.csv`, section 2) - **no
Fase 4 re-run and no new column**. Only `payload_bands` are learned, and only
from the training normals (like every other threshold).

### 7.1 Signals per packet kind (bit ranges: `payload_model.md` sec. 1-2)

| Packet kind (key) | Signals (`name`, nature) |
|---|---|
| `NOTIFICATION` (16 B) | `speed` u16 cont, `steer` i16 cont, `gear` enum (byte 4, low nibble), `brake` enum (byte 5 bit 0), `acc` enum (byte 6 bits 3-5), `turn` enum (byte 7 bits 2-4) |
| `0x1234\|REQUEST` (ECHO, 16 B) | `seq` u32 cont (bytes 0-3) |
| `SETMODE\|REQUEST` (2 B) | `mode` enum (byte 0) |
| `RESPONSE` (4 B) | `echo` enum (byte 0), `mode` enum (byte 1) |
| SD (`0xFFFF\|SD:*`) | none (no signal payload -> tuple unchanged) |

### 7.2 State components

For each signal of the packet's kind, **two** components are appended to the
7 base components of section 2 (Tabela IV):

- **continuo** (`speed`, `steer`, `seq`): `name:changed` in `{0,1,NA}`
  (1 = value differs from the previous packet of the same `stream_key`) and
  `name:band` in `{low, mid, high}`. Bands are the **terciles** of the signal
  values observed in the training normals (one `[b1,b2]` per signal *name*,
  stored in the model as `payload_bands`).
- **enumerado** (`gear`, `brake`, `acc`, `turn`, `mode`, `echo`): `name=value`
  and `name=prev>value` (value transition within the `stream_key`).

The previous-packet values are tracked per `stream_key`; on the first packet of
the holdout region the transitions are `NA` (the prefix discarded by the E1
`row_filter` is scanned first to seed them, so only the true first packet of a
capture is `NA`).

### 7.3 Cost and consequence (measured, `results/exp_E3`)

The payload components multiply the reachable states: on the training normals
the number of distinct states per key goes from 130 (baseline) to 16 229 (E3);
`0x1235|NOTIFICATION` alone goes from 15 to 8 090. This is the intended effect
(payload-identity attacks now differ from the normals) but it also inflates the
Algorithm-1 false positives, since rare payload states are under-sampled. The
measured TPR/FPR (direct, Algorithm 1, final, by category) and the FP
classification (D1a-style) are in `ids_model.md` sec. 10.

Reproduction:

```bash
python3 tools/ids_realtime.py train --payload-state --identity ip \
    --model results/exp_E3/payload_model_100_use_ip.json          # D1a reference
python3 tools/evaluate_ids.py --identity ip --holdout 0.3 --retro-window 3 \
    --payload-state --results-dir results/exp_E3/ip \
    --out results/exp_E3/ip/report.json
```

### 7.4 E3b -- exclusao de contadores / identificadores monotonos

O E3 (§7.2) tratava o `seq` do ECHO como sinal **continuo** e aprendia a sua
faixa por tercis **globais**. Como o ECHO e' um contador monotonico
(captura-relativo), a "faixa" nao e' uma propriedade de comportamento: o mesmo
estado do servidor cai em `seq:low`/`seq:mid`/`seq:high` consoante a posicao no
tempo. Isto gerou o grupo dominante de falsos positivos do E3 (§10.2 do
`ids_model.md`): `0x1234|REQUEST`, `...|seq:1|seq:high`, n = 12 754 (87,5 %).

E3b retira do estado de payload os sinais que sao **so' numeracao** (nao
transportam estado fisico/enumerado do servico). Implementacao:
`--payload-exclude SINAL` em `tools/ids_realtime.py`/`tools/evaluate_ids.py`
(o conjunto fica gravado no modelo em `payload_exclude`; o `prev` continua a ser
mantido para os restantes sinais da mesma stream).

Campos de `payload_model.md` **excluidos** em E3b:

| sinal | local (payload) | porque e' excluido |
|---|---|---|
| `seq` | `0x1234\|REQUEST` (ECHO), bytes 0-3 (u32) | contador monotonico: e' numeracao de sequencia da stream, sem significado de estado; a sua faixa e' posicional (tercil global) e nao comportamental |

Nenhum outro sinal e' excluido, e por uma razao verifica-se para cada um:

- `speed`, `steer` (`NOTIFICATION`) -- sinais **continuos** fisicos (senoides de
  velocidade/direcao), nao numeracao; mantidos.
- `gear`, `brake`, `acc`, `turn` -- **enumerados** de estado (posicao de caixa,
  travagem, aceleracao, pisca); ciclicos/agrupados, nao monotonos; mantidos.
- `mode` (`SETMODE|REQUEST`) e `echo`/`mode` (`RESPONSE`) -- indices de modo que
  **circulam** A>B>C>D>A (wraparound), nao uma sequencia monotonica; mantidos.
  (`echo` e' o eco do `mode` pedido -- informacao dependente do `mode`, nao um
  contador.)
- O `session_id` do cabecalho SOME/IP **e'** um contador monotonico, mas nao e'
  um campo do payload: ja entra na tupla base como `os` (§2), que apenas usa a
  **ordem** (`prev+1`), nao a magnitude -- por isso nao sofre do defeito de
  tercil. Nao e' tocado pelo E3b.

Efeito: a chave `0x1234|REQUEST` volta a ter os 7 componentes base (o `seq`
deixa de gerar componentes), e `payload_bands` deixa de conter `seq`. Resultado
medido (FP por classe, TPR/FPR, por sinal) em `ids_model.md` sec. 10.3.

Reproducao (isolada, sobre `baseline_v3`):

```bash
python3 tools/ids_realtime.py train --normal normal_rr --normal normal_nepc \
    --normal normal_nec --payload-state --payload-exclude seq --identity ip \
    --model results/exp_E3b/payload_model_100_use_ip.json
python3 tools/evaluate_ids.py --identity ip --holdout 0.3 --retro-window 3 \
    --payload-state --payload-exclude seq --results-dir results/exp_E3b/ip \
    --out results/exp_E3b/ip/report.json
python3 tools/diagnose_ids.py --results-dir results/exp_E3b/ip \
    --model-100 results/exp_E3b/payload_model_100_use_ip.json \
    --out results/exp_E3b/diagnose.json
python3 tools/experiment_e3b_report.py --results-dir results/exp_E3b/ip \
    --model-100 results/exp_E3b/payload_model_100_use_ip.json \
    --out results/exp_E3b/per_signal.json
```


