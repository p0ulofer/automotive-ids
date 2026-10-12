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
