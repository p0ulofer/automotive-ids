#!/usr/bin/env python3
"""Fase 6 -- IDS SOME/IP em modo online (tempo real + retroativo com T=3 s).

Modo de operacao
================
Este script NAO treina nada. Carrega na inicializacao os artefactos congelados
do `baseline_v3` (modelo de transicoes + thresholds de discretizacao + chaves
com `os` excluido) e limita-se a fazer inferencia:

    results/baseline_v3/ip/realtime_model_use_ip_h30.json
    features/thresholds.json

Duas fontes de pacotes:

  * `--pcap FILE`      replay deterministico (timestamps originais do pcap).
                       Serve para provar equivalencia pacote-a-pacote com o
                       pipeline offline congelado, sem jitter de rede.
  * `--interface IF`   captura ao vivo com scapy (`AsyncSniffer`), ex. `eth0`
                       no ecu4 (observador).

O calculo das features e' exactamente o mesmo do modo offline: usa
`tools/feature_logic.py`, tambem usado por `tools/extract_features.py`.

Algoritmo 1 (tempo real)
------------------------
Para cada pacote, constroi a tupla de estado discretizada (sem `n_cs`) e
verifica se a transicao existe na tabela normal do seu `(Service ID, tipo)`.
Um pacote e' `alert_transition` se for "checkable" (tem pacote anterior na
mesma `stream_key`) e a transicao nao existe no modelo.

Algoritmo 2 (retroativo, janela T=3 s)
--------------------------------------
O veredito FINAL de um pacote nao e' emitido imediatamente. Um hit futuro do
Algoritmo 1 pode contaminar pacotes anteriores da mesma sessao dentro de
`|ts - ts_hit| <= T`. Alem disso, o gatilho V-C 1+3 (fim de sessao com numero
anomalo de CSs + intervalo medio fora dos anchors) so pode ser avaliado quando
a sessao fecha por inactividade (`--session-timeout`, default 10 s).

Logo, ha duas latencias de decisao inerentes ao desenho:

  * V-C 2 (janela): ate' T = 3 s;
  * V-C 1+3 (fim de sessao): ate' ao timeout de sessao (10 s apos o ultimo
    pacote daquela sessao).

Os alertas do Algoritmo 1 sao impressos imediatamente (`[ALERT]`); o CSV de
veredito final (`retro_*.csv`) e' escrito quando cada sessao fecha. Isto e'
documentado em `docs/ids_live.md`.

Limites de memoria/tempo
------------------------
Uma sessao em espera (V-C 1+3 por resolver porque o servico nunca excedeu os
CSs) teria de ficar retida para sempre. Existem, por isso, dois mecanismos:

  * `--session-hold-timeout` (default 300 s; `0` = sem teto): teto RIGIDO de
    tempo. Uma sessao ja' fechada e' finalizada sem o gatilho V-C 1+3 quando o
    teto expira (`_expire_holds`), removendo-a de `waiting_cs`. Contador em
    `summary()["sessions_hold_expired"]` + aviso em stderr.
  * `--session-max-age` (default 0 = sem corte): uma sessao mais antiga e'
    CORTADA como o EOF do offline faria. E' o que limita a memoria em streams
    que nunca ficam inactivos (a sessao nunca fecharia sozinha).

Ordem de saida
--------------
O `retro_*.csv` e' escrito POR SESSAO: cada sessao descarrega as suas linhas
assim que o veredito e' definitivo. Nao ha' ordem global por `idx` -- a marca
retroativa e' por sessao (como no offline, `ids_retroactive.apply_retroactive`),
pelo que o veredito de uma linha nao depende da ordem das outras. Quem precisar
de ordem global reordena pelo campo `idx` (e' o que faz o comparador de
validacao, `tools/validate_ids_live.py`).

A memoria retida e' a das sessoes AINDA ABERTAS (linhas compactas em
`s["pending"]`), nao O(stream inteiro) -- ver `docs/ids_live.md` sec. 5.

Cold start
----------
Ao arrancar nao existe historico. O primeiro pacote de cada `stream_key` fica
com as features de referencia N/A e nao e' "checkable", tal como no modo
offline. Nao e' bug: e' o mesmo comportamento documentado para o pipeline
batch.

Uso
===
    # replay deterministico de um pcap (validacao de equivalencia)
    python3 tools/ids_live.py --pcap datasets/attack/ANEpc-a1.pcap \\
        --labels-csv datasets/attack/ANEpc-a1.csv \\
        --out-dir results/ids_live_validation/ANEpc-a1

    # captura ao vivo no observador (ecu4), ex. eth0
    python3 tools/ids_live.py --interface eth0 --out-dir results/ids_live/run1

    # replay de um normal, com o mesmo corte de holdout do baseline_v3
    python3 tools/ids_live.py --pcap datasets/normal/normal_rr.pcap \\
        --emit-from-index 4659 --out-dir results/ids_live_validation/normal_rr
"""
from __future__ import annotations

import argparse
import csv
import heapq
import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from feature_logic import FEATURE_COLS, Extractor, fmt  # noqa: E402
from ids_common import (  # noqa: E402
    NA,
    is_checkable,
    load_json,
    sender_id,
    split_stream_key,
    state_str,
    state_tuple,
)
from pcap_to_csv import CSV_FIELDS, packet_to_rows  # noqa: E402

# Colunas identicas as do pipeline offline (Fase 5), para comparacao directa.
DETECT_COLUMNS = [
    "idx", "timestamp", "label", "src_ip", "src_mac", "client_id", "sender_key",
    "service_id", "type_label", "stream_key", "n_cs", "sender_count", "cs_max",
    "cs_armed", "is_new_stream", "checkable", "avg_full", "state", "in_model",
    "alert_transition", "alert_flag", "dt_prev_res", "service_seg",
]
RETRO_COLUMNS = [
    "idx", "timestamp", "label", "service_id", "src_ip", "src_mac", "type_label",
    "stream_key", "dt_prev_res", "alert_transition", "cs_armed", "session_key",
    "session_mean_dt_res", "session_deviates", "poisoned_by",
    "retro_anomaly", "final_anomaly", "service_seg",
]

DEFAULT_MODEL = "results/baseline_v3/ip/realtime_model_use_ip_h30.json"
DEFAULT_THRESHOLDS = "features/thresholds.json"
DEFAULT_RETRO_WINDOW = 3.0
DEFAULT_SESSION_TIMEOUT = 10.0
# Teto de seguranca: sessao fechada mas por resolver (V-C 1+3 pendente de um
# excesso de CS que nunca chega) e' finalizada ao fim destes segundos, para que
# em operacao longa o estado nao fique retido para sempre. 0 = sem teto.
DEFAULT_SESSION_HOLD_TIMEOUT = 300.0


def _detect_state(row, thresholds, excluded, avg_full, avg_cold_start):
    """Mesma tupla de estado do Algoritmo 1 offline (ids_realtime._state)."""
    state = state_tuple(row, thresholds, excluded)
    if avg_cold_start == "na" and not avg_full:
        # componentes 2 e 3 = bins das medias (ver TUPLE_FEATURES)
        state = (state[0], state[1], NA, NA, state[4], state[5], state[6])
    return state


class _FeatureDumper:
    """Escreve as linhas+features calculadas (debug/validacao), em streaming."""

    def __init__(self, path):
        self.path = path
        self.fh = None
        self.w = None
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self.fh = open(path, "w", newline="")
            self.w = csv.DictWriter(self.fh,
                                   fieldnames=CSV_FIELDS + FEATURE_COLS,
                                   extrasaction="ignore")
            self.w.writeheader()

    def write(self, row):
        if self.w is not None:
            self.w.writerow(row)

    def close(self):
        if self.fh is not None:
            self.fh.close()
            self.fh = None
            self.w = None


class LiveIDS:
    """Motor online: features incrementais + Algoritmo 1 + Algoritmo 2.

    O estado por stream (dt, medias W=10, session-id, payload) vive dentro do
    `Extractor` partilhado. Aqui ficam apenas o estado do detetor (transicoes,
    remetentes/CSs) e o estado das sessoes retroactivas.
    """

    def __init__(self, model, thresholds, out_dir, retro_window=3.0,
                 session_timeout=10.0, session_hold_timeout=300.0,
                 session_max_age=0.0,
                 emit_from_index=0, alert_stream=sys.stderr,
                 write_outputs=True, prefix="live"):
        self.model = model
        self.thresholds = thresholds
        self.excluded = set(model.get("excluded_os_keys", []))
        self.identity = model.get("identity", "ip")
        self.window_w = int(model.get("window_w", 10))
        self.avg_cold_start = model.get("avg_cold_start", "use")
        self.retro_window = float(retro_window)
        self.session_timeout = float(session_timeout)
        #: Teto de seguranca: uma sessao FECHADA mas ainda por resolver (V-C 1+3
        #: pendente de um excesso de CSs que nunca chega) e' finalizada ao fim
        #: destes segundos. 0 = sem teto (semantica exacta do offline).
        self.session_hold_timeout = float(session_hold_timeout)
        #: Idade maxima de uma sessao (s). Uma sessao mais antiga e' cortada
        #: como o EOF do offline faria (a media do V-C 1+3 passa a ser calculada
        #: sobre a parte ja' vista). 0 = sem corte (semantica exacta do offline).
        #: E' o que limita a memoria em streams que nunca ficam inactivos.
        self.session_max_age = float(session_max_age)
        self.emit_from_index = int(emit_from_index)
        self.alert_stream = alert_stream
        self.write_outputs = write_outputs

        self.transitions = {k: set(v)
                            for k, v in model.get("transitions", {}).items()}
        self.services = model.get("services", {})
        self.interval = model.get("interval_model", {}).get("dt_prev_res", {})

        # --- estado de features (partilhado com o offline)
        self.extractor = Extractor(thresholds=thresholds)

        # --- Algoritmo 1
        self.seen_keys = set()
        self.senders_seen = defaultdict(set)
        self.pos = defaultdict(int)

        # --- registos por pacote emitido, ainda por escrever no retro CSV.
        # NAO existe uma fila global: cada sessao guarda as suas proprias
        # linhas e escreve-as assim que o veredito da sessao fica definitivo
        # (ver `flush_ready`). A ordem global por `idx` nao e' necessaria --
        # a marca retroativa e' por sessao (ids_retroactive.apply_retroactive).
        self.global_idx = -1
        self.pending_rows = 0         # linhas pendentes (todas as sessoes)
        self.ready_sessions = deque()  # sessoes fechadas com veredito definido

        # --- Algoritmo 2: sessoes (svc|sender_key#contador), timeout 10 s
        self.sessions = {}
        self.current_counter = defaultdict(int)
        self.last_ts_by_base = {}
        self.expiry_heap = []   # (ts + session_timeout, skey)
        self.hold_heap = []     # (closed_at + session_hold_timeout, skey)
        self.age_heap = []      # (first_ts + session_max_age, skey)
        self.service_cs_exceeded = set()
        self.waiting_cs = defaultdict(set)

        # ultimas features calculadas (para `--dump-features`)
        self.last_feats = None
        # dumper das features calculadas (opcional, ver `_FeatureDumper`)
        self.feature_dumper = None

        # Cache de strings repetidas (label, service_id, src_ip, src_mac,
        # type_label): as linhas pendentes de uma sessao partilham os mesmos
        # objectos -> memoria por linha muito menor.
        self._intern = {}

        # --- contadores (memoria O(1); nao se guardam registos ja' escritos)
        self.counts = {
            "rows": 0, "attack": 0, "normal": 0,
            "alert_transition": 0,
            "final_flagged": 0, "tp_final": 0, "fp_final": 0,
            "sessions_seen": 0, "sessions_marked": 0,
            "sessions_hold_expired": 0, "sessions_pruned": 0,
            "sessions_cut": 0,
            "max_records_buffered": 0,
            # diagnostico de memoria: linhas descarregadas ANTES do fim do
            # stream (0 = toda a memoria foi o buffer de sessoes abertas)
            "retro_rows_streamed": 0,
        }

        # --- saida
        self.out_dir = Path(out_dir) if write_outputs else None
        self.prefix = prefix
        self.detect_path = self.retro_path = None
        self.detect_file = self.detect_writer = None
        self.retro_file = self.retro_writer = None
        if self.write_outputs:
            self.out_dir.mkdir(parents=True, exist_ok=True)
            self.detect_path = self.out_dir / f"realtime_{prefix}.csv"
            self.retro_path = self.out_dir / f"retro_{prefix}.csv"
            self.detect_file = open(self.detect_path, "w", newline="")
            self.detect_writer = csv.DictWriter(self.detect_file,
                                                fieldnames=DETECT_COLUMNS)
            self.detect_writer.writeheader()
            self.retro_file = open(self.retro_path, "w", newline="")
            self.retro_writer = csv.DictWriter(self.retro_file,
                                               fieldnames=RETRO_COLUMNS)
            self.retro_writer.writeheader()

    # ------------------------------------------------------------------ #
    # Algoritmo 1 + alimentacao do estado retroactivo
    # ------------------------------------------------------------------ #
    def process_row(self, row):
        """Processa uma linha SOME/IP. Devolve a linha de deteccao ou None.

        Linhas antes de `emit_from_index` servem so' para aquecer o estado de
        features (necessario para reproduzir o holdout do baseline_v3); nao
        entram no detetor, exactamente como `row_filter` no modo offline.
        """
        self.global_idx += 1
        idx = self.global_idx
        feats = self.extractor.process(row)
        self.last_feats = feats   # para `--dump-features` (mesmas no frio e quente)
        if self.feature_dumper is not None:
            fr = dict(row)
            for col in FEATURE_COLS:
                fr[col] = fmt(col, feats[col])
            self.feature_dumper.write(fr)
        if idx < self.emit_from_index:
            return None

        frow = dict(row)
        for col in FEATURE_COLS:
            frow[col] = fmt(col, feats[col])

        skey = frow["stream_key"]
        svc, tl, src = split_stream_key(skey)
        sid = sender_id(frow, self.identity)
        is_new_stream = skey not in self.seen_keys
        self.seen_keys.add(skey)
        self.senders_seen[svc].add(sid)
        sender_count = len(self.senders_seen[svc])
        cs_max = self.services.get(svc, {}).get("max_senders", 10 ** 9)
        cs_armed = bool(sender_count > cs_max)

        self.pos[skey] += 1
        avg_full = (self.pos[skey] - 1) >= self.window_w
        checkable = is_checkable(frow)
        state = _detect_state(frow, self.thresholds, self.excluded,
                              avg_full, self.avg_cold_start)
        sstr = state_str(state)
        in_model = sstr in self.transitions.get(f"{svc}|{tl}", set())
        alert_transition = bool(checkable and not in_model)

        # --- CS por servico: uma vez excedido, fica excedido (V-C 1+3)
        if cs_armed and svc not in self.service_cs_exceeded:
            self.service_cs_exceeded.add(svc)
            self._resolve_waiting_cs(svc)

        # --- sessao retroactiva: (svc, identidade) truncada por inactividade
        ts = float(frow["timestamp"])
        self._advance(ts)
        base = f"{svc}|{sid}"
        if base in self.last_ts_by_base and \
                ts - self.last_ts_by_base[base] > self.session_timeout:
            self.current_counter[base] += 1
        self.last_ts_by_base[base] = ts
        session_key = f"{base}#{self.current_counter[base]}"

        # --- linha de deteccao (formato identico ao offline)
        rec = {
            "idx": idx,
            "timestamp": frow["timestamp"],
            "label": str(frow.get("label", "")),
            "src_ip": src,
            "src_mac": frow.get("src_mac", ""),
            "client_id": frow.get("client_id", ""),
            "sender_key": sid,
            "service_id": svc,
            "type_label": tl,
            "stream_key": skey,
            "n_cs": frow["n_cs"],
            "sender_count": sender_count,
            "cs_max": cs_max,
            "cs_armed": int(cs_armed),
            "is_new_stream": int(is_new_stream),
            "checkable": int(checkable),
            "avg_full": int(avg_full),
            "state": sstr,
            "in_model": int(in_model),
            "alert_transition": int(alert_transition),
            "alert_flag": int(alert_transition),
            "dt_prev_res": frow.get("dt_prev_res", ""),
            "service_seg": 0,
        }
        self.counts["rows"] += 1
        if rec["label"] == "1":
            self.counts["attack"] += 1
        elif rec["label"] == "0":
            self.counts["normal"] += 1
        if alert_transition:
            self.counts["alert_transition"] += 1
        if self.detect_writer is not None:
            self.detect_writer.writerow({k: rec[k] for k in DETECT_COLUMNS})

        # --- linha compacta para o retro CSV (memoria): o `stream_key` e'
        # derivado de (service_id, type_label, src_ip) e `service_seg` e' 0.
        # As strings repetidas sao partilhadas (ver `self._intern`).
        it = self._intern.setdefault
        row = (idx, ts, rec["timestamp"],
               it(rec["label"], rec["label"]),
               it(svc, svc),
               it(src, src),
               it(rec["src_mac"], rec["src_mac"]),
               it(tl, tl),
               rec["dt_prev_res"],
               int(alert_transition), int(cs_armed))
        self._add_to_session(session_key, svc, base, idx, frow, tl, ts,
                             alert_transition, row)
        heapq.heappush(self.expiry_heap,
                       (ts + self.session_timeout, session_key))

        if alert_transition and self.alert_stream is not None:
            print(f"[ALERT] ts={rec['timestamp']} svc={svc} type={tl} "
                  f"stream={skey} state={sstr}", file=self.alert_stream,
                  flush=True)
        return rec

    def process_packet(self, pkt):
        """Processa um pacote scapy (pode conter varias mensagens SOME/IP)."""
        out = []
        for row in packet_to_rows(pkt):
            rec = self.process_row(row)
            if rec is not None:
                out.append(rec)
        return out

    # ------------------------------------------------------------------ #
    # Estado de sessoes / Algoritmo 2
    # ------------------------------------------------------------------ #
    def _session(self, session_key, svc, base):
        s = self.sessions.get(session_key)
        if s is None:
            s = self.sessions[session_key] = {
                "session_key": session_key,
                "svc": svc,
                "base": base,
                "n_rows": 0,
                "n_written": 0,
                "by_type": defaultdict(list),
                "hits": [],
                "first_ts": None,
                "last_ts": None,
                "closed": False,
                "closed_at": None,
                "hold_deadline": None,
                "hold_expired": False,
                "marked": False,
                "deviates": False,
                "means": {},
                "interval_poisoned": False,
                # linhas desta sessao ainda por escrever no retro CSV
                "pending": [],
            }
            self.counts["sessions_seen"] += 1
        return s

    def _add_to_session(self, session_key, svc, base, idx, frow, tl, ts, alert,
                        row):
        s = self._session(session_key, svc, base)
        s["n_rows"] += 1
        s["last_ts"] = ts
        if s["first_ts"] is None:
            s["first_ts"] = ts
            if self.session_max_age > 0:
                heapq.heappush(self.age_heap,
                               (ts + self.session_max_age, session_key))
        dt = frow.get("dt_prev_res", "")
        if dt not in ("", None):
            s["by_type"][tl].append(float(dt))
        if alert:
            s["hits"].append(ts)
        s["pending"].append(row)
        self.pending_rows += 1
        if self.pending_rows > self.counts["max_records_buffered"]:
            self.counts["max_records_buffered"] = self.pending_rows

    def _close_session(self, session_key, now=None):
        s = self.sessions.get(session_key)
        if s is None or s["closed"]:
            return
        s["closed"] = True
        s["closed_at"] = now
        means = {}
        deviates = False
        for tl, vals in s["by_type"].items():
            if not vals:
                continue
            m = sum(vals) / len(vals)
            means[tl] = m
            anchor = self.interval.get(f"{s['svc']}|{tl}")
            if anchor and (m < anchor["min"] or m > anchor["max"]):
                deviates = True
        s["means"] = means
        s["deviates"] = deviates
        # Libertar as amostras ja' agregadas (a media ja' foi calculada).
        s["by_type"].clear()
        if deviates and s["svc"] not in self.service_cs_exceeded:
            # V-C 1+3: a condicao de CS pode ficar verdadeira mais tarde.
            # O veredito desta sessao fica em espera (nao e' final) ate'
            # `session_hold_timeout` -- teto de seguranca p/ memoria/tempo.
            self.waiting_cs[s["svc"]].add(session_key)
            if self.session_hold_timeout > 0 and now is not None:
                deadline = now + self.session_hold_timeout
                s["hold_deadline"] = deadline
                heapq.heappush(self.hold_heap, (deadline, session_key))
        else:
            # Veredito definido: pode ser escrito (ja' agora ou quando a
            # janela T desta sessao passar).
            self.ready_sessions.append(session_key)

    def _resolve_waiting_cs(self, svc):
        for session_key in list(self.waiting_cs.get(svc, ())):
            s = self.sessions.get(session_key)
            if s is not None and s["deviates"] and not s["hold_expired"]:
                s["interval_poisoned"] = True
                self.ready_sessions.append(session_key)
        self.waiting_cs.pop(svc, None)

    def _expire_holds(self, now):
        """Teto de seguranca: fecha sessoes em espera apos `session_hold_timeout`.

        Sem isto, uma sessao cujo servico NUNCA exceda os CSs ficaria em espera
        para sempre (estado + registos retidos). Com o teto, a sessao e'
        finalizada sem o gatilho V-C 1+3 e a sua memoria e' libertada.
        """
        while self.hold_heap and self.hold_heap[0][0] <= now:
            deadline, session_key = heapq.heappop(self.hold_heap)
            s = self.sessions.get(session_key)
            if s is None:
                continue  # ja' resolvida e' ja' libertada
            if s["interval_poisoned"] or not s["deviates"]:
                continue  # resolvida antes do teto
            if s["hold_deadline"] != deadline:
                continue  # prazo desactualizado
            s["hold_expired"] = True
            self.counts["sessions_hold_expired"] += 1
            self.waiting_cs[s["svc"]].discard(session_key)
            self.ready_sessions.append(session_key)

    def _cut_session(self, session_key, now):
        """Corta uma sessao por idade maxima (`--session-max-age`).

        E' o analogo do EOF do modo offline: a sessao termina aqui e e'
        avaliada com o que ja' viu. A proxima linha da mesma base abre uma
        sessao nova.
        """
        s = self.sessions.get(session_key)
        if s is None or s["closed"]:
            return
        self._close_session(session_key, now=now)
        base = s["base"]
        self.current_counter[base] += 1
        # A regra de inactividade nao se aplica a esta base (a sessao foi
        # cortada por idade, nao por silencio) -> evita um salto no contador.
        self.last_ts_by_base.pop(base, None)
        self.counts["sessions_cut"] += 1

    def _advance(self, now):
        """Fecha sessoes cujo timeout de inactividade ja' passou."""
        while self.expiry_heap and self.expiry_heap[0][0] < now:
            expiry, session_key = heapq.heappop(self.expiry_heap)
            s = self.sessions.get(session_key)
            if s is None or s["closed"]:
                continue
            # A expiracao pode estar desactualizada (a sessao continuou).
            if s["last_ts"] is not None and \
                    s["last_ts"] + self.session_timeout < now:
                self._close_session(session_key, now=now)
        # Cortes por idade maxima (--session-max-age): analogo do EOF.
        if self.session_max_age > 0:
            while self.age_heap and self.age_heap[0][0] <= now:
                deadline, session_key = heapq.heappop(self.age_heap)
                s = self.sessions.get(session_key)
                if s is None or s["closed"]:
                    continue
                if s["first_ts"] is None or \
                        s["first_ts"] + self.session_max_age != deadline:
                    continue   # prazo desactualizado
                self._cut_session(session_key, now=now)
        self._expire_holds(now)

    def _write_row(self, s, row):
        """Veredito final de uma linha (conteudo identico ao offline).

        A marca retroativa e' POR SESSAO (hits da propria sessao + estado
        V-C 1+3 da sessao) -- por isso o veredito de uma linha nao depende da
        ordem global das linhas.
        """
        (idx, ts, timestamp, label, service_id, src_ip, src_mac, type_label,
         dt_prev_res, alert_transition, cs_armed) = row
        realtime = alert_transition == 1
        retro = False
        trigger = ""
        if s["interval_poisoned"]:
            retro, trigger = True, "session-interval"
        elif s["hits"]:
            if any(abs(ts - h) <= self.retro_window for h in s["hits"]):
                retro, trigger = True, "realtime-window"
        final = bool(realtime or retro)
        mean_val = s["means"].get(type_label, "")
        if final and not s["marked"]:
            s["marked"] = True
            self.counts["sessions_marked"] += 1
        self.counts["final_flagged"] += int(final)
        if label == "1":
            self.counts["tp_final"] += int(final)
        elif label == "0":
            self.counts["fp_final"] += int(final)
        out = {
            "idx": idx,
            "timestamp": timestamp,
            "label": label,
            "service_id": service_id,
            "src_ip": src_ip,
            "src_mac": src_mac,
            "type_label": type_label,
            "stream_key": f"{service_id}|{type_label}|{src_ip}",
            "dt_prev_res": dt_prev_res,
            "alert_transition": alert_transition,
            "cs_armed": cs_armed,
            "session_key": s["session_key"],
            "session_mean_dt_res": (f"{mean_val:.6f}"
                                    if mean_val != "" else ""),
            "session_deviates": int(s["deviates"]),
            "poisoned_by": ("realtime" if realtime else trigger),
            "retro_anomaly": int(retro),
            "final_anomaly": int(final),
            "service_seg": 0,
        }
        if self.retro_writer is not None:
            self.retro_writer.writerow(out)
        return out

    def flush_ready(self, now, force=False):
        """Escreve os vereditos das sessoes cujo veredito ja' e' definitivo.

        NAO existe uma fila global por `idx`: cada sessao e' escrita assim que
        (a) fecha, (b) a condicao de CS esta' resolvida (ou expirou o teto
        `session_hold_timeout`) e (c) a janela T das suas linhas ja' passou.
        As linhas de uma sessao ficam contiguas e por ordem; a ordem global
        por `idx` NAO e' necessaria, porque a marca retroativa e' por sessao
        (ver `ids_retroactive.apply_retroactive`, que faz o mesmo no offline
        numa passage final sobre o ficheiro inteiro).

        Consequencia pratica: uma sessao longa (ou em espera) ja' nao bloqueia
        o veredito das outras -- e a memoria retida passa a ser a das sessoes
        AINDA ABERTAS, e nao a de tudo o que vier depois da mais antiga.
        """
        if force:
            for session_key in list(self.sessions):
                self._close_session(session_key, now=now)
            # No fim do stream, o estado de CSs observado e' o estado final.
            for svc in list(self.service_cs_exceeded):
                self._resolve_waiting_cs(svc)
            self.hold_heap.clear()
            # Sessoes que ficaram em espera (o servico nunca excedeu os CSs):
            # finalizadas SEM o gatilho V-C 1+3, tal como o offline no EOF.
            for svc, keys in list(self.waiting_cs.items()):
                for session_key in list(keys):
                    s = self.sessions.get(session_key)
                    if s is not None and not s["interval_poisoned"]:
                        s["hold_expired"] = True
                        self.ready_sessions.append(session_key)
                self.waiting_cs.pop(svc, None)

        written = []
        blocked = deque()
        while self.ready_sessions:
            session_key = self.ready_sessions.popleft()
            s = self.sessions.get(session_key)
            if s is None:
                continue
            pending = s["pending"]
            n = 0
            for row in pending:
                if not force and (row[1] + self.retro_window) > now:
                    break     # linha ainda dentro da janela T
                written.append(self._write_row(s, row))
                n += 1
            if n:
                del pending[:n]
                self.pending_rows -= n
                s["n_written"] += n
                if not force:
                    self.counts["retro_rows_streamed"] += n
            if pending:
                # As linhas desta sessao ainda estao dentro da janela T: a
                # sessao volta ao fim da fila (nao bloqueia as outras).
                blocked.append(session_key)
                continue
            # Sessao completa: liberta o estado (incl. amostras por tipo).
            self.sessions.pop(session_key, None)
            self.waiting_cs[s["svc"]].discard(session_key)
            self.counts["sessions_pruned"] += 1
        self.ready_sessions.extend(blocked)
        if self.retro_file is not None and written:
            self.retro_file.flush()
        return written

    # ------------------------------------------------------------------ #
    # Fecho
    # ------------------------------------------------------------------ #
    def finish(self):
        rows = self.flush_ready(now=float("inf"), force=True)
        if self.detect_file is not None:
            self.detect_file.close()
        if self.retro_file is not None:
            self.retro_file.close()
        return rows

    def summary(self):
        c = self.counts
        attack, normal = c["attack"], c["normal"]
        return {
            "rows": c["rows"], "attack": attack, "normal": normal,
            "alert_transition": c["alert_transition"],
            "tp": c["tp_final"], "fp": c["fp_final"],
            "tpr": (c["tp_final"] / attack) if attack else None,
            "fpr": (c["fp_final"] / normal) if normal else None,
            "sessions": c["sessions_seen"],
            "sessions_poisoned": c["sessions_marked"],
            "sessions_hold_expired": c["sessions_hold_expired"],
            "sessions_pruned": c["sessions_pruned"],
            "sessions_cut": c["sessions_cut"],
            "max_records_buffered": c["max_records_buffered"],
            "pending_rows_end": self.pending_rows,
            "retro_rows_streamed": c["retro_rows_streamed"],
            "session_hold_timeout_s": self.session_hold_timeout,
            "session_max_age_s": self.session_max_age,
        }


def _load_thresholds(model, explicit_path, root):
    if explicit_path:
        return load_json(explicit_path)
    model_th = model.get("thresholds_file")
    if model_th and Path(model_th).exists():
        return load_json(model_th)
    return load_json(root / DEFAULT_THRESHOLDS)


def _load_labels(path):
    with open(path, newline="") as fh:
        return [row.get("label", "") for row in csv.DictReader(fh)]


def _run_pcap(args, engine, root):
    """Replay deterministico: usa os timestamps ORIGINAIS do pcap.

    Sem dormir entre pacotes (relogio virtual do proprio pcap), pelo que este
    modo serve para provar equivalencia pacote-a-pacote com o offline sem
    jitter de agendamento.
    """
    from scapy.all import PcapReader
    labels = _load_labels(args.labels_csv) if args.labels_csv else None
    pcap_idx = -1
    with PcapReader(args.pcap) as reader:
        for pkt in reader:
            for row in packet_to_rows(pkt):
                pcap_idx += 1
                if labels is not None and pcap_idx < len(labels):
                    row["label"] = labels[pcap_idx]
                engine.process_row(row)
                engine.flush_ready(float(row["timestamp"]))
                if args.max_packets and pcap_idx + 1 >= args.max_packets:
                    break
            if args.max_packets and pcap_idx + 1 >= args.max_packets:
                break
    engine.finish()
    print(f"[ids_live] replay {args.pcap}: {pcap_idx + 1} mensagens SOME/IP",
          file=sys.stderr)


def _run_interface(args, engine):
    from scapy.all import AsyncSniffer

    # As labels (verdade de terreno) sao OPCIONAIS e nunca sao entrada do
    # detetor: servem so' para calcular metricas. Sao atribuidas por indice
    # de mensagem, como no replay deterministico -- assumem que o trafego
    # capturado e' exactamente o do dataset (ver o aviso no fim).
    labels = _load_labels(args.labels_csv) if args.labels_csv else None
    counter = 0

    def on_packet(pkt):
        nonlocal counter
        for row in packet_to_rows(pkt):
            if labels is not None and counter < len(labels):
                row["label"] = labels[counter]
            counter += 1
            engine.process_row(row)
        engine.flush_ready(float(pkt.time))

    sniffer = AsyncSniffer(iface=args.interface, filter=args.bpf_filter,
                           prn=on_packet, store=False)
    print(f"[ids_live] a escutar em {args.interface} "
          f"(Ctrl-C para terminar)...", file=sys.stderr, flush=True)
    sniffer.start()
    try:
        while True:
            sniffer.join(timeout=1.0)
            if not sniffer.running:
                break
    except KeyboardInterrupt:
        print("\n[ids_live] a terminar...", file=sys.stderr, flush=True)
    finally:
        if sniffer.running:
            sniffer.stop()
    engine.finish()
    if labels is not None and counter != len(labels):
        print(f"[ids_live] AVISO: {counter} mensagens capturadas vs "
              f"{len(labels)} labels no CSV -- a atribuicao por indice pode "
              f"estar errada (o trafego capturado tem de ser o do dataset)",
              file=sys.stderr)


def main():
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(
        description="IDS SOME/IP online (Fase 6) -- Algoritmo 1 + 2, "
                    "sem treino, usando o modelo congelado baseline_v3.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="replay deterministico de um pcap")
    src.add_argument("--interface", help="interface de captura ao vivo (ex. eth0)")
    ap.add_argument("--model", default=str(root / DEFAULT_MODEL))
    ap.add_argument("--thresholds", default=None,
                    help="thresholds.json (default: o do modelo ou "
                         "features/thresholds.json)")
    ap.add_argument("--labels-csv", default=None,
                    help="opcional: CSV com a coluna label (so' para replay; "
                         "nunca e' entrada do detetor)")
    ap.add_argument("--out-dir", default=str(root / "results" / "ids_live"))
    ap.add_argument("--name", default=None, help="prefixo dos ficheiros de saida")
    ap.add_argument("--retro-window", type=float, default=DEFAULT_RETRO_WINDOW,
                    help="T (s) da janela retroactiva V-C 2 (default 3.0)")
    ap.add_argument("--session-timeout", type=float,
                    default=DEFAULT_SESSION_TIMEOUT,
                    help="inactividade (s) que fecha uma sessao (default 10.0)")
    ap.add_argument("--session-hold-timeout", type=float,
                    default=DEFAULT_SESSION_HOLD_TIMEOUT,
                    help="teto de seguranca (s): uma sessao fechada mas ainda "
                         "por resolver (V-C 1+3 pendente de CS) e' finalizada "
                         "ao fim destes segundos, libertando o estado. "
                         "0 = sem teto (semantica exacta do offline, "
                         f"default {DEFAULT_SESSION_HOLD_TIMEOUT:.0f})")
    ap.add_argument("--session-max-age", type=float, default=0.0,
                    help="idade maxima de uma sessao (s): uma sessao mais "
                         "antiga e' cortada como o EOF faria, o que limita a "
                         "memoria em streams que nunca ficam inactivos. "
                         "0 = sem corte (semantica exacta do offline)")
    ap.add_argument("--emit-from-index", type=int, default=0,
                    help="so' emite vereditos a partir deste indice global; "
                         "antes disso apenas aquece o estado de features "
                         "(reproduz o holdout do baseline_v3)")
    ap.add_argument("--bpf-filter", default="udp",
                    help="filtro BPF para captura ao vivo (default: udp)")
    ap.add_argument("--max-packets", type=int, default=None,
                    help="limite de pacotes (debug)")
    ap.add_argument("--dump-features", default=None,
                    help="grava as linhas+features calculadas (debug/validacao)")
    ap.add_argument("--quiet-alerts", action="store_true")
    args = ap.parse_args()

    model = load_json(args.model)
    thresholds = _load_thresholds(model, args.thresholds, root)
    name = args.name or (Path(args.pcap).stem if args.pcap else "live")
    engine = LiveIDS(
        model, thresholds, args.out_dir, retro_window=args.retro_window,
        session_timeout=args.session_timeout,
        session_hold_timeout=args.session_hold_timeout,
        session_max_age=args.session_max_age,
        emit_from_index=args.emit_from_index,
        alert_stream=None if args.quiet_alerts else sys.stderr,
        prefix=name)
    engine.feature_dumper = _FeatureDumper(args.dump_features)
    print(f"[ids_live] modelo={args.model} identity={engine.identity} "
          f"avg_cold_start={engine.avg_cold_start} T={engine.retro_window}s "
          f"sessao={engine.session_timeout}s "
          f"hold_teto={engine.session_hold_timeout}s "
          f"max_idade={engine.session_max_age or 'off'}s "
          f"emit_from={engine.emit_from_index}",
          file=sys.stderr, flush=True)
    if not engine.session_max_age:
        print("[ids_live] NOTA: sem --session-max-age, uma stream que nunca "
              "fica inactiva mantem as suas linhas em memoria ate' ao fim do "
              "stream (ver docs/ids_live.md sec. 5.3).",
              file=sys.stderr, flush=True)

    if args.pcap:
        _run_pcap(args, engine, root)
    else:
        _run_interface(args, engine)
    if engine.feature_dumper is not None:
        engine.feature_dumper.close()

    s = engine.summary()
    print(f"[ids_live] {s['rows']} pacotes | ataque={s['attack']} "
          f"normal={s['normal']} | A1={s['alert_transition']} "
          f"| TP={s['tp']} FP={s['fp']}", file=sys.stderr)
    if s["attack"]:
        print(f"[ids_live] TPR={s['tpr']:.4f}", file=sys.stderr)
    if s["normal"]:
        print(f"[ids_live] FPR={s['fpr']:.4f}", file=sys.stderr)
    print(f"[ids_live] -> {engine.detect_path}", file=sys.stderr)
    print(f"[ids_live] -> {engine.retro_path}", file=sys.stderr)
    if s.get("sessions_hold_expired"):
        print(f"[ids_live] AVISO: {s['sessions_hold_expired']} sessoes em "
              f"espera fechadas por teto de "
              f"{engine.session_hold_timeout:.0f}s (V-C 1+3 nao disparou)",
              file=sys.stderr)
    # lado a maquina: uso de memoria/tempo por sessao (validacao de operacao)
    stats_path = Path(args.out_dir) / f"stats_{name}.json"
    stats_path.write_text(json.dumps(s, indent=2) + "\n")
    print(f"[ids_live] -> {stats_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
