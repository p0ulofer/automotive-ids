#!/usr/bin/env python3
"""Logica de features de transicao partilhada (Fase 4 / Fase 5 / Fase 6).

Este modulo contem APENAS o calculo das features da Tabela IV de Koyama et al.
(VTC2022-Spring) a partir de linhas SOME/IP ja descodificadas. E usado por:

  * `tools/extract_features.py` -- pipeline offline/batch (Fase 4);
  * `tools/ids_live.py`         -- pipeline online (Fase 6).

Manter uma unica implementacao e' deliberado: o modo online tem de calcular
exactamente as mesmas features que validaram o `baseline_v3` offline.

Estado incremental por `stream_key` = (Service ID, tipo, remetente):
  - ultimo timestamp (dt_prev_res);
  - ultimo Session-ID (os);
  - ultimo payload (dp_prev_res);
  - deque W=10 dos ultimos dT nao-nulos (medias moveis);
  - ultimo REQUEST por servico/remetente (dt/dp_prev_req);
  - streams de sessao abertas por Service ID (n_cs).

O primeiro pacote de cada stream nao tem referencia: as features relativas ao
pacote anterior ficam N/A ("cold start"), tal como documentado no modo offline.
"""
from __future__ import annotations

from collections import defaultdict, deque

WINDOW_W = 10  # janela deslizante das medias de dT (artigo nao especifica)

FEATURE_COLS = [
    "dt_prev_req", "dt_prev_res",
    "dt_prev_req_avg", "dt_prev_res_avg",
    "dt_prev_req_bin", "dt_prev_res_bin",
    "dp_prev_req", "dp_prev_res",
    "dp_prev_req_l1", "dp_prev_res_l1",
    "n_cs", "os", "stream_key",
]

SD_PORT_TYPES = ("Offer", "Find", "Subscribe", "SubAck")


def type_label(is_sd, message_type_name, sd_entry_types):
    """Tipo do pacote para a chave de transicao (Tabela IV / Sec. V-B)."""
    if is_sd:
        parts = [p for p in (sd_entry_types or "").split(";") if p]
        names = sorted({p.rsplit("x", 1)[0] for p in parts})
        return "SD:" + "+".join(names) if names else "SD:?"
    return message_type_name or "?"


def in_order_session(a, b):
    """Session-ID em ordem estrita: prev+1 ou wraparound 0xFFFF -> 0x0000/0x0001."""
    if b == (a + 1) & 0xFFFF:
        return True
    if a == 0xFFFF and b in (0x0000, 0x0001):
        return True
    return False


def continuous_range(payload_len, tl):
    """Bytes CONTINUOS do payload do pacote ATUAL (docs/payload_model.md §1-2).

    NOTIFICATION/REQUEST 16 B: Speed+Steering (bytes 0-3) / contador ECHO.
    RESPONSE 4 B: byte 0 (eco do contador). REQUEST 2 B (SetMode): nenhum
    campo continuo -> comparar payload completo (fallback).
    """
    if tl == "NOTIFICATION" and payload_len >= 4:
        return (0, 4)
    if tl == "REQUEST" and payload_len >= 4:
        return (0, 4)
    if tl == "RESPONSE" and payload_len >= 1:
        return (0, 1)
    return None


def dp_l1(cur, ref):
    """Soma L1 das diferencas de byte sobre a sobreposicao dos dois payloads."""
    n = min(len(cur), len(ref))
    return sum(abs(cur[i] - ref[i]) for i in range(n))


def dp_cat(cur, ref, tl):
    """0 = sem mudanca / 1 = com mudanca nos campos CONTINUOS do payload."""
    n = min(len(cur), len(ref))
    if n == 0:
        return None
    cont = continuous_range(len(cur), tl)
    if cont is None:
        idxs = range(n)
    else:
        idxs = [i for i in range(cont[0], cont[1]) if i < n]
        if not idxs:
            idxs = range(n)
    return 1 if any(cur[i] != ref[i] for i in idxs) else 0


class StreamState:
    """Estado por stream_key = (Service ID, tipo, remetente)."""

    __slots__ = ("last_t", "last_session", "last_payload",
                 "dt_req_deque", "dt_res_deque")

    def __init__(self):
        self.last_t = None
        self.last_session = None
        self.last_payload = None
        self.dt_req_deque = deque(maxlen=WINDOW_W)
        self.dt_res_deque = deque(maxlen=WINDOW_W)


class Extractor:
    """Calcula features de transicao incrementalmente, linha a linha."""

    def __init__(self, thresholds=None, collect=None):
        # thresholds: {"dt_prev_req": {"SVC|TIPO": {...}}, "dt_prev_res": {...}}
        self.thresholds = thresholds or {"dt_prev_req": {}, "dt_prev_res": {}}
        self.collect = collect  # {"dt_prev_req": {key: [vals]}, ...} p/ aprendizagem
        self.streams = {}
        self.last_req_svc = {}     # svc -> (t, payload)
        self.last_req_sender = {}  # (svc, src) -> (t, payload)
        self.open_keys = defaultdict(set)  # svc -> chaves de sessao abertas
        self.na_counts = defaultdict(int)

    def _bin(self, dt, feat, svc, tl):
        if dt is None:
            return ""
        th = self.thresholds.get(feat, {}).get(f"{svc}|{tl}")
        if th is None:
            return ""
        if dt <= th["b1"]:
            return "short"
        if dt <= th["b2"]:
            return "medium"
        return "long"

    def process(self, row):
        ts = float(row["timestamp"])
        svc = row["service_id"]
        src = row["src_ip"]
        tl = type_label(row["is_sd"] == "1", row.get("message_type_name"),
                        row.get("sd_entry_types"))
        session = int(row["session_id"], 16)
        payload = bytes.fromhex(row["payload_hex"]) if row["payload_hex"] else b""
        key = (svc, tl, src)

        st = self.streams.get(key)
        if st is None:
            st = self.streams[key] = StreamState()

        # --- dt_prev_res / os / sessao (referencia = pacote anterior da stream)
        if st.last_t is None:
            dt_res = None
            os_val = None
            session_start = True
            prev_payload = None
        else:
            dt_res = ts - st.last_t
            os_val = 1 if in_order_session(st.last_session, session) else 0
            session_start = (not in_order_session(st.last_session, session)
                             and session < st.last_session)
            prev_payload = st.last_payload

        # --- dt_prev_req / dp_prev_req (referencia = REQUEST anterior)
        if tl == "REQUEST":
            ref = self.last_req_sender.get((svc, src))
        else:
            ref = self.last_req_svc.get(svc)
        if ref is None:
            dt_req = None
            dp_req_cat = None
            dp_req_l1 = None
        else:
            dt_req = ts - ref[0]
            dp_req_cat = dp_cat(payload, ref[1], tl)
            dp_req_l1 = dp_l1(payload, ref[1])

        # --- dp_prev_res
        if prev_payload is None and st.last_t is not None:
            # stream existe mas payload de referencia ausente (nao ocorre aqui)
            dp_res_cat = None
            dp_res_l1 = None
        elif st.last_t is None:
            dp_res_cat = None
            dp_res_l1 = None
        else:
            dp_res_cat = dp_cat(payload, prev_payload, tl)
            dp_res_l1 = dp_l1(payload, prev_payload)

        # --- medias moveis (valor atual excluido; ultimos W nao-nulos da stream)
        avg_req = (sum(st.dt_req_deque) / len(st.dt_req_deque)
                   if st.dt_req_deque else None)
        avg_res = (sum(st.dt_res_deque) / len(st.dt_res_deque)
                   if st.dt_res_deque else None)

        # --- n_cs: streams de sessao abertas do Service ID
        if key not in self.open_keys[svc]:
            self.open_keys[svc].add(key)  # nova stream; restart nao altera (supersede)
        n_cs = len(self.open_keys[svc])

        # --- bins
        bin_req = self._bin(dt_req, "dt_prev_req", svc, tl)
        bin_res = self._bin(dt_res, "dt_prev_res", svc, tl)

        # --- aprendizagem (somente datasets normais)
        if self.collect is not None:
            if dt_req is not None:
                self.collect["dt_prev_req"].setdefault(f"{svc}|{tl}", []).append(dt_req)
            if dt_res is not None:
                self.collect["dt_prev_res"].setdefault(f"{svc}|{tl}", []).append(dt_res)

        # --- update de estado
        if tl == "REQUEST":
            self.last_req_svc[svc] = (ts, payload)
            self.last_req_sender[(svc, src)] = (ts, payload)
        if dt_req is not None:
            st.dt_req_deque.append(dt_req)
        if dt_res is not None:
            st.dt_res_deque.append(dt_res)
        st.last_t = ts
        st.last_session = session
        st.last_payload = payload

        feats = {
            "dt_prev_req": dt_req, "dt_prev_res": dt_res,
            "dt_prev_req_avg": avg_req, "dt_prev_res_avg": avg_res,
            "dt_prev_req_bin": bin_req, "dt_prev_res_bin": bin_res,
            "dp_prev_req": dp_req_cat, "dp_prev_res": dp_res_cat,
            "dp_prev_req_l1": dp_req_l1, "dp_prev_res_l1": dp_res_l1,
            "n_cs": n_cs, "os": os_val,
            "stream_key": f"{svc}|{tl}|{src}",
        }
        for col in FEATURE_COLS:
            if feats[col] is None:
                self.na_counts[col] += 1
        return feats


def fmt(col, val):
    """Formata um valor de feature como no CSV offline (None -> vazio)."""
    if val is None:
        return ""
    if col in ("dt_prev_req", "dt_prev_res", "dt_prev_req_avg", "dt_prev_res_avg"):
        return f"{val:.6f}"
    return str(val)
