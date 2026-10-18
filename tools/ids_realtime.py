#!/usr/bin/env python3
"""Algoritmo 1 -- deteccao em tempo real (Koyama et al., Sec. V-B, Figs. 7 e 8).

Treina um modelo de maquina de estados por (Service ID, tipo de mensagem) nos
datasets NORMAIS e, na observacao, compara a tupla de estado de cada pacote com
a tabela de transicoes permitidas. Produz dois sinais distintos (Fig. 8):

  * `alert_transition` -- transicao desconhecida: a tupla de estado do pacote
    nao existe na tabela normal do seu (Service ID, tipo). E UMA anomalia de
    pacote (entra no TPR/FPR do Algoritmo 1).
  * `cs_armed`         -- o numero de remetentes do servico excedeu o maximo
    aprendido. NAO marca o pacote: apenas "arma" a avaliacao retroativa
    (Algoritmo 2, V-C 1+3), tal como o fluxo "Number of CSs ... ? -> Load
    retroactive detection algorithm" da Fig. 8.

Identidade do remetente (`--identity`, ver docs/ids_model.md):
  * `mac`       -- (src_ip, src_mac). CENARIO-ORACULO: o MAC so existe nos
    datasets de ataque, nunca nos normais; e uma entrada que o detetor nao
    pode ter (usado so como limite superior).
  * `ip`        -- (src_ip). "Sem MAC" principal.
  * `ip_client` -- (src_ip, client_id). "Sem MAC" alternativo.

O MAC e usado SOMENTE para `--identity mac` (oraculo); a etiqueta `label` ja
vem calculada na Fase 4 e nunca e entrada do detetor.

Variante de arranque da media movel (`--avg-cold-start`):
  * `use` (default) -- usa os bins das medias sempre que existem.
  * `na`            -- trata os bins das medias como N/A enquanto a janela W=10
                       nao estiver completa, em treino e deteccao.

Filtro de linhas (`row_filter`, usado no experimento E1): treino/teste podem
restringir-se a um intervalo de indices de linha (ex.: primeiros 70%).

Uso:
    python3 tools/ids_realtime.py train [options]
    python3 tools/ids_realtime.py detect --input features/ARR-Req-a1.csv [options]
    python3 tools/ids_realtime.py run --dataset ARR-Req-a1 [options]
"""
from __future__ import annotations

import argparse
import csv
import struct
import sys
from bisect import bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ids_common import (  # noqa: E402
    DEFAULT_FEATURES_DIR,
    DEFAULT_MANIFEST,
    DEFAULT_THRESHOLDS,
    IDENTITIES,
    NA,
    NORMAL_DATASETS,
    TUPLE_FEATURES,
    is_checkable,
    iter_rows,
    load_exclusions,
    load_json,
    save_json,
    sender_id,
    split_stream_key,
    state_str,
    state_tuple,
)

MODEL_VERSION = 3

DETECT_COLUMNS = [
    "idx", "timestamp", "label", "src_ip", "src_mac", "client_id", "sender_key",
    "service_id", "type_label", "stream_key", "n_cs", "sender_count", "cs_max",
    "cs_armed", "is_new_stream", "checkable", "avg_full", "state", "in_model",
    "alert_transition", "alert_flag", "dt_prev_res", "service_seg",
]


def _state(row, thresholds, excluded, avg_full, avg_cold_start):
    state = state_tuple(row, thresholds, excluded)
    if avg_cold_start == "na" and not avg_full:
        # componentes 2 e 3 = bins das medias (ver TUPLE_FEATURES)
        state = (state[0], state[1], "NA", "NA", state[4], state[5], state[6])
    return state


def _normalize_specs(specs):
    """Aceita [`path` | (`path`, filter)`] e devolve [(Path, filter|None)]."""
    out = []
    for s in specs:
        if isinstance(s, (tuple, list)):
            out.append((Path(s[0]), s[1]))
        else:
            out.append((Path(s), None))
    return out


# --------------------------------------------------------------------------- #
# E3 -- estado por sinal do payload (ver docs/feature_model.md sec. 7)
# --------------------------------------------------------------------------- #
#: Sinais por tipo de pacote (nome, natureza). `cont` = continuo -> componentes
#: "com/sem mudanca" + "faixa quantizada"; `enum` = enumerado -> "valor" +
#: "transicao" (valor anterior -> valor actual, na mesma stream_key).
#: Layout dos bit ranges: docs/payload_model.md sec. 1-2. Pacotes SD nao tem
#: payload de sinal -> nao acrescentam componentes.
_PAYLOAD_KINDS = {
    "NOTIFICATION": (("speed", "cont"), ("steer", "cont"), ("gear", "enum"),
                     ("brake", "enum"), ("acc", "enum"), ("turn", "enum")),
    "ECHO_REQ": (("seq", "cont"),),
    "SETMODE_REQ": (("mode", "enum"),),
    "RESPONSE": (("echo", "enum"), ("mode", "enum")),
}


def _payload_kind(row):
    """Tipo de payload do pacote (chave de `_PAYLOAD_KINDS`) ou None."""
    if row.get("is_sd") == "1":
        return None
    m = row.get("message_type_name", "")
    if m == "NOTIFICATION":
        return "NOTIFICATION"
    if m == "REQUEST":
        return "ECHO_REQ" if row.get("service_id") == "0x1234" else "SETMODE_REQ"
    if m == "RESPONSE":
        return "RESPONSE"
    return None


def _decode_payload(row, kind):
    """Valores dos sinais do pacote (`{nome: valor}`) ou None se ilegivel."""
    if kind is None:
        return None
    try:
        b = bytes.fromhex(row.get("payload_hex", ""))
    except ValueError:
        return None
    if kind == "NOTIFICATION":
        if len(b) < 8:
            return None
        return {"speed": int.from_bytes(b[0:2], "big"),
                "steer": int.from_bytes(b[2:4], "big", signed=True),
                "gear": b[4] & 0x0F, "brake": b[5] & 0x01,
                "acc": (b[6] >> 3) & 0x07, "turn": (b[7] >> 2) & 0x07}
    if kind == "ECHO_REQ":
        return {"seq": int.from_bytes(b[0:4], "big")} if len(b) >= 4 else None
    if kind == "SETMODE_REQ":
        return {"mode": b[0]} if len(b) >= 1 else None
    if kind == "RESPONSE":
        return {"echo": b[0], "mode": b[1]} if len(b) >= 2 else None
    return None


def _band(name, v, bands):
    b = bands.get(name) if bands else None
    if not b or v is None:
        return NA
    if v <= b[0]:
        return "low"
    return "mid" if v <= b[1] else "high"


def _payload_comps(row, prev, bands, excluded=frozenset()):
    """Componentes de estado do payload e novo `prev` da stream.

    `prev` = `{nome: valor}` do pacote anterior da mesma stream (ou None).
    `excluded` = nomes de sinais retirados do estado (E3b: contadores /
    identificadores monotonos, ex. `seq` do ECHO -- ver feature_model.md sec. 7.4).
    """
    kind = _payload_kind(row)
    if kind is None:
        return (), prev
    vals = _decode_payload(row, kind)
    comps = []
    new = dict(prev) if prev else {}
    for name, nat in _PAYLOAD_KINDS[kind]:
        if name in excluded:
            if vals is not None and vals.get(name) is not None:
                new[name] = vals[name]
            continue
        v = None if vals is None else vals.get(name)
        pv = (prev or {}).get(name)
        if vals is not None:
            new[name] = v
        if nat == "cont":
            chg = NA if (vals is None or pv is None) else (0 if pv == v else 1)
            comps.append(f"{name}:{chg}")
            comps.append(f"{name}:{_band(name, v, bands)}")
        else:
            comps.append(f"{name}={'NA' if v is None else v}")
            trans = "NA" if (pv is None or v is None) else f"{pv}>{v}"
            comps.append(f"{name}:{trans}")
    return tuple(comps), new


def _terciles(vals):
    s = sorted(vals)
    if not s:
        return None
    return [s[int(0.333 * (len(s) - 1))], s[int(0.667 * (len(s) - 1))]]


def _learn_payload_bands(specs, excluded=frozenset()):
    """Tercis por sinal continuo, aprendidos SO nos normais de treino."""
    vals = defaultdict(list)
    for path, row_filter in specs:
        for _idx, row in iter_rows(path, row_filter):
            if not is_checkable(row):
                continue
            kind = _payload_kind(row)
            if kind is None:
                continue
            d = _decode_payload(row, kind)
            if not d:
                continue
            for name, nat in _PAYLOAD_KINDS[kind]:
                if nat == "cont" and name not in excluded and d.get(name) is not None:
                    vals[name].append(d[name])
    return {k: b for k, v in vals.items() if (b := _terciles(v)) is not None}


def _seed_payload_prev(input_path, row_filter, excluded=frozenset()):
    """`prev` dos sinais no inicio da regiao processada (prefixo descartado)."""
    prev = {}
    if row_filter is None:
        return prev
    for idx, row in iter_rows(input_path):
        if row_filter(idx):
            break
        skey = row["stream_key"]
        _, prev[skey] = _payload_comps(row, prev.get(skey), None, excluded)
    return prev


# --------------------------------------------------------------------------- #
# treino
# --------------------------------------------------------------------------- #
def train(normal_specs, thresholds_path, manifest_path, out_path,
          avg_cold_start="use", identity="mac", payload_state=False,
          payload_exclude=frozenset()):
    specs = _normalize_specs(normal_specs)
    thresholds = load_json(thresholds_path)
    excluded = load_exclusions(manifest_path)
    window_w = int(thresholds.get("window_w", 10))
    payload_exclude = frozenset(payload_exclude)
    bands = _learn_payload_bands(specs, payload_exclude) if payload_state else {}

    transitions = {}                       # "svc|tipo" -> set(state_str)
    keys_by_service = {}                   # svc -> set(stream_key)
    senders_by_service = {}                # svc -> set(sender_id)
    rows = checked = 0

    for path, row_filter in specs:
        pos = {}                           # reinicia por captura (janela por stream)
        prev_sig = {}                      # E3: sinais do pacote anterior por stream
        for _idx, row in iter_rows(path, row_filter):
            rows += 1
            skey = row["stream_key"]
            svc, tl, _src = split_stream_key(skey)
            keys_by_service.setdefault(svc, set()).add(skey)
            senders_by_service.setdefault(svc, set()).add(sender_id(row, identity))
            pos[skey] = pos.get(skey, 0) + 1
            avg_full = (pos[skey] - 1) >= window_w
            if payload_state:
                comps, prev_sig[skey] = _payload_comps(
                    row, prev_sig.get(skey), bands, payload_exclude)
            if not is_checkable(row):
                continue
            checked += 1
            state = _state(row, thresholds, excluded, avg_full, avg_cold_start)
            if payload_state:
                state = state + comps
            transitions.setdefault(f"{svc}|{tl}", set()).add(state_str(state))

    model = {
        "version": MODEL_VERSION,
        "algorithm": "real-time state-transition (Koyama et al., Sec. V-B)",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "tools/ids_realtime.py",
        "trained_on": [p.stem for p, _ in specs],
        "thresholds_file": str(thresholds_path),
        "window_w": window_w,
        "avg_cold_start": avg_cold_start,
        "identity": identity,
        "payload_state": payload_state,
        "payload_bands": bands,
        "payload_exclude": sorted(payload_exclude),
        "excluded_os_keys": sorted(excluded),
        "tuple_features": TUPLE_FEATURES,
        "note_n_cs": ("CS = numero de remetentes distintos por servico segundo "
                      "`identity`; o n_cs da Fase 4 (stream_keys) nao e usado"),
        "services": {
            svc: {
                "max_senders": len(senders_by_service[svc]),
                "keys": sorted(keys_by_service[svc]),
            }
            for svc in sorted(keys_by_service)
        },
        "transitions": {k: sorted(v) for k, v in sorted(transitions.items())},
        "interval_model": {
            "dt_prev_res": {
                k: {"min": v["min"], "median": v["median"], "max": v["max"]}
                for k, v in sorted(thresholds.get("dt_prev_res", {}).items())
            }
        },
        "stats": {"rows_seen": rows, "checkable_transitions": checked},
    }
    save_json(model, out_path)

    print(f"[train] {len(specs)} normais: {rows} linhas, {checked} transicoes; "
          f"identity={identity} avg-cold-start={avg_cold_start} "
          f"payload-state={payload_state}", file=sys.stderr)
    print(f"[train] max_senders={ {k: v['max_senders'] for k, v in model['services'].items()} }",
          file=sys.stderr)
    print(f"[train] modelo -> {out_path}", file=sys.stderr)
    return model


# --------------------------------------------------------------------------- #
# delimitacao de sessao por eventos SD (experimento E4)
# --------------------------------------------------------------------------- #
_SD_OFFER = 0x01        # OfferService  (TTL=0 -> StopOfferService)
_SD_SUBSCRIBE = 0x06    # SubscribeEventgroup (TTL=0 -> Stop/Unsubscribe)


def _iter_sd_subscription_events(input_path, row_filter=None):
    """Devolve `(svc, ts, ttl)` por cada entry Offer/Subscribe num pacote SD.

    O `service_id` do pacote SD e' 0xFFFF; o servico visado esta' em cada entry
    (bytes [4..5]). O TTL (bytes [9..11]) distingue renovacao (TTL>0) de
    StopOffer/StopSubscribe (TTL=0).
    """
    for _idx, row in iter_rows(input_path, row_filter):
        if row.get("is_sd") != "1":
            continue
        try:
            b = bytes.fromhex(row.get("payload_hex", ""))
        except ValueError:
            continue
        if len(b) < 8:
            continue
        elen = struct.unpack(">I", b[4:8])[0]
        off, end = 8, min(8 + elen, len(b))
        ts = float(row["timestamp"])
        while off + 16 <= end:
            e = b[off:off + 16]
            if e[0] in (_SD_OFFER, _SD_SUBSCRIBE):
                svc = struct.unpack(">H", e[4:6])[0]
                ttl = int.from_bytes(e[9:12], "big")
                yield f"0x{svc:04X}", ts, ttl
            off += 16


def sd_service_boundaries(input_path, row_filter=None):
    """Instantes que FECHAM uma sessao de servico, por Service ID.

    Semantica SOME/IP-SD: um Offer/Subscribe com TTL>0 renova a "concessao" do
    servico ate' `ts+TTL`; um StopOffer/StopSubscribe (TTL=0) fecha a sessao
    nesse instante; se a concessao expirar sem renovacao, a sessao termina no
    instante de expiracao. Devolve `{svc: [instantes ordenados]}`.
    """
    events = defaultdict(list)
    for svc, ts, ttl in _iter_sd_subscription_events(input_path, row_filter):
        events[svc].append((ts, ttl))
    bounds = {}
    for svc, evs in events.items():
        evs.sort()
        out, on, until = [], False, 0.0
        for ts, ttl in evs:
            if not on:
                if ttl > 0:
                    on, until = True, ts + ttl
            elif ttl == 0:
                out.append(ts)
                on = False
            elif ts > until:
                out.append(until)
                until = ts + ttl
            else:
                until = max(until, ts + ttl)
        bounds[svc] = out
    return bounds


# --------------------------------------------------------------------------- #
# deteccao
# --------------------------------------------------------------------------- #
def detect(input_path, model, out_path, row_filter=None, session_source="timeout"):
    thresholds = load_json(model["thresholds_file"])
    excluded = set(model["excluded_os_keys"])
    services = model["services"]
    transitions = {k: set(v) for k, v in model["transitions"].items()}
    window_w = int(model.get("window_w", 10))
    avg_cold_start = model.get("avg_cold_start", "use")
    identity = model.get("identity", "mac")
    payload_state = bool(model.get("payload_state", False))
    bands = model.get("payload_bands", {})
    payload_exclude = frozenset(model.get("payload_exclude", []))

    seen_keys = set()
    senders_seen = {}                      # svc -> set(sender_id)
    pos = {}
    summary = Counter()
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    # E3: sinais do pacote anterior por stream (semeado no prefixo descartado
    # pelo `row_filter`, para a 1.a linha do holdout ja ter transicao).
    prev_sig = (_seed_payload_prev(input_path, row_filter, payload_exclude)
                if payload_state else {})

    # E4: sessões delimitadas por eventos SD (renovação/TTL/StopOffer/StopSubscribe).
    # `service_seg` = índice do segmento (0 = 1.a sessão) do Service ID desse pacote.
    sd_bounds = (sd_service_boundaries(input_path, row_filter)
                 if session_source == "sd" else {})

    with open(out_path, "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(DETECT_COLUMNS)
        for idx, row in iter_rows(input_path, row_filter):
            skey = row["stream_key"]
            svc, tl, src = split_stream_key(skey)
            sid = sender_id(row, identity)
            is_new_stream = skey not in seen_keys
            seen_keys.add(skey)
            senders_seen.setdefault(svc, set()).add(sid)
            sender_count = len(senders_seen[svc])
            cs_max = services.get(svc, {}).get("max_senders", 10 ** 9)
            cs_armed = bool(sender_count > cs_max)

            pos[skey] = pos.get(skey, 0) + 1
            avg_full = (pos[skey] - 1) >= window_w
            checkable = is_checkable(row)
            state = _state(row, thresholds, excluded, avg_full, avg_cold_start)
            if payload_state:
                comps, prev_sig[skey] = _payload_comps(
                    row, prev_sig.get(skey), bands, payload_exclude)
                state = state + comps
            sstr = state_str(state)
            in_model = sstr in transitions.get(f"{svc}|{tl}", set())
            alert_transition = bool(checkable and not in_model)
            label = row.get("label", "")
            seg = (bisect_right(sd_bounds.get(svc, ()), float(row["timestamp"]))
                   if session_source == "sd" else 0)

            writer.writerow([
                idx, row["timestamp"], label, src, row.get("src_mac", ""),
                row.get("client_id", ""), sid, svc, tl, skey, row["n_cs"],
                sender_count, cs_max, int(cs_armed), int(is_new_stream),
                int(checkable), int(avg_full), sstr, int(in_model),
                int(alert_transition), int(alert_transition),
                row.get("dt_prev_res", ""), seg,
            ])

            summary["rows"] += 1
            if label == "1":
                summary["attack"] += 1
                summary["attack_flagged" if alert_transition else "attack_missed"] += 1
            elif label == "0":
                summary["normal"] += 1
                summary["normal_flagged" if alert_transition else "normal_ok"] += 1
            if alert_transition:
                summary["alert_transition"] += 1
            if cs_armed:
                summary["cs_armed_packets"] += 1
    summary["services_cs_armed"] = sum(
        1 for svc in senders_seen
        if len(senders_seen[svc]) > services.get(svc, {}).get("max_senders", 10 ** 9))
    return summary, out_path


def _print_summary(name, s, model):
    a, n = s.get("attack", 0), s.get("normal", 0)
    tp, fp = s.get("attack_flagged", 0), s.get("normal_flagged", 0)
    tpr = tp / a if a else float("nan")
    fpr = fp / n if n else float("nan")
    print(f"[detect] {name} (identity={model.get('identity','mac')}, "
          f"avg-cold-start={model.get('avg_cold_start','use')}): "
          f"{s.get('rows',0)} pacotes (ataque={a}, normal={n})")
    print(f"         transition={s.get('alert_transition',0)} | TP={tp} FP={fp} "
          f"TPR={tpr:.4f} FPR={fpr:.4f} | servicos com CS armado="
          f"{s.get('services_cs_armed',0)}")


def main():
    root = Path(__file__).resolve().parent.parent
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--features-dir", default=str(root / DEFAULT_FEATURES_DIR))
    common.add_argument("--thresholds", default=str(root / DEFAULT_THRESHOLDS))
    common.add_argument("--manifest", default=str(root / DEFAULT_MANIFEST))
    common.add_argument("--model", default=str(root / "results" / "realtime_model.json"))
    common.add_argument("--avg-cold-start", choices=["use", "na"], default="use")
    common.add_argument("--identity", choices=list(IDENTITIES), default="mac")
    common.add_argument("--payload-state", action="store_true",
                        help="E3: acrescentar o estado por sinal do payload a tupla")
    common.add_argument("--payload-exclude", action="append", default=[], metavar="SINAL",
                        help="E3b: sinal de payload a retirar do estado (ex. seq)")
    common.add_argument("--session-source", choices=["timeout", "sd"], default="timeout",
                        help="E4: delimitar sessoes por timeout de inatividade ou por eventos SD")
    common.add_argument("--out", default=None)

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_train = sub.add_parser("train", parents=[common])
    p_train.add_argument("--normal", action="append", default=[], metavar="NOME")
    p_det = sub.add_parser("detect", parents=[common])
    p_det.add_argument("--input", required=True)
    p_run = sub.add_parser("run", parents=[common])
    p_run.add_argument("--dataset", action="append", required=True, metavar="NOME")
    p_run.add_argument("--force-train", action="store_true")

    args = ap.parse_args()
    feat = Path(args.features_dir)

    if args.cmd == "train":
        normals = args.normal or NORMAL_DATASETS
        paths = [feat / f"{n}.csv" for n in normals]
        for p in paths:
            if not p.exists():
                sys.exit(f"ERRO: {p} nao existe")
        train(paths, args.thresholds, args.manifest, args.model,
              avg_cold_start=args.avg_cold_start, identity=args.identity,
              payload_state=args.payload_state,
              payload_exclude=args.payload_exclude)
        return

    if args.cmd == "detect":
        model = load_json(args.model)
        out = args.out or str(root / "results" / f"realtime_{Path(args.input).stem}.csv")
        s, out_path = detect(args.input, model, out,
                             session_source=args.session_source)
        _print_summary(Path(args.input).stem, s, model)
        print(f"[detect] -> {out_path}")
        return

    if args.cmd == "run":
        if args.force_train or not Path(args.model).exists():
            paths = [feat / f"{n}.csv" for n in NORMAL_DATASETS]
            train(paths, args.thresholds, args.manifest, args.model,
                  avg_cold_start=args.avg_cold_start, identity=args.identity,
                  payload_state=args.payload_state,
                  payload_exclude=args.payload_exclude)
        model = load_json(args.model)
        for name in args.dataset:
            inp = feat / f"{name}.csv"
            if not inp.exists():
                sys.exit(f"ERRO: {inp} nao existe")
            out = str(root / "results" / f"realtime_{name}.csv")
            s, _ = detect(inp, model, out)
            _print_summary(name, s, model)


if __name__ == "__main__":
    main()
