#!/usr/bin/env python3
"""Algoritmo 2 -- deteccao retroativa (Koyama et al., Sec. V-C).

Reavalia a sessao inteira quando ha sinal de anomalia. Consome o CSV por
pacote produzido pelo Algoritmo 1 (`results/realtime_<dataset>.csv`).

Definicao de SESSAO (o artigo nao a fixa; ver docs/ids_model.md):
  sessao = (Service ID, identidade do remetente), onde a identidade e' a do
  modelo do Algoritmo 1 (`mac`/`ip`/`ip_client`) -- ver `--identity`. A sessao e'
  truncada por um timeout de inatividade (SESSION_TIMEOUT, default 10 s), ou por
  eventos SD (experimento E4, ainda nao implementado).

Os tres gatilhos do artigo (item -> implementacao):

  V-C 2) Um pacote marcado anómalo em tempo real (`alert_transition`) ->
         marca TODOS os pacotes anteriores da mesma sessao e todos os
         seguintes ("all future packets from the same sender").
         Gatilho: `realtime`.
  V-C 1+3) Numero anómalo de CSs (n.o de remetentes do servico > max aprendido)
         NAO marca sozinho: apenas arma a avaliacao. No fim da sessao, se o
         servico excedeu os CSs E o intervalo medio da sessao desvia do modelo
         normal, a sessao inteira e marcada. Gatilho: `session-interval`.
         O desvio e avaliado por tipo de mensagem dentro da sessao (comparacao
         com os anchors [min,max] de dt_prev_res da Fase 4), para nao colar o
         intervalo bimodal de uma sessao servidor (responses + notifications).

Uso:
    python3 tools/ids_retroactive.py apply \\
        --detect results/realtime_ARR-Req-a1.csv \\
        --model results/realtime_model.json \\
        --out results/retro_ARR-Req-a1.csv
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ids_common import load_json, save_json  # noqa: E402

SESSION_TIMEOUT = 10.0  # s de inatividade que fecha uma sessao (decisao de projeto)

RETRO_COLUMNS = [
    "idx", "timestamp", "label", "service_id", "src_ip", "src_mac", "type_label",
    "stream_key", "dt_prev_res", "alert_transition", "cs_armed", "session_key",
    "session_mean_dt_res", "session_deviates", "poisoned_by",
    "retro_anomaly", "final_anomaly", "service_seg",
]


def apply_retroactive(detect_path, model, out_path, session_timeout=SESSION_TIMEOUT,
                      session_source="timeout", retro_window=None):
    rows = list(csv.DictReader(open(detect_path, newline="")))
    interval = model.get("interval_model", {}).get("dt_prev_res", {})

    # ---- sessões: (svc, identidade) -----------------------------------------
    # `timeout` (default): truncadas por inatividade (SESSION_TIMEOUT).
    # `sd` (E4): truncadas pelos segmentos SD calculados pelo Algoritmo 1
    #            (`service_seg`: StopOffer/StopSubscribe ou expiração de TTL).
    session_of = {}                        # posicao -> session_key
    sessions = defaultdict(list)           # session_key -> [posicao]
    last_ts = {}
    counter = defaultdict(int)
    for pos, r in enumerate(rows):
        svc = r["service_id"]
        ts = float(r["timestamp"])
        if session_source == "sd":
            skey = f"{svc}|{r['sender_key']}|s{r.get('service_seg', 0) or 0}"
        else:
            base = f"{svc}|{r['sender_key']}"    # sender_key = identidade do modelo
            if base in last_ts and ts - last_ts[base] > session_timeout:
                counter[base] += 1
            last_ts[base] = ts
            skey = f"{base}#{counter[base]}"
        session_of[pos] = skey
        sessions[skey].append(pos)

    # ---- CS por serviço: excedeu o máximo aprendido? -----------------------
    service_cs_exceeded = defaultdict(bool)
    for r in rows:
        if r["cs_armed"] == "1":
            service_cs_exceeded[r["service_id"]] = True

    # ---- gatilho V-C 2: pacote marcado em tempo real -----------------------
    # `retro_window=None` -> literal (toda a sessão) = baseline_v2. Com T>0 s, a
    # retroação (contágio) cobre apenas `|ts - ts_hit| <= T` em torno de cada hit
    # do Algoritmo 1 da mesma sessão (o próprio hit é sempre "direto").
    hits = defaultdict(list)               # session_key -> [ts dos hits]
    for pos, r in enumerate(rows):
        if r["alert_transition"] == "1":
            hits[session_of[pos]].append(float(r["timestamp"]))

    # ---- gatilho V-C 1+3: fim de sessão ------------------------------------
    session_mean = {}
    session_dev = {}
    interval_poisoned = set()
    for skey, poss in sessions.items():
        svc = skey.split("|")[0]
        by_type = defaultdict(list)
        for p in poss:
            v = rows[p]["dt_prev_res"]
            if v not in ("", None):
                by_type[rows[p]["type_label"]].append(float(v))
        deviates = False
        means = {}
        for tl, vals in by_type.items():
            m = sum(vals) / len(vals)
            means[tl] = m
            anchor = interval.get(f"{svc}|{tl}")
            if anchor and (m < anchor["min"] or m > anchor["max"]):
                deviates = True
        session_dev[skey] = deviates
        session_mean[skey] = means
        if deviates and service_cs_exceeded.get(svc, False):
            interval_poisoned.add(skey)     # V-C3: marca a sessão inteira

    # ---- saída por pacote ---------------------------------------------------
    summary = Counter()
    marked_sessions = set()
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(RETRO_COLUMNS)
        for pos, r in enumerate(rows):
            i = int(r["idx"])
            skey = session_of[pos]
            ts = float(r["timestamp"])
            realtime = r["alert_transition"] == "1"
            retro = False
            trigger = ""
            if skey in interval_poisoned:
                retro, trigger = True, "session-interval"
            elif skey in hits:
                if retro_window is None:
                    retro, trigger = True, "realtime"
                elif any(abs(ts - h) <= retro_window for h in hits[skey]):
                    retro, trigger = True, "realtime-window"
            final = bool(realtime or retro)
            if final:
                marked_sessions.add(skey)
            means = session_mean.get(skey, {})
            mean_val = means.get(r["type_label"], "")
            writer.writerow([
                i, r["timestamp"], r["label"], r["service_id"], r["src_ip"],
                r["src_mac"], r["type_label"], r["stream_key"],
                r["dt_prev_res"], r["alert_transition"], r["cs_armed"], skey,
                f"{mean_val:.6f}" if mean_val != "" else "",
                int(session_dev.get(skey, False)),
                ("realtime" if realtime else trigger),
                int(retro), int(final), r.get("service_seg", 0),
            ])
            # métricas
            if final:
                summary["final_flagged"] += 1
                summary["via_realtime" if realtime else "via_retro"] += 1
            if r["label"] == "1":
                summary["attack"] += 1
                summary["attack_final"] += final
                summary["attack_realtime"] += realtime
            elif r["label"] == "0":
                summary["normal"] += 1
                summary["normal_final"] += final
                summary["normal_realtime"] += realtime
    summary["sessions"] = len(sessions)
    summary["sessions_marked"] = len(marked_sessions)
    summary["sessions_poisoned"] = len(marked_sessions)
    summary["sessions_with_hits"] = len(hits)
    summary["vc3_condition_met"] = len(interval_poisoned)
    summary["poisoned_realtime"] = len(hits)
    # "novas" sessões devidas a V-C 3 (as que V-C 2 não marcaria sozinho)
    summary["poisoned_session-interval"] = len(interval_poisoned - set(hits))
    return summary, out_path


def _print_summary(name, s):
    a, n = s["attack"], s["normal"]
    tp, fp = s["attack_final"], s["normal_final"]
    tpr = tp / a if a else float("nan")
    fpr = fp / n if n else float("nan")
    tot = s["final_flagged"]
    rt = s["via_realtime"]
    print(f"[retro] {name}: {s['sessions']} sessoes ({s['sessions_poisoned']} marcadas)")
    print(f"        TP={tp} FP={fp} TPR={tpr:.4f} FPR={fpr:.4f}")
    print(f"        sessoes marcadas por gatilho: "
          f"realtime={s.get('poisoned_realtime',0)} "
          f"session-interval={s.get('poisoned_session-interval',0)}")
    if tot:
        print(f"        deteccoes: tempo-real={rt} ({100*rt/tot:.1f}%)  "
              f"retroativo={tot-rt} ({100*(tot-rt)/tot:.1f}%)")


def main():
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("apply")
    p.add_argument("--detect", required=True)
    p.add_argument("--model", default=str(root / "results" / "realtime_model.json"))
    p.add_argument("--out", default=None)
    p.add_argument("--session-timeout", type=float, default=SESSION_TIMEOUT)
    p.add_argument("--session-source", choices=["timeout", "sd"], default="timeout",
                   help="E4: 'timeout' (inatividade) ou 'sd' (segmentos SD do Algoritmo 1)")
    p.add_argument("--retro-window", type=float, default=None,
                   help="R2:janela T (s) de retroacao em torno do hit; omitido = literal "
                        "(toda a sessao, baseline_v2)")
    args = ap.parse_args()

    model = load_json(args.model)
    out = args.out or str(root / "results" /
                          f"retro_{Path(args.detect).stem.replace('realtime_','')}.csv")
    s, out_path = apply_retroactive(args.detect, model, out,
                                    session_timeout=args.session_timeout,
                                    session_source=args.session_source,
                                    retro_window=args.retro_window)
    name = Path(args.detect).stem.replace("realtime_", "")
    _print_summary(name, s)
    print(f"[retro] -> {out_path}")


if __name__ == "__main__":
    main()
