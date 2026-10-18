#!/usr/bin/env python3
"""R2 -- curva de amplificacao do gatilho V-C 2 (janela T) vs literal.

Reutiliza os CSVs por-pacote do Algoritmo 1 ja produzidos (baseline_v2); so
re-corre o Algoritmo 2 com uma `--retro-window` diferente. Variantes isoladas:

  * `literal` : toda a sessao (baseline_v2).
  * `T1`/`T5`/`T30` : contagio limitado a `|ts - ts_hit| <= T` em torno de cada
    hit do Algoritmo 1 da mesma sessao.

Reporta, por variante: TPR/FPR por pacote, TPR/FPR por sessao, e a fracao
direta vs contagio. NAO escolhe T.

Uso:
    python3 tools/experiment_r2.py --detect-dir results/baseline_v2/ip \
        --out-dir results/exp_R2/ip --out results/exp_R2/ip/report.json
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ids_common import ATTACK_DATASETS, NORMAL_DATASETS, load_json, save_json  # noqa: E402
from ids_retroactive import apply_retroactive  # noqa: E402
from diagnose_ids import detect_path  # noqa: E402

VARIANTS = [("literal", None), ("T1", 1.0), ("T3", 3.0), ("T5", 5.0), ("T30", 30.0)]


def _session_and_packet_metrics(retro_csv):
    c = Counter()
    sessions = defaultdict(lambda: {"n0": 0, "n1": 0, "marked": False,
                                    "hits0": 0, "hits1": 0})
    for r in csv.DictReader(open(retro_csv, newline="")):
        lab, final = r["label"], r["final_anomaly"] == "1"
        direct = r["alert_transition"] == "1"
        contagion = final and not direct
        if lab == "1":
            c["attack"] += 1
            c["attack_final"] += final
            c["attack_direct"] += direct
            c["attack_contagion"] += contagion
        elif lab == "0":
            c["normal"] += 1
            c["normal_final"] += final
            c["normal_direct"] += direct
            c["normal_contagion"] += contagion
        s = sessions[r["session_key"]]
        if lab == "1":
            s["n1"] += 1
        elif lab == "0":
            s["n0"] += 1
        if final:
            s["marked"] = True
        if direct:
            if lab == "1":
                s["hits1"] += 1
            else:
                s["hits0"] += 1
    # contagio por origem do envenenamento
    for r in csv.DictReader(open(retro_csv, newline="")):
        if r["final_anomaly"] != "1" or r["alert_transition"] == "1":
            continue
        s = sessions[r["session_key"]]
        origin = "attack" if s["hits1"] > 0 else ("normal" if s["hits0"] > 0 else "none")
        if r["label"] == "1":
            c[f"attack_contagion_{origin}"] += 1
        elif r["label"] == "0":
            c[f"normal_contagion_{origin}"] += 1
    pure_a = [s for s in sessions.values() if s["n1"] > 0 and s["n0"] == 0]
    pure_n = [s for s in sessions.values() if s["n0"] > 0 and s["n1"] == 0]
    mixed = [s for s in sessions.values() if s["n0"] > 0 and s["n1"] > 0]
    c["sess_total"] = len(sessions)
    c["sess_pure_attack"] = len(pure_a)
    c["sess_pure_attack_marked"] = sum(s["marked"] for s in pure_a)
    c["sess_pure_normal"] = len(pure_n)
    c["sess_pure_normal_marked"] = sum(s["marked"] for s in pure_n)
    c["sess_mixed"] = len(mixed)
    c["sess_mixed_marked"] = sum(s["marked"] for s in mixed)
    return dict(c)


def run(detect_dir, model, out_dir):
    detect_dir = Path(detect_dir)
    out = {}
    for vname, T in VARIANTS:
        vdir = Path(out_dir) / vname
        vdir.mkdir(parents=True, exist_ok=True)
        agg = Counter()
        per_ds = {}
        for name in ATTACK_DATASETS + NORMAL_DATASETS:
            det = detect_path(detect_dir, name)
            retro_csv = vdir / f"retro_{vname}_{name}.csv"
            apply_retroactive(det, model, retro_csv, retro_window=T)
            c = _session_and_packet_metrics(retro_csv)
            per_ds[name] = c
            agg.update(c)
        out[vname] = {"retro_window_s": T, "per_dataset": per_ds,
                      "aggregate": dict(agg)}
    return out


def _agg_view(v):
    """Agrega ataques vs normais-retidos."""
    a = v["per_dataset"]
    atk = [n for n in ATTACK_DATASETS]
    na = sum(a[n]["attack"] for n in atk)
    tp = sum(a[n]["attack_final"] for n in atk)
    direct_tp = sum(a[n]["attack_direct"] for n in atk)
    cont_tp = sum(a[n]["attack_contagion"] for n in atk)
    na_n = sum(a[n]["normal"] for n in atk)
    fp = sum(a[n]["normal_final"] for n in atk)
    direct_fp = sum(a[n]["normal_direct"] for n in atk)
    cont_fp = sum(a[n]["normal_contagion"] for n in atk)
    nn = sum(a[n]["normal"] for n in NORMAL_DATASETS)
    fpn = sum(a[n]["normal_final"] for n in NORMAL_DATASETS)
    pa = sum(a[n]["sess_pure_attack"] for n in atk)
    pam = sum(a[n]["sess_pure_attack_marked"] for n in atk)
    pn = sum(a[n]["sess_pure_normal"] for n in atk)
    pnm = sum(a[n]["sess_pure_normal_marked"] for n in atk)
    mx = sum(a[n]["sess_mixed"] for n in atk)
    mxm = sum(a[n]["sess_mixed_marked"] for n in atk)
    return {
        "attack": {"n": na, "tp": tp, "tpr": tp / na if na else None,
                   "direct": direct_tp, "contagion": cont_tp,
                   "pct_direct": 100 * direct_tp / tp if tp else None},
        "normal_in_attacks": {"n": na_n, "fp": fp, "fpr": fp / na_n if na_n else None,
                              "direct": direct_fp, "contagion": cont_fp,
                              "pct_direct": 100 * direct_fp / fp if fp else None},
        "normals_only": {"n": nn, "fp": fpn, "fpr": fpn / nn if nn else None},
        "sessions": {"pure_attack": pa, "pure_attack_marked": pam,
                     "pure_normal": pn, "pure_normal_marked": pnm,
                     "mixed": mx, "mixed_marked": mxm},
        "contagion_tp_origin": {
            "attack": sum(a[n].get("attack_contagion_attack", 0) for n in atk),
            "normal": sum(a[n].get("attack_contagion_normal", 0) for n in atk)},
        "contagion_fp_origin": {
            "attack": sum(a[n].get("normal_contagion_attack", 0) for n in atk),
            "normal": sum(a[n].get("normal_contagion_normal", 0) for n in atk)},
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--detect-dir", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    model = load_json(args.model)
    res = run(args.detect_dir, model, args.out_dir)
    views = {k: {**v, "view": _agg_view(v)} for k, v in res.items()}
    ident = Path(args.detect_dir).name
    report = {"identity": ident, "detect_dir": args.detect_dir,
              "model": args.model, "variants": views}

    def f(x): return " n/a " if x is None else f"{x:.4f}"
    print(f"\n===== R2 ({ident}) -- V-C 2: literal vs janela T =====")
    print(f"{'variante':9s} {'TPR':>7s} {'FPR':>7s} {'FPR_nrm':>8s} "
          f"{'TP_d':>6s} {'TP_c':>6s} {'FP_d':>6s} {'FP_c':>6s} "
          f"{'sessA':>7s} {'sessN':>9s} {'sessM':>7s}")
    for k in ("literal", "T1", "T3", "T5", "T30"):
        w = views[k]["view"]
        a, n, s = w["attack"], w["normal_in_attacks"], w["sessions"]
        print(f"{k:9s} {f(a['tpr']):>7s} {f(n['fpr']):>7s} {f(w['normals_only']['fpr']):>8s} "
              f"{a['direct']:6d} {a['contagion']:6d} {n['direct']:6d} {n['contagion']:6d} "
              f"{s['pure_attack_marked']}/{s['pure_attack']:<5d} "
              f"{s['pure_normal_marked']}/{s['pure_normal']:<7d} "
              f"{s['mixed_marked']}/{s['mixed']:<5d}")

    if args.out:
        save_json(report, args.out)
        print(f"[R2] -> {args.out}")


if __name__ == "__main__":
    main()
