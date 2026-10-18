#!/usr/bin/env python3
"""D2/E3 -- tabela unica: baseline_v3 (T=3 s, sem payload) vs E3 (T=3 s + payload).

Le os `report.json` congelados (nao re-corre nada) e escreve um JSON + imprime
a tabela com os numeros pedidos: TPR direta (Algoritmo 1), FPR do Algoritmo 1
(contagem de FP), TPR/FPR final, por categoria.

Uso:
    python3 tools/experiment_e3_report.py \
        --baseline results/baseline_v3 --experiment results/exp_E3 \
        --out results/exp_E3/E3_vs_baseline_v3.json
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ids_common import ATTACK_DATASETS, NORMAL_DATASETS, load_json, save_json  # noqa: E402

CATEGORIES = ("ARR-Req", "ARR-Res", "ANEpc", "ANEc")


def _a1_from_csvs(results_dir):
    """A1 FP/checkable lidos dos CSVs do Algoritmo 1 (denominador checkable)."""
    c = {"checkable": 0, "a1_fp": 0, "normal": 0, "a1_tp": 0, "attack": 0}
    for name in NORMAL_DATASETS:
        hits = sorted(Path(results_dir).glob(f"realtime_*_{name}.csv"))
        for r in csv.DictReader(open(hits[0], newline="")):
            if r["label"] == "0":
                c["normal"] += 1
                if r["checkable"] == "1":
                    c["checkable"] += 1
                    if r["alert_transition"] == "1":
                        c["a1_fp"] += 1
    return c


def _cat(datasets, report):
    """Por categoria: TPR direta (Algoritmo 1) e TPR/FPR final."""
    out = {}
    for cat in CATEGORIES:
        names = [n for n in report["attack_datasets"] if n.startswith(cat)]
        if not names:
            continue
        a = sum(datasets[n]["n_attack"] for n in names)
        rt_tp = sum(datasets[n]["realtime"]["tp"] for n in names)
        fin_tp = sum(datasets[n]["final"]["tp"] for n in names)
        fin_fp = sum(datasets[n]["final"]["fp"] for n in names)
        nn = sum(datasets[n]["n_normal"] for n in names)
        out[cat] = {
            "n_attack": a, "direct_tp": rt_tp,
            "direct_tpr": rt_tp / a if a else None,
            "final_tp": fin_tp, "final_tpr": fin_tp / a if a else None,
            "final_fp": fin_fp, "final_fpr": fin_fp / nn if nn else None,
        }
    return out


def summarize(results_dir, report_path, kind):
    rep = load_json(report_path)
    v = "use" if "use" in rep["variants"] else list(rep["variants"])[0]
    agg = rep["variants"][v]["aggregate"]
    ds = rep["variants"][v]["datasets"]
    a1 = _a1_from_csvs(results_dir)
    f = agg["final"]
    return {
        "kind": kind,
        "results_dir": str(results_dir),
        "payload_state": rep.get("payload_state"),
        "retro_window": rep.get("retro_window"),
        "identity": rep.get("identity"),
        "a1": {
            "fp": a1["a1_fp"], "checkable": a1["checkable"],
            "fpr_checkable": a1["a1_fp"] / a1["checkable"] if a1["checkable"] else None,
            "tpr_direct": agg["realtime"]["tpr"],
        },
        "final": {
            "tpr": f["tpr"],
            "fpr_normals_only": f["fpr_normals_only"],
            "fpr_in_attacks": f["fpr"],
            "fp_normals_only": f["fp_normal_only"],
        },
        "detections": agg["detections"],
        "patterns_perfect": agg["patterns_perfect_tpr1_fpr0"]["n"],
        "by_category": _cat(ds, rep),
    }


def main():
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", default=str(root / "results" / "baseline_v3"))
    ap.add_argument("--experiment", default=str(root / "results" / "exp_E3"))
    ap.add_argument("--out", default=str(root / "results" / "exp_E3" / "E3_vs_baseline_v3.json"))
    args = ap.parse_args()

    out = {"categories": list(CATEGORIES), "identities": {}}
    for ident in ("ip", "ip_client"):
        base = summarize(Path(args.baseline) / ident,
                         Path(args.baseline) / ident / "report.json", "baseline_v3")
        e3 = summarize(Path(args.experiment) / ident,
                       Path(args.experiment) / ident / "report.json", "E3")
        out["identities"][ident] = {"baseline_v3": base, "E3": e3}

    def f(x, nd=4):
        return "n/a" if x is None else f"{x:.{nd}f}"

    for ident, d in out["identities"].items():
        b, e = d["baseline_v3"], d["E3"]
        print(f"\n===== D2/E3  identity={ident} =====")
        print(f"{'metrica':30s} {'baseline_v3':>14s} {'E3':>14s}")
        rows = [
            ("A1 FP (normais holdout)", b["a1"]["fp"], e["a1"]["fp"]),
            ("A1 FPR (sobre checkable)", f(b["a1"]["fpr_checkable"], 6), f(e["a1"]["fpr_checkable"], 6)),
            ("TPR direta (Alg. 1, micro)", f(b["a1"]["tpr_direct"]), f(e["a1"]["tpr_direct"])),
            ("TPR final (micro)", f(b["final"]["tpr"]), f(e["final"]["tpr"])),
            ("FPR final (3 normais)", f(b["final"]["fpr_normals_only"]), f(e["final"]["fpr_normals_only"])),
            ("FPR final (normais nos ataques)", f(b["final"]["fpr_in_attacks"]), f(e["final"]["fpr_in_attacks"])),
            ("% detecoes tempo-real", f(b["detections"]["pct_realtime"], 1), f(e["detections"]["pct_realtime"], 1)),
            ("padroes TPR=1 & FPR=0", b["patterns_perfect"], e["patterns_perfect"]),
        ]
        for lbl, bb, ee in rows:
            print(f"{lbl:30s} {str(bb):>14s} {str(ee):>14s}")
        print(f"{'-- por categoria --':30s}")
        for cat in CATEGORIES:
            if cat not in e["by_category"]:
                continue
            bc, ec = b["by_category"][cat], e["by_category"][cat]
            print(f"  {cat:8s} TPR dir  {f(bc['direct_tpr'])} -> {f(ec['direct_tpr'])}"
                  f" | TPR fin {f(bc['final_tpr'])} -> {f(ec['final_tpr'])}"
                  f" | FPR fin {f(bc['final_fpr'])} -> {f(ec['final_fpr'])}")

    save_json(out, args.out)
    print(f"\n[E3] -> {args.out}")


if __name__ == "__main__":
    main()
