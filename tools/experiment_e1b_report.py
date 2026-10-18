#!/usr/bin/env python3
"""E1b -- tabela de tres colunas: baseline_v3 (frozen) | Control | E1b.

Isolamento do experimento E1b (limiares de discretizacao da Fase 4):
  * `baseline_v3` -- valores CONGELADOS (protocolo E1 + sem MAC, T=3 s);
  * `Control`     -- re-corrido agora sobre as MESMAS features que o v3
                     (limiares 100 %) -- deve coincidir com o v3, exceto o
                     dataset `ARR-Req-a1` que foi regenerado (o ficheiro de
                     entrada tinha sido substituido por um smoke run);
  * `E1b`         -- limiares reaprendidos so nos primeiros 70 % de cada normal.

Comparar `E1b` com `Control` isola o efeito dos limiares (mesmos dados);
comparar com `baseline_v3` e' a comparacao pedida, com a ressalva do `ARR-Req-a1`.

Le os `report.json` (nao re-corre nada) e imprime TPR/FPR por pacote, TPR
direta (Algoritmo 1) vs contagio e o detalhe por categoria.

Uso:
    python3 tools/experiment_e1b_report.py \
        --baseline results/baseline_v3 \
        --control results/exp_E1b --experiment results/exp_E1b \
        --out results/exp_E1b/E1b_vs_baseline_v3.json
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ids_common import NORMAL_DATASETS, load_json, save_json  # noqa: E402

CATEGORIES = ("ARR-Req", "ARR-Res", "ANEpc", "ANEc")


def _a1_from_csvs(results_dir):
    """A1 FP no holdout dos normais, lido dos CSVs do Algoritmo 1."""
    c = {"checkable": 0, "a1_fp": 0}
    for name in NORMAL_DATASETS:
        hits = sorted(Path(results_dir).glob(f"realtime_*_{name}.csv"))
        if not hits:
            continue
        for r in csv.DictReader(open(hits[0], newline="")):
            if r.get("label") == "0" and r.get("checkable") == "1":
                c["checkable"] += 1
                if r.get("alert_transition") == "1":
                    c["a1_fp"] += 1
    return c


def _cat(datasets, report):
    out = {}
    for cat in CATEGORIES:
        names = [n for n in report["attack_datasets"] if n.startswith(cat)]
        if not names:
            continue
        a = sum(datasets[n]["n_attack"] for n in names)
        dir_tp = sum(datasets[n]["realtime"]["tp"] for n in names)
        fin_tp = sum(datasets[n]["final"]["tp"] for n in names)
        fin_fp = sum(datasets[n]["final"]["fp"] for n in names)
        nn = sum(datasets[n]["n_normal"] for n in names)
        out[cat] = {
            "n_attack": a,
            "direct_tp": dir_tp, "direct_tpr": dir_tp / a if a else None,
            "final_tp": fin_tp, "final_tpr": fin_tp / a if a else None,
            "contagion_tp": fin_tp - dir_tp,
            "final_fp": fin_fp, "final_fpr": fin_fp / nn if nn else None,
        }
    return out


def summarize(results_dir, kind):
    results_dir = Path(results_dir)
    rep = load_json(results_dir / "report.json")
    v = "use" if "use" in rep["variants"] else list(rep["variants"])[0]
    agg = rep["variants"][v]["aggregate"]
    ds = rep["variants"][v]["datasets"]
    a1 = _a1_from_csvs(results_dir)
    f = agg["final"]
    d = agg["realtime"]
    return {
        "kind": kind, "results_dir": str(results_dir),
        "retro_window": rep.get("retro_window"), "identity": rep.get("identity"),
        "a1_fp": a1["a1_fp"], "a1_checkable": a1["checkable"],
        "a1_fpr_checkable": a1["a1_fp"] / a1["checkable"] if a1["checkable"] else None,
        "tpr_direct": d["tpr"],
        "tpr": f["tpr"],
        "direct_tp": d["tp"],
        "contagion_tp": f["tp"] - d["tp"],
        "pct_direct_of_tp": (d["tp"] / f["tp"]) if f["tp"] else None,
        "pct_contagion_of_tp": ((f["tp"] - d["tp"]) / f["tp"]) if f["tp"] else None,
        "fpr_normals_only": f["fpr_normals_only"],
        "fpr_in_attacks": f["fpr"],
        "pct_realtime": agg["detections"]["pct_realtime"],
        "patterns_perfect": agg["patterns_perfect_tpr1_fpr0"]["n"],
        "by_category": _cat(ds, rep),
    }


def fmt(x, nd=4):
    return "n/a" if x is None else f"{x:.{nd}f}"


def main():
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", default=str(root / "results" / "baseline_v3"))
    ap.add_argument("--control", default=str(root / "results" / "exp_E1b"))
    ap.add_argument("--experiment", default=str(root / "results" / "exp_E1b"))
    ap.add_argument("--out", default=str(root / "results" / "exp_E1b" / "E1b_vs_baseline_v3.json"))
    args = ap.parse_args()

    out = {"categories": list(CATEGORIES), "identities": {}}
    for ident in ("ip", "ip_client"):
        out["identities"][ident] = {
            "baseline_v3": summarize(Path(args.baseline) / ident, "baseline_v3"),
            "control": summarize(Path(args.control) / f"control_{ident}", "control"),
            "E1b": summarize(Path(args.experiment) / ident, "E1b"),
        }

    rows = [
        ("A1 FP (normais, holdout)", "a1_fp", None),
        ("A1 FPR (sobre checkable)", "a1_fpr_checkable", 6),
        ("TPR direta A1 (micro)", "tpr_direct", 4),
        ("TPR final (micro)", "tpr", 4),
        ("TP diretos (pacotes)", "direct_tp", None),
        ("TP contagio (pacotes)", "contagion_tp", None),
        ("% diretos do TP final", "pct_direct_of_tp", 4),
        ("% contagio do TP final", "pct_contagion_of_tp", 4),
        ("FPR final (3 normais)", "fpr_normals_only", 4),
        ("FPR final (normais nos ataques)", "fpr_in_attacks", 4),
        ("% deteccoes tempo-real", "pct_realtime", 1),
        ("padroes TPR=1 & FPR=0", "patterns_perfect", None),
    ]

    for ident, d in out["identities"].items():
        b, c, e = d["baseline_v3"], d["control"], d["E1b"]
        print(f"\n===== E1b  identity={ident}  (T={b['retro_window']}s, holdout=0.3) =====")
        print(f"{'metrica':36s} {'baseline_v3':>12s} {'Control':>12s} {'E1b':>12s}")
        for lbl, key, nd in rows:
            f = (lambda x: str(x)) if nd is None else (lambda x, n=nd: fmt(x, n))
            print(f"{lbl:36s} {f(b[key]):>12s} {f(c[key]):>12s} {f(e[key]):>12s}")
        print("  -- por categoria (direct TPR | final TPR | final FPR) --")
        for cat in CATEGORIES:
            if cat not in e["by_category"]:
                continue
            bc, cc, ec = b["by_category"][cat], c["by_category"][cat], e["by_category"][cat]
            print(f"  {cat:8s} dir {fmt(bc['direct_tpr'])}|{fmt(cc['direct_tpr'])}|{fmt(ec['direct_tpr'])}"
                  f"   fin {fmt(bc['final_tpr'])}|{fmt(cc['final_tpr'])}|{fmt(ec['final_tpr'])}"
                  f"   fpr {fmt(bc['final_fpr'])}|{fmt(cc['final_fpr'])}|{fmt(ec['final_fpr'])}")

    save_json(out, args.out)
    print(f"\n[E1b] -> {args.out}")


if __name__ == "__main__":
    main()
