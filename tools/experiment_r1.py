#!/usr/bin/env python3
"""R1/D2 -- treino mais justo (sem mexer no detetor) e FPR por fold.

Reporta a FPR do Algoritmo 1 (transicoes desconhecidas) e a FPR final (apos o
gatilho V-C 2) sobre os normais, em dois regimes de treino mais ricos que o
holdout 70/30 do baseline:

  * `holdout90` : treina nos primeiros 90% de cada normal, testa nos ultimos 10%.
  * `blocks5`   : 5 blocos temporais contiguos; treina em 4, testa no bloco
                  retido, rodando os 5 (cada pacote e' testado 1 vez, com ~80%
                  do normal no treino).

Decompoe a FPR final em: (i) FPR do Algoritmo 1 = *cobertura de treino*;
(ii) fator de amplificacao = FPR final / FPR do Algoritmo 1 (= gatilho V-C 2).

D2: `--retro-window T` reaplica so o Algoritmo 2 (com `--reuse-detect`) sobre os
mesmos CSVs do Algoritmo 1, para dar a FPR por fold com a janela T.

Uso:
    python3 tools/experiment_r1.py --mode blocks5 --identity ip \
        --out-dir results/exp_R1/blocks5_ip --out results/exp_R1/blocks5_ip/report.json
    python3 tools/experiment_r1.py --mode blocks5 --identity ip --retro-window 3 \
        --reuse-detect --detect-dir results/exp_R1/blocks5_ip \
        --out-dir results/exp_R1/blocks5T3_ip --out results/exp_R1/blocks5T3_ip/report.json
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ids_common import (  # noqa: E402
    ATTACK_DATASETS, DEFAULT_FEATURES_DIR, DEFAULT_MANIFEST, DEFAULT_THRESHOLDS,
    IDENTITIES, NORMAL_DATASETS, count_rows, load_json, save_json,
)
from ids_realtime import detect, train  # noqa: E402
from ids_retroactive import apply_retroactive  # noqa: E402


def _counts(detect_csv, retro_csv, kind):
    """kind='normal' (dataset normal) ou 'attack'. Contadores separados."""
    c = Counter()
    for r in csv.DictReader(open(detect_csv, newline="")):
        lab = r["label"]
        if lab == "0":
            c[f"{kind}_n"] += 1
            if r["checkable"] == "1":
                c[f"{kind}_checkable"] += 1
                if r["alert_transition"] == "1":
                    c[f"{kind}_a1_fp"] += 1
            if r["alert_transition"] == "1":
                c[f"{kind}_a1_fp_all"] += 1
        elif lab == "1":
            c["atk_n"] += 1
            if r["alert_transition"] == "1":
                c["atk_a1_tp"] += 1
    for r in csv.DictReader(open(retro_csv, newline="")):
        if r["final_anomaly"] != "1":
            continue
        if r["label"] == "0":
            c[f"{kind}_final_fp"] += 1
        elif r["label"] == "1":
            c["atk_final_tp"] += 1
    return c


def _rates(norm, atk):
    def r(num, den):
        return num / den if den else None
    fin = r(norm["normal_final_fp"], norm["normal_n"])
    a1 = r(norm["normal_a1_fp"], norm["normal_checkable"])
    return {
        "normals": {
            "n": norm["normal_n"], "checkable": norm["normal_checkable"],
            "a1_fp": norm["normal_a1_fp"], "a1_fpr": a1,
            "a1_fpr_all": r(norm["normal_a1_fp_all"], norm["normal_n"]),
            "final_fp": norm["normal_final_fp"], "final_fpr": fin,
            "amplification": (fin / a1 if a1 else None),
        },
        "attacks": {
            "n": atk["atk_n"], "a1_tp": atk["atk_a1_tp"], "final_tp": atk["atk_final_tp"],
            "a1_tpr": r(atk["atk_a1_tp"], atk["atk_n"]),
            "final_tpr": r(atk["atk_final_tp"], atk["atk_n"]),
        },
    }


def run(mode, identity, folds, holdout, feat_dir, detect_dir, results_dir,
        thresholds, manifest, payload_state=False, retro_window=None,
        reuse_detect=False):
    counts = {n: count_rows(feat_dir / f"{n}.csv") for n in NORMAL_DATASETS}
    K = folds if mode == "blocks5" else 1
    n_splits = K if mode == "blocks5" else 1

    fold_reports = []
    norm_pool, atk_pool = Counter(), Counter()
    for f in range(n_splits):
        specs, tests = [], {}
        for name in NORMAL_DATASETS:
            N = counts[name]
            p = feat_dir / f"{name}.csv"
            if mode == "blocks5":
                a, b = f * N // K, (f + 1) * N // K
                specs.append((p, lambda i, a=a, b=b: i < a or i >= b))
                tests[name] = lambda i, a=a, b=b: a <= i < b
            else:
                cut = int(N * (1 - holdout))
                specs.append((p, lambda i, c=cut: i < c))
                tests[name] = lambda i, c=cut: i >= c

        model_path = detect_dir / f"realtime_model_{mode}_{identity}_f{f}.json"
        if reuse_detect:
            model = load_json(model_path)
        else:
            train(specs, thresholds, manifest, model_path,
                  avg_cold_start="use", identity=identity,
                  payload_state=payload_state)
            model = load_json(model_path)

        norm, atk = Counter(), Counter()
        for name in NORMAL_DATASETS:
            det = detect_dir / f"realtime_{mode}_{identity}_f{f}_{name}.csv"
            retro = results_dir / f"retro_{mode}_{identity}_f{f}_{name}.csv"
            if not reuse_detect:
                detect(feat_dir / f"{name}.csv", model, det, row_filter=tests[name])
            apply_retroactive(det, model, retro, retro_window=retro_window)
            norm.update(_counts(det, retro, "normal"))
        for name in ATTACK_DATASETS:
            det = detect_dir / f"realtime_{mode}_{identity}_f{f}_{name}.csv"
            retro = results_dir / f"retro_{mode}_{identity}_f{f}_{name}.csv"
            if not reuse_detect:
                detect(feat_dir / f"{name}.csv", model, det)
            apply_retroactive(det, model, retro, retro_window=retro_window)
            atk.update(_counts(det, retro, "attack"))

        fold_reports.append({"fold": f, **_rates(norm, atk)})
        norm_pool.update(norm)
        atk_pool.update(atk)

    return {
        "mode": mode, "identity": identity, "folds": n_splits,
        "holdout": holdout, "payload_state": payload_state,
        "retro_window": retro_window,
        "per_fold": fold_reports,
        "pooled": _rates(norm_pool, atk_pool),
    }


def main():
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["holdout90", "blocks5"], required=True)
    ap.add_argument("--identity", choices=list(IDENTITIES), default="ip")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--holdout", type=float, default=0.1)
    ap.add_argument("--features-dir", default=str(root / DEFAULT_FEATURES_DIR))
    ap.add_argument("--thresholds", default=str(root / DEFAULT_THRESHOLDS))
    ap.add_argument("--manifest", default=str(root / DEFAULT_MANIFEST))
    ap.add_argument("--retro-window", type=float, default=None)
    ap.add_argument("--payload-state", action="store_true")
    ap.add_argument("--reuse-detect", action="store_true",
                    help="reusar modelos/CSVs do Algoritmo 1 em --detect-dir")
    ap.add_argument("--detect-dir", default=None,
                    help="onde estao modelo e CSVs do Algoritmo 1 (default: --out-dir)")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    results_dir = Path(args.out_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    detect_dir = Path(args.detect_dir) if args.detect_dir else results_dir
    summary = run(args.mode, args.identity, args.folds, args.holdout,
                  Path(args.features_dir), detect_dir, results_dir,
                  args.thresholds, args.manifest,
                  payload_state=args.payload_state,
                  retro_window=args.retro_window, reuse_detect=args.reuse_detect)

    def f(x): return " n/a " if x is None else f"{x:.4f}"
    print(f"\n===== R1 / {args.mode} / identity={args.identity} "
          f"retro_window={args.retro_window} =====\n")
    print(f"{'fold':>4s} {'norm_n':>9s} {'checkable':>10s} {'A1FP':>6s} "
          f"{'finFP':>8s} {'A1_FPR':>8s} {'fin_FPR':>8s} {'TPR':>7s}")
    for fr in summary["per_fold"]:
        n, a = fr["normals"], fr["attacks"]
        print(f"{fr['fold']:4d} {n['n']:9d} {n['checkable']:10d} {n['a1_fp']:6d} "
              f"{n['final_fp']:8d} {f(n['a1_fpr']):>8s} {f(n['final_fpr']):>8s} "
              f"{f(a['final_tpr']):>7s}")
    p = summary["pooled"]
    n, a = p["normals"], p["attacks"]
    amp = "n/a" if n["amplification"] is None else f"{n['amplification']:.1f}x"
    print(f"POOLED A1_FPR={f(n['a1_fpr'])} (sobre checkable; all={f(n['a1_fpr_all'])}) "
          f"| fin_FPR={f(n['final_fpr'])} | amplificacao fin/A1 = {amp}")
    print(f"       TPR final={f(a['final_tpr'])} (A1={f(a['a1_tpr'])})")
    save_json(summary, args.out)
    print(f"[R1] -> {args.out}")


if __name__ == "__main__":
    main()
