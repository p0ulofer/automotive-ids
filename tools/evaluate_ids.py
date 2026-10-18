#!/usr/bin/env python3
"""Avaliacao da Fase 5 -- corre os dois algoritmos sobre os 11 ataques + os 3
normais, calcula TPR/FPR por dataset e agregado, a proporcao tempo-real/
retroativo e compara com os valores-alvo do artigo (Sec. VI).

Opcoes de experimento (cada uma aplicada ISOLADAMENTE sobre baseline_v1):
  * `--identity {mac,ip,ip_client}` -- E2 (mac = cenario-oraculo).
  * `--holdout FRAC`                -- E1: treina nos primeiros (1-FRAC) de cada
    normal e mede a FPR nos FRAC retidos (som temporal), mantendo os limiares de
    discretizacao da Fase 4 (aprendidos com 100% dos normais).

Uso:
    python3 tools/evaluate_ids.py --out results/exp_E1/report.json \
        --results-dir results/exp_E1 --holdout 0.3
    python3 tools/evaluate_ids.py --out results/exp_E2_ip/report.json \
        --results-dir results/exp_E2_ip --identity ip
    python3 tools/evaluate_ids.py --compare-baseline results/baseline_v1/evaluation_report.json
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ids_common import (  # noqa: E402
    ATTACK_DATASETS,
    DEFAULT_FEATURES_DIR,
    DEFAULT_MANIFEST,
    DEFAULT_THRESHOLDS,
    IDENTITIES,
    NORMAL_DATASETS,
    count_rows,
    load_json,
    save_json,
)
from ids_realtime import detect, train  # noqa: E402
from ids_retroactive import apply_retroactive  # noqa: E402

PAPER_TARGETS = {
    "tpr": 0.91,
    "fpr": 0.052,
    "pct_realtime": 18,
    "pct_retro": 82,
    "patterns_tpr1_fpr0": [5, 9],
    "note": ("11 dos 25 datasets do artigo; comparacao PARCIAL (conjunto menor "
             "e diferente), nao se pretende paridade numerica"),
}

CATEGORIES = ("ARR-Req", "ARR-Res", "ANEpc", "ANEc")


def category_of(name):
    for cat in CATEGORIES:
        if name.startswith(cat):
            return cat
    return "normal"


def _ratio(num, den):
    return num / den if den else None


def _pack(name, rsum, ssum):
    rt_tp = rsum.get("attack_flagged", 0)
    rt_fp = rsum.get("normal_flagged", 0)
    tot = ssum["final_flagged"]
    via_rt = ssum["via_realtime"]
    return {
        "category": category_of(name),
        "n_attack": ssum["attack"],
        "n_normal": ssum["normal"],
        "realtime": {"tp": rt_tp, "fp": rt_fp,
                     "tpr": _ratio(rt_tp, ssum["attack"]),
                     "fpr": _ratio(rt_fp, ssum["normal"])},
        "final": {"tp": ssum["attack_final"], "fp": ssum["normal_final"],
                  "tpr": _ratio(ssum["attack_final"], ssum["attack"]),
                  "fpr": _ratio(ssum["normal_final"], ssum["normal"])},
        "sessions": ssum["sessions"],
        "sessions_poisoned": ssum["sessions_poisoned"],
        "poisoned_realtime": ssum.get("poisoned_realtime", 0),
        "poisoned_session_interval": ssum.get("poisoned_session-interval", 0),
        "detections": {
            "total": tot, "via_realtime": via_rt, "via_retroactive": tot - via_rt,
            "pct_realtime": (100 * via_rt / tot) if tot else None,
        },
    }


def run_variant(variant, identity, holdout, feat_dir, results_dir,
                thresholds, manifest, do_train=True, session_source="timeout",
                payload_state=False, retro_window=None, payload_exclude=()):
    tag = f"{variant}_{identity}" + (f"_h{int(holdout*100)}" if holdout else "") \
        + ("" if session_source == "timeout" else f"_{session_source}")
    model_path = results_dir / f"realtime_model_{tag}.json"

    counts = {n: count_rows(feat_dir / f"{n}.csv") for n in NORMAL_DATASETS}
    specs = []
    for name in NORMAL_DATASETS:
        p = feat_dir / f"{name}.csv"
        if holdout > 0:
            cut = int(counts[name] * (1 - holdout))
            specs.append((p, lambda i, c=cut: i < c))
        else:
            specs.append(p)

    if do_train or not model_path.exists():
        train(specs, thresholds, manifest, model_path,
              avg_cold_start=variant, identity=identity, payload_state=payload_state,
              payload_exclude=payload_exclude)
    model = load_json(model_path)

    datasets = {}
    for name in NORMAL_DATASETS:
        p = feat_dir / f"{name}.csv"
        flt = None
        if holdout > 0:
            cut = int(counts[name] * (1 - holdout))
            flt = lambda i, c=cut: i >= c
        det_out = results_dir / f"realtime_{tag}_{name}.csv"
        retro_out = results_dir / f"retro_{tag}_{name}.csv"
        rsum, _ = detect(p, model, det_out, row_filter=flt,
                         session_source=session_source)
        ssum, _ = apply_retroactive(det_out, model, retro_out,
                                    session_source=session_source,
                                    retro_window=retro_window)
        datasets[name] = _pack(name, rsum, ssum)

    for name in ATTACK_DATASETS:
        p = feat_dir / f"{name}.csv"
        det_out = results_dir / f"realtime_{tag}_{name}.csv"
        retro_out = results_dir / f"retro_{tag}_{name}.csv"
        rsum, _ = detect(p, model, det_out, session_source=session_source)
        ssum, _ = apply_retroactive(det_out, model, retro_out,
                                    session_source=session_source,
                                    retro_window=retro_window)
        datasets[name] = _pack(name, rsum, ssum)

    meta = {"variant": variant, "identity": identity, "holdout": holdout,
            "session_source": session_source, "normal_rows": counts,
            "payload_state": payload_state, "retro_window": retro_window,
            "payload_exclude": list(payload_exclude),
            "model": str(model_path)}
    return model_path, datasets, meta


def aggregate(datasets):
    def sums(names, which):
        a = sum(datasets[n]["n_attack"] for n in names)
        n = sum(datasets[n]["n_normal"] for n in names)
        tp = sum(datasets[n][which]["tp"] for n in names)
        fp = sum(datasets[n][which]["fp"] for n in names)
        return {"n_attack": a, "n_normal": n, "tp": tp, "fp": fp,
                "tpr": _ratio(tp, a), "fpr": _ratio(fp, n)}

    attacks = [n for n in datasets if datasets[n]["n_attack"] > 0]
    normals = [n for n in datasets if datasets[n]["n_attack"] == 0]

    out = {}
    for which in ("realtime", "final"):
        agg_atk = sums(attacks, which)
        agg_nrm = sums(normals, which) if normals else {"n_normal": 0, "fp": 0}
        micro = {
            "n_attack": agg_atk["n_attack"], "tp": agg_atk["tp"],
            "tpr": agg_atk["tpr"],
            "n_normal_in_attacks": agg_atk["n_normal"],
            "fp_in_attacks": agg_atk["fp"],
            "fpr": _ratio(agg_atk["fp"], agg_atk["n_normal"]),
            "n_normal_only": agg_nrm["n_normal"], "fp_normal_only": agg_nrm["fp"],
            "fpr_normals_only": _ratio(agg_nrm["fp"], agg_nrm["n_normal"]),
            "fpr_all_normal": _ratio(agg_atk["fp"] + agg_nrm["fp"],
                                     agg_atk["n_normal"] + agg_nrm["n_normal"]),
        }
        tprs = [datasets[n][which]["tpr"] for n in attacks
                if datasets[n][which]["tpr"] is not None]
        fprs = [datasets[n][which]["fpr"] for n in attacks
                if datasets[n][which]["fpr"] is not None]
        micro["macro_tpr"] = sum(tprs) / len(tprs) if tprs else None
        micro["macro_fpr"] = sum(fprs) / len(fprs) if fprs else None
        micro["per_category"] = {}
        for cat in CATEGORIES:
            names = [n for n in attacks if datasets[n]["category"] == cat]
            if not names:
                continue
            agg = sums(names, which)
            f = [datasets[n][which]["fpr"] for n in names
                 if datasets[n][which]["fpr"] is not None]
            agg["macro_fpr"] = sum(f) / len(f) if f else None
            agg["datasets"] = names
            micro["per_category"][cat] = agg
        out[which] = micro

    tot = sum(datasets[n]["detections"]["total"] for n in attacks)
    via_rt = sum(datasets[n]["detections"]["via_realtime"] for n in attacks)
    out["detections"] = {
        "total": tot, "via_realtime": via_rt, "via_retroactive": tot - via_rt,
        "pct_realtime": (100 * via_rt / tot) if tot else None,
        "pct_retroactive": (100 * (tot - via_rt) / tot) if tot else None,
    }
    perfect = [n for n in attacks
               if datasets[n]["final"]["tpr"] == 1.0
               and datasets[n]["final"]["fpr"] == 0.0]
    out["patterns_perfect_tpr1_fpr0"] = {"n": len(perfect), "datasets": perfect}
    out["sessions_poisoned_by_interval"] = sum(
        datasets[n]["poisoned_session_interval"] for n in attacks)
    return out


def _fmt(x, nd=4):
    return "n/a" if x is None else f"{x:.{nd}f}"


def print_report(name, datasets, agg, meta):
    print(f"\n===== {name} (identity={meta['identity']}, "
          f"holdout={meta['holdout']}) =====")
    print(f"{'dataset':14s} {'cat':8s} {'atk':>5s} {'nrm':>7s} "
          f"{'A1 TPR':>7s} {'A1 FPR':>7s} {'fin TPR':>7s} {'fin FPR':>7s} {'rt%':>5s}")
    for n in datasets:
        d = datasets[n]
        rt = d["detections"]["pct_realtime"]
        print(f"{n:14s} {d['category']:8s} {d['n_attack']:5d} {d['n_normal']:7d} "
              f"{_fmt(d['realtime']['tpr']):>7s} {_fmt(d['realtime']['fpr']):>7s} "
              f"{_fmt(d['final']['tpr']):>7s} {_fmt(d['final']['fpr']):>7s} "
              f"{'n/a' if rt is None else f'{rt:.1f}':>5s}")
    f = agg["final"]
    print(f"AGREGADO: TPR={_fmt(f['tpr'])} | FPR(normais nos ataques)={_fmt(f['fpr'])} "
          f"| FPR(3 normais retidos)={_fmt(f['fpr_normals_only'])}")
    print(f"  macro TPR/FPR={_fmt(f['macro_tpr'])}/{_fmt(f['macro_fpr'])}")
    for cat, v in f["per_category"].items():
        print(f"  {cat:8s}: TPR={_fmt(v['tpr'])} FPR={_fmt(v['fpr'])} "
              f"(macro FPR={_fmt(v['macro_fpr'])})")
    d = agg["detections"]
    print(f"  deteccoes tempo-real={_fmt(d['pct_realtime'],1)}% "
          f"retroativo={_fmt(d['pct_retroactive'],1)}%")
    print(f"  sessoes marcadas por V-C3 (session-interval)={agg['sessions_poisoned_by_interval']}"
          f" | padroes TPR=1&FPR=0: {agg['patterns_perfect_tpr1_fpr0']['n']}/{len(datasets)-3}")


def compare_table(baseline_path, reports):
    """Tabela unica: baseline_v1 vs cada experimento (por categoria)."""
    base = load_json(baseline_path)
    cols = []
    for label, rep in reports:
        variants = list(rep["variants"].keys())
        v = variants[0] if len(variants) == 1 else "use"
        cols.append((label, rep["variants"][v]["aggregate"]))
    base_v = "use" if "use" in base["variants"] else list(base["variants"])[0]
    base_agg = base["variants"][base_v]["aggregate"]
    header = f"{'metrica':34s} {'baseline_v1':>14s}" + "".join(
        f"{lbl:>16s}" for lbl, _ in cols)
    print("\n" + header)
    print("-" * len(header))

    def row(label, getter):
        cells = [f"{_fmt(getter(base_agg)):>14s}"]
        cells += [f"{_fmt(getter(a)):>16s}" for _, a in cols]
        print(f"{label:34s}" + "".join(cells))

    row("TPR (micro, 11 ataques)", lambda a: a["final"]["tpr"])
    row("FPR (normais nos ataques)", lambda a: a["final"]["fpr"])
    row("FPR (3 normais retidos)", lambda a: a["final"]["fpr_normals_only"])
    for cat in CATEGORIES:
        row(f"  {cat} TPR", lambda a, c=cat: a["final"]["per_category"].get(c, {}).get("tpr"))
        row(f"  {cat} FPR", lambda a, c=cat: a["final"]["per_category"].get(c, {}).get("fpr"))
    row("% tempo-real (deteccoes)", lambda a: a["detections"]["pct_realtime"])
    row("% retroativo (deteccoes)", lambda a: a["detections"]["pct_retroactive"])
    row("padroes TPR=1 & FPR=0", lambda a: a["patterns_perfect_tpr1_fpr0"]["n"])


def main():
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--features-dir", default=str(root / DEFAULT_FEATURES_DIR))
    ap.add_argument("--thresholds", default=str(root / DEFAULT_THRESHOLDS))
    ap.add_argument("--manifest", default=str(root / DEFAULT_MANIFEST))
    ap.add_argument("--results-dir", default=str(root / "results"))
    ap.add_argument("--variant", choices=["use", "na", "both"], default="use")
    ap.add_argument("--identity", choices=list(IDENTITIES), default="mac")
    ap.add_argument("--holdout", type=float, default=0.0)
    ap.add_argument("--session-source", choices=["timeout", "sd"], default="timeout",
                    help="E4: delimitar sessoes por timeout ou por eventos SD")
    ap.add_argument("--retro-window", type=float, default=None,
                    help="R2/D2: janela T (s) de retroacao em torno do hit do "
                         "Algoritmo 1; omitido = literal (toda a sessao)")
    ap.add_argument("--payload-state", action="store_true",
                    help="E3: acrescentar o estado por sinal do payload a tupla")
    ap.add_argument("--payload-exclude", action="append", default=[], metavar="SINAL",
                    help="E3b: sinal de payload a retirar do estado (ex. seq)")
    ap.add_argument("--out", default=str(root / "results" / "evaluation_report.json"))
    ap.add_argument("--no-train", action="store_true")
    ap.add_argument("--compare-baseline", default=None,
                    help="imprime tabela unica vs. baseline e sai")
    args = ap.parse_args()

    if args.compare_baseline:
        reports = []
        for p in sorted(Path(args.results_dir).glob("*/report.json")):
            reports.append((p.parent.name, load_json(p)))
        compare_table(args.compare_baseline, reports)
        return

    feat_dir = Path(args.features_dir)
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    variants = ["use", "na"] if args.variant == "both" else [args.variant]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "tools/evaluate_ids.py",
        "paper_targets": PAPER_TARGETS,
        "training": NORMAL_DATASETS,
        "attack_datasets": ATTACK_DATASETS,
        "identity": args.identity,
        "holdout": args.holdout,
        "session_source": args.session_source,
        "payload_state": args.payload_state,
        "retro_window": args.retro_window,
        "payload_exclude": args.payload_exclude,
        "variants": {},
    }
    for v in variants:
        model_path, datasets, meta = run_variant(
            v, args.identity, args.holdout, feat_dir, results_dir,
            args.thresholds, args.manifest, do_train=not args.no_train,
            session_source=args.session_source, payload_state=args.payload_state,
            retro_window=args.retro_window, payload_exclude=args.payload_exclude)
        agg = aggregate(datasets)
        report["variants"][v] = {"model": str(model_path), "meta": meta,
                                 "datasets": datasets, "aggregate": agg}
        print_report(v, datasets, agg, meta)

    save_json(report, args.out)
    print(f"\n[report] -> {args.out}")


if __name__ == "__main__":
    main()
