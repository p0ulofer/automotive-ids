#!/usr/bin/env python3
"""Compara uma execucao AO VIVO (rede real) com o baseline congelado.

Usado no Estagio B: o `ids_live.py` captura o trafego replayado com
`tools/replay_pcap_live.py` (temporismo original, stack de rede real) e este
script confronta o resultado com o `baseline_v3` congelado.

Ao contrario do replay deterministico (`--pcap` do `ids_live.py`), aqui os
timestamps medidos sao os de CAPTURA, logo ha' jitter: o objectivo nao e' dar
0 diffs, e' **quantificar** o desvio e a sua causa.

Saidas:
  * atraso fim-a-fim por pacote (`t_capturado - t_original`) e o seu jitter
    (variacao em torno da mediana);
  * features que mudaram de bin (`dt_prev_res` e respectivos bins) e de quanto;
  * linhas de classificacao que divergem do baseline, por coluna;
  * metricas (TP/FP/TPR/FPR) de ambos.

Uso:
    python3 tools/compare_live_replay.py \\
        --live-dir results/ids_live_stageB/ANEpc-a1 \\
        --dataset ANEpc-a1 \\
        --out-json results/ids_live_stageB/compare_ANEpc-a1.json
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Colunas de classificacao (as que determinam o veredito).
CLASS_COLS = ("state", "in_model", "checkable", "avg_full", "alert_transition",
              "alert_flag", "cs_armed", "n_cs", "sender_count", "cs_max",
              "is_new_stream", "dt_prev_res", "type_label", "stream_key",
              "service_id", "src_ip")
# Colunas de metadados (excluidas do veredicto).
META_COLS = ("src_mac", "label")


def load(path: Path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def by_idx(rows):
    return {r["idx"]: r for r in rows}


def metrics(rows):
    atk = [r for r in rows if r.get("label") == "1"]
    nor = [r for r in rows if r.get("label") == "0"]
    final = [r for r in rows if r.get("final_anomaly") == "1"]
    return {
        "rows": len(rows),
        "attack": len(atk), "normal": len(nor),
        "alert_transition": sum(1 for r in rows
                                if r.get("alert_transition") == "1"),
        "final_flagged": len(final),
        "tp_final": sum(1 for r in atk if r.get("final_anomaly") == "1"),
        "fp_final": sum(1 for r in nor if r.get("final_anomaly") == "1"),
        "tpr_final": (sum(1 for r in atk if r.get("final_anomaly") == "1")
                      / len(atk)) if atk else None,
        "fpr_final": (sum(1 for r in nor if r.get("final_anomaly") == "1")
                      / len(nor)) if nor else None,
    }


def compare_sets(base_rows, live_rows, cols):
    """Conta diferencas celula-a-celula por coluna.

    Alinha pelo campo `idx` quando existe (ficheiros de deteccao); caso
    contrario alinha por POSICAO (ficheiros de features, que nao tem `idx`).
    """
    has_idx = bool(base_rows) and "idx" in base_rows[0]
    if has_idx:
        b, l = by_idx(base_rows), by_idx(live_rows)
        pairs = [(i, b[i], l[i]) for i in sorted(set(b) & set(l), key=int)]
    else:
        n = min(len(base_rows), len(live_rows))
        pairs = [(i, base_rows[i], live_rows[i]) for i in range(n)]
    per = Counter()
    examples = []
    for idx, brow, lrow in pairs:
        for c in cols:
            if brow.get(c) != lrow.get(c):
                per[c] += 1
                if len(examples) < 40:
                    examples.append({"idx": idx, "column": c,
                                     "baseline": brow.get(c),
                                     "live": lrow.get(c),
                                     "timestamp": brow.get("timestamp")})
    return {"rows_compared": len(pairs),
            "rows_baseline": len(base_rows), "rows_live": len(live_rows),
            "alignment": "idx" if has_idx else "posicao",
            "per_column": dict(per),
            "total_cell_diffs": sum(per.values()),
            "rows_with_diff": sum(1 for idx, brow, lrow in pairs
                                  if any(brow.get(c) != lrow.get(c)
                                         for c in cols)),
            "examples": examples}


def main():
    ap = argparse.ArgumentParser(
        description="Quantifica o desvio entre uma captura ao vivo e o "
                    "baseline congelado (Estagio B).")
    ap.add_argument("--live-dir", required=True,
                    help="pasta com realtime_<nome>.csv / retro_<nome>.csv")
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--baseline-dir", default="results/baseline_v3/ip")
    ap.add_argument("--features", default=None,
                    help="CSV de features congelado (features/<ds>.csv) para "
                         "comparar as features calculadas ao vivo")
    ap.add_argument("--live-features", default=None,
                    help="CSV de features do dump do ids_live")
    ap.add_argument("--out-json", default=None)
    args = ap.parse_args()

    live_dir = Path(args.live_dir)
    if not live_dir.is_absolute():
        live_dir = ROOT / live_dir
    baseline = ROOT / args.baseline_dir

    name = args.dataset
    b_rt = sorted(baseline.glob(f"realtime_use_ip_*_{name}.csv"))
    b_ro = sorted(baseline.glob(f"retro_use_ip_*_{name}.csv"))
    if not b_rt or not b_ro:
        raise SystemExit(f"sem baseline para {name} em {baseline}")
    l_rt = live_dir / f"realtime_{name}.csv"
    l_ro = live_dir / f"retro_{name}.csv"
    for p in (l_rt, l_ro):
        if not p.exists():
            raise SystemExit(f"faltam os ficheiros ao vivo: {p}")

    report = {
        "tool": "tools/compare_live_replay.py",
        "dataset": name,
        "live_dir": str(live_dir),
        "baseline": str(baseline),
    }

    # ---- deriva da linha temporal e jitter ------------------------------
    # O atraso tem de ser RELATIVO ao primeiro pacote de cada serie: as
    # capturas existem em epocas diferentes (o dataset congelado e' antigo),
    # logo so' a deriva dos intervalos inter-pacote e' comparavel.
    b_rt_rows, l_rt_rows = load(b_rt[0]), load(l_rt)
    b_by, l_by = by_idx(b_rt_rows), by_idx(l_rt_rows)
    common = sorted(set(b_by) & set(l_by), key=int)
    delays_ms = []
    if common:
        t0_b = float(b_by[common[0]]["timestamp"])
        t0_l = float(l_by[common[0]]["timestamp"])
        for idx in common:
            d = ((float(l_by[idx]["timestamp"]) - t0_l)
                 - (float(b_by[idx]["timestamp"]) - t0_b)) * 1000
            delays_ms.append(d)
    if delays_ms:
        med = statistics.median(delays_ms)
        jit = [d - med for d in delays_ms]
        report["timing"] = {
            "rows": len(delays_ms),
            "delay_ms": {
                "median": med,
                "mean": statistics.fmean(delays_ms),
                "p95": sorted(delays_ms)[int(0.95 * (len(delays_ms) - 1))],
                "max": max(delays_ms),
                "min": min(delays_ms),
            },
            "jitter_ms": {
                "median_abs": statistics.median([abs(j) for j in jit]),
                "p95_abs": sorted(abs(j) for j in jit)[
                    int(0.95 * (len(jit) - 1))],
                "max_abs": max(abs(j) for j in jit),
                "stdev": statistics.pstdev(jit),
            },
        }

    # ---- features ------------------------------------------------------
    lf = args.live_features
    if lf is None:
        cand = live_dir / "features.csv"
        lf = str(cand) if cand.exists() else None
    if lf and args.features:
        f_base = load(ROOT / args.features)
        f_live = load(Path(lf))
        fcols = ("dt_prev_res", "dt_prev_res_avg", "dt_prev_res_bin",
                 "dt_prev_req", "dt_prev_req_avg", "dt_prev_req_bin",
                 "n_cs", "os", "stream_key")
        report["features"] = compare_sets(f_base, f_live, fcols)
        # quanto variou o dt_prev_res (em ms) nas linhas que mudaram
        deltas = []
        for i in range(min(len(f_base), len(f_live))):
            a = f_base[i].get("dt_prev_res", "")
            c = f_live[i].get("dt_prev_res", "")
            if a not in ("", None) and c not in ("", None):
                deltas.append(abs(float(c) - float(a)) * 1000)
        if deltas:
            report["features"]["dt_prev_res_delta_ms"] = {
                "n": len(deltas),
                "median": statistics.median(deltas),
                "p95": sorted(deltas)[int(0.95 * (len(deltas) - 1))],
                "max": max(deltas),
                "nonzero": sum(1 for d in deltas if d > 1e-9),
            }

    # ---- classificacao --------------------------------------------------
    report["realtime"] = compare_sets(b_rt_rows, l_rt_rows,
                                      CLASS_COLS + META_COLS)
    report["retro"] = compare_sets(load(b_ro[0]), load(l_ro),
                                   ("session_key", "session_mean_dt_res",
                                    "session_deviates", "poisoned_by",
                                    "retro_anomaly", "final_anomaly",
                                    "alert_transition", "cs_armed",
                                    "dt_prev_res", "type_label",
                                    "stream_key", "service_id", "src_ip"))
    report["metrics"] = {
        "baseline": metrics(load(b_ro[0])),
        "live": metrics(load(l_ro)),
    }
    report["metrics_equal"] = (report["metrics"]["baseline"]
                               == report["metrics"]["live"])

    if args.out_json:
        out = Path(args.out_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    t = report.get("timing", {})
    if t:
        print(f"[compare] deriva da linha temporal (relativa): mediana "
              f"{t['delay_ms']['median']:.3f} ms | jitter: mediana "
              f"{t['jitter_ms']['median_abs']:.3f} ms, p95 "
              f"{t['jitter_ms']['p95_abs']:.3f} ms, max "
              f"{t['jitter_ms']['max_abs']:.3f} ms")
    if "features" in report:
        fe = report["features"]
        d = fe.get("dt_prev_res_delta_ms") or {}
        print(f"[compare] features: {fe['total_cell_diffs']} celulas "
              f"diferentes em {fe['rows_with_diff']} linhas | dt_prev_res "
              f"variou em {d.get('nonzero')}/{d.get('n')} linhas "
              f"(mediana {d.get('median', 0):.4f} ms, max "
              f"{d.get('max', 0):.3f} ms)")
    for kind in ("realtime", "retro"):
        c = report[kind]
        print(f"[compare] {kind}: {c['total_cell_diffs']} celulas diferentes "
              f"em {c['rows_with_diff']} de {c['rows_compared']} linhas | "
              f"por coluna: {c['per_column']}")
    print(f"[compare] metricas baseline={report['metrics']['baseline']}")
    print(f"[compare] metricas live   ={report['metrics']['live']}")
    if args.out_json:
        print(f"[compare] -> {args.out_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
