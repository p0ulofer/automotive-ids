#!/usr/bin/env python3
"""Consolida as metricas das configuracoes congeladas da Fase 5 (relatorio).

Le SO' os CSVs por-pacote congelados (Algoritmo 1 + retro) e recomputa, de forma
uniforme para todas as configuracoes:

  * por pacote: TPR final, TPR direta (Algoritmo 1), FPR (normais holdout),
    FPR (normais dentro dos ataques);
  * direta vs contagio: TP com `alert_transition` vs TP so' por sessao;
  * por sessao: TPR (sessoes com >=1 pacote de ataque) e FPR (sessoes so' normais);
  * % detecoes em tempo-real vs retroativas.

Nao corre nenhum detector nem treina nada -- so' leitura.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ids_common import ATTACK_DATASETS, NORMAL_DATASETS  # noqa: E402

# configuracao -> (dir, glob do CSV retro por-dataset)
CONFIGS = {
    "baseline_v1 (mac, oraculo)": ("results/baseline_v1", "retro_{ds}.csv"),
    "baseline_v2 / ip": ("results/baseline_v2/ip", "retro_use_ip_h30_{ds}.csv"),
    "baseline_v2 / ip_client": ("results/baseline_v2/ip_client",
                                "retro_use_ip_client_h30_{ds}.csv"),
    "baseline_v3 / ip": ("results/baseline_v3/ip", "retro_use_ip_h30_{ds}.csv"),
    "baseline_v3 / ip_client": ("results/baseline_v3/ip_client",
                                "retro_use_ip_client_h30_{ds}.csv"),
    "E3b / ip": ("results/exp_E3b/ip", "retro_use_ip_h30_{ds}.csv"),
    "E3b / ip_client": ("results/exp_E3b/ip_client",
                        "retro_use_ip_client_h30_{ds}.csv"),
}


def _rows(p):
    with open(p, newline="") as fh:
        return list(csv.DictReader(fh))


def metrics(rdir, rglob):
    d = Path(rdir)
    out = {"packet": defaultdict(int), "session": defaultdict(int), "det": defaultdict(int),
           "n_attack_pkt": 0, "n_normal_3n": 0, "n_normal_atk": 0,
           "sessions_atk": 0, "sessions_normal_3n": 0, "sessions_normal_atk": 0,
           "per_dataset_missing": []}
    for name in NORMAL_DATASETS + ATTACK_DATASETS:
        tp = d / rglob.format(ds=name)
        if not tp.exists():
            out["per_dataset_missing"].append(name)
            continue
        rows = _rows(tp)
        is_atk = name in ATTACK_DATASETS
        n_norm = sum(1 for r in rows if r["label"] == "0")
        if is_atk:
            out["n_attack_pkt"] += sum(1 for r in rows if r["label"] == "1")
            out["n_normal_atk"] += n_norm
        else:
            out["n_normal_3n"] += n_norm
        for r in rows:
            lab = r["label"] == "1"
            hit = r["alert_transition"] == "1"
            fin = r["final_anomaly"] == "1"
            if fin and is_atk:
                out["det"]["rt" if hit else "retro"] += 1
            if lab:
                if hit:
                    out["packet"]["tp_direct"] += 1
                if fin:
                    out["packet"]["tp_final"] += 1
                    if not hit:
                        out["packet"]["tp_contagion"] += 1
            else:
                if fin:
                    out["packet"]["fp_normal_atk" if is_atk else "fp_normal_3n"] += 1
        # sessoes
        sess = defaultdict(list)
        for r in rows:
            sess[r["session_key"]].append(r)
        for k, rs in sess.items():
            atk = any(x["label"] == "1" for x in rs)
            marked = any(x["final_anomaly"] == "1" for x in rs)
            if atk:
                out["sessions_atk"] += 1
                out["session"]["atk_marked"] += marked
            else:
                key = "normal_3n" if not is_atk else "normal_atk"
                out["sessions_" + key] += 1
                out["session"][key + "_marked"] += marked
    return out


def ratio(a, b):
    return round(a / b, 4) if b else None


def main():
    table = {}
    for label, (rdir, rglob) in CONFIGS.items():
        m = metrics(rdir, rglob)
        p, s = m["packet"], m["session"]
        rt, retro = m["det"]["rt"], m["det"]["retro"]
        tot = rt + retro
        table[label] = {
            "TPR_pkt": ratio(p["tp_final"], m["n_attack_pkt"]),
            "FPR_pkt_3normais": ratio(p["fp_normal_3n"], m["n_normal_3n"]),
            "FPR_pkt_normais_nos_ataques": ratio(p["fp_normal_atk"], m["n_normal_atk"]),
            "A1_TPR_direta": ratio(p["tp_direct"], m["n_attack_pkt"]),
            "TP_direct_pct": ratio(p["tp_direct"], p["tp_final"]),
            "TP_contagion_pct": ratio(p["tp_contagion"], p["tp_final"]),
            "TPR_sessao": ratio(s["atk_marked"], m["sessions_atk"]),
            "FPR_sessao_3normais": ratio(s["normal_3n_marked"], m["sessions_normal_3n"]),
            "FPR_sessao_normais_nos_ataques": ratio(s["normal_atk_marked"],
                                                    m["sessions_normal_atk"]),
            "pct_tempo_real": round(100 * rt / tot, 1) if tot else None,
            "pct_retroativo": round(100 * retro / tot, 1) if tot else None,
            "n_sessions_atk": m["sessions_atk"],
            "n_sessions_normal_3n": m["sessions_normal_3n"],
            "n_sessions_normal_atk": m["sessions_normal_atk"],
            "n_attack_pkt": m["n_attack_pkt"],
            "n_normal_3n": m["n_normal_3n"],
            "missing": m["per_dataset_missing"],
        }

    print(f"{'configuracao':28s} {'TPRpkt':>7s} {'FPR3n':>8s} {'FPRatk':>8s} "
          f"{'A1dir':>7s} {'dir%':>6s} {'cont%':>6s} {'TPRsess':>8s} {'FPRsess3n':>9s} {'rt%':>5s}")
    for k, v in table.items():
        print(f"{k:28s} {str(v['TPR_pkt']):>7s} {str(v['FPR_pkt_3normais']):>8s} "
              f"{str(v['FPR_pkt_normais_nos_ataques']):>8s} {str(v['A1_TPR_direta']):>7s} "
              f"{str(v['TP_direct_pct']):>6s} {str(v['TP_contagion_pct']):>6s} "
              f"{str(v['TPR_sessao']):>8s} {str(v['FPR_sessao_3normais']):>9s} "
              f"{str(v['pct_tempo_real']):>5s}")
    Path("results/fase5_consolidado.json").write_text(json.dumps(table, indent=2) + "\n")
    print("\n[out] results/fase5_consolidado.json")


if __name__ == "__main__":
    main()
