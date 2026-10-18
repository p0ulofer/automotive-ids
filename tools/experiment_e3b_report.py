#!/usr/bin/env python3
"""E3b -- distribuicao por sinal dos FP remanescentes do Algoritmo 1.

Le o CSV do Algoritmo 1 (`results/exp_E3b/ip/realtime_*_normal_*.csv`) e o
modelo de 100 % do E3b, e responde a pergunta (c) do E3b:

  "Se os FPs restantes forem dominados por faixas de sinais continuos
   aprendidas como tercil global, mostra a distribuicao por sinal."

Para cada FP faz-se a atribuicao por *causa unica*: para cada posicao da tupla
`p`, verifica-se se existe um estado do modelo (100 %) que coincide com o do FP
em TODAS as outras posicoes. Se existir, mudar so' `p` "repara" o FP -> `p` e'
uma causa suficiente. Isto separa:

  * band  = faixa de tercil de sinal continuo (defeito "tercil global" do E3);
  * chg   = mudanca de valor do sinal continuo (0/1);
  * value = valor de campo enumerado;
  * trans = transicao de campo enumerado (prev>valor).

Uso:
    python3 tools/experiment_e3b_report.py \
        --results-dir results/exp_E3b/ip \
        --model-100 results/exp_E3b/payload_model_100_use_ip.json \
        --out results/exp_E3b/per_signal.json
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ids_common import NORMAL_DATASETS, TUPLE_FEATURES  # noqa: E402

BASE = len(TUPLE_FEATURES)  # 7


def comp_class(comp):
    """(nome, tipo) de um componente da tupla."""
    if "=" in comp:
        return comp.split("=", 1)[0], "value"
    name, _, val = comp.partition(":")
    if val in ("low", "mid", "high"):
        return name, "band"
    if val in ("0", "1"):
        return name, "chg"
    if ">" in val:
        return name, "trans"
    return name, "other"


def _reduce_sets(states):
    """Para cada posicao p, o conjunto de estados 'sem a posicao p'."""
    comps = [s.split("|") for s in states]
    n = len(comps[0])
    out = []
    for p in range(n):
        idx = [j for j in range(n) if j != p]
        out.append({tuple(c[j] for j in idx) for c in comps})
    return out, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", default="results/exp_E3b/ip")
    ap.add_argument("--model-100", required=True,
                    help="modelo treinado com 100%% dos normais (classe i/ii/iii)")
    ap.add_argument("--model-70", default=None,
                    help="modelo de treino (70%%) que produziu os FP (referencia da causa); "
                         "por omissao, o `realtime_model_*.json` irmao do --results-dir")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    model = json.load(open(args.model_100))
    tr = {k: set(v) for k, v in model["transitions"].items()}
    red = {k: _reduce_sets(v) for k, v in tr.items()}

    m70_path = args.model_70
    if m70_path is None:
        cands = sorted(Path(args.results_dir).glob("realtime_model_use_*_h30.json"))
        if not cands:
            sys.exit("ERRO: --model-70 nao dado e nao encontrei realtime_model_*_h30.json")
        m70_path = str(cands[0])
    tr70 = {k: set(v) for k, v in json.load(open(m70_path))["transitions"].items()}
    red70 = {k: _reduce_sets(v) for k, v in tr70.items()}
    use70 = all(k in tr70 for k in tr)     # identidade coerente entre os dois modelos

    n_fp = 0
    classes = Counter()
    by_class = Counter()               # total / payload / base / none
    cause = Counter()                  # (nome, tipo) -> n de FPs em que e' causa
    cause_pos = Counter()              # posicao relativa no payload -> n
    ncauses = Counter()                # n de causas por FP
    signal_present = Counter()         # sinal presente no estado do FP
    band_dist = defaultdict(Counter)   # sinal continuo -> band nos FP
    groups = Counter()                 # (svc|tipo, estado)

    for name in NORMAL_DATASETS:
        hits = sorted(Path(args.results_dir).glob(f"realtime_*_{name}.csv"))
        if not hits:
            sys.exit(f"ERRO: sem CSV do Algoritmo 1 para {name} em {args.results_dir}")
        for r in csv.DictReader(open(hits[0], newline="")):
            if not (r["label"] == "0" and r["alert_transition"] == "1"):
                continue
            n_fp += 1
            key = f"{r['service_id']}|{r['type_label']}"
            comps = r["state"].split("|")
            n = len(comps)
            groups[(key, r["state"])] += 1

            states100 = tr.get(key, set())
            # classe D1a
            if r["avg_full"] == "0":
                cls = "i_cold_start"
            elif r["state"] in states100:
                cls = "ii_in100_not_in70"
            else:
                cls = "iii_never_seen"
            classes[cls] += 1

            for p in range(BASE, n):
                nm, tp = comp_class(comps[p])
                signal_present[nm] += 1
                if tp == "band":
                    band_dist[nm][comps[p].split(":", 1)[1]] += 1

            # causa (contra o modelo de 70% que produziu o FP): so' p/ classe ii
            models_red, mn = red70.get(key, ([], 0))
            if cls != "ii_in100_not_in70" or mn != n or not models_red:
                continue
            causes = []
            for p in range(n):
                idx = [j for j in range(n) if j != p]
                if tuple(comps[j] for j in idx) in models_red[p]:
                    causes.append(p)
            ncauses[len(causes)] += 1
            if not causes:
                by_class["none"] += 1
            for p in causes:
                if p >= BASE:
                    nm, tp = comp_class(comps[p])
                    cause[(nm, tp)] += 1
                    cause_pos[p - BASE] += 1
                    by_class["payload"] += 1
                else:
                    cause[(TUPLE_FEATURES[p], "base")] += 1
                    by_class["base"] += 1
            for p in range(BASE, n):
                nm, tp = comp_class(comps[p])
                signal_present[nm] += 1
                if tp == "band":
                    band_dist[nm][comps[p].split(":", 1)[1]] += 1

    total_cause = sum(cause.values())
    out = {
        "results_dir": args.results_dir,
        "model_100": args.model_100,
        "model_70": m70_path,
        "total_a1_fp": n_fp,
        "classes": dict(classes),
        "attribution": dict(by_class),
        "fp_with_causes": n_fp - by_class["none"] - by_class["no_model_key"],
        "n_causes_per_fp": {str(k): v for k, v in sorted(ncauses.items())},
        "cause_by_component": {f"{k[0]}.{k[1]}": v for k, v in
                               sorted(cause.items(), key=lambda kv: -kv[1])},
        "cause_by_payload_position": {str(k): v for k, v in sorted(cause_pos.items())},
        "signal_present_in_fp_state": dict(signal_present.most_common()),
        "band_distribution_in_fp": {k: dict(v) for k, v in sorted(band_dist.items())},
        "top_fp_groups": [
            {"svc_type": k[0], "state": k[1], "n": v}
            for k, v in sorted(groups.items(), key=lambda kv: -kv[1])[:20]
        ],
    }
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(out, indent=2) + "\n")

    print(f"A1 FP (normais holdout) = {n_fp}")
    print(f"classes D1a: {out['classes']}")
    print(f"atribuicao da causa (so' classe ii, vs modelo de 70%): {out['attribution']}")
    print(f"FPs com causa unica identificada = {out['fp_with_causes']}")
    print(f"n. de causas por FP: {out['n_causes_per_fp']}")
    print(f"total causas (posicoes) = {total_cause}")
    print("\ncausas por componente (nome.tipo):")
    for k, v in sorted(cause.items(), key=lambda kv: -kv[1])[:20]:
        print(f"  {v:5d}  {k[0]}.{k[1]}")
    print("\ndistribuicao de faixa (band) nos FP (sinais continuos):")
    for s, d in sorted(band_dist.items()):
        print(f"  {s:8s} {dict(d)}")
    print("\ntop grupos de FP:")
    for g in out["top_fp_groups"][:10]:
        print(f"  n={g['n']:4d} {g['svc_type']:12s} {g['state'][:90]}")
    if args.out:
        print(f"\n[out] {args.out}")


if __name__ == "__main__":
    main()
