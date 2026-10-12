#!/usr/bin/env python3
"""
tools/validate_features.py -- Fase 4 someip-ids: sanity check das features
Tabela IV SEM treinar modelo nenhum (o IDS e' Fase 5).

Para cada features/<nome>.csv:
  - dataset NORMAL: resumo das distribuicoes (n, N/A%, mediana, media, p95,
    max), taxa de violacao de Session-ID (os=0) por servico e n_cs max por
    servico -> baseline para os ataques;
  - dataset DE ATAQUE: compara label=0 (trafego normal do proprio arquivo)
    vs label=1 (injecao/ataque):
      * numericos  -> KS two-sample (scipy); sinal se KS >= 0.10;
      * categoricos -> maior diferenca de taxa em percentual-points;
      sinal se >= 5 pp;
      * n_cs       -> sinal se o maximo por servico excede o baseline dos
      3 datasets normais.
  Veredito: SIGNAL se ao menos 1 feature sinalizar; NONE caso contrario.

Atualiza o bloco "sanity" de features/MANIFEST.json e imprime o relatorio.
Exit code: 0 = pipeline OK; 1 = nenhum dataset de ataque sinalizou (quebra).

Uso: python3 tools/validate_features.py [--features-dir features]
        [--ks 0.10] [--pp 5.0] [--only NOME]
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from scipy.stats import ks_2samp

NUMERIC = ["dt_prev_req", "dt_prev_res", "dt_prev_req_avg", "dt_prev_res_avg",
           "dp_prev_req_l1", "dp_prev_res_l1"]
CATEGORICAL = ["dt_prev_req_bin", "dt_prev_res_bin", "dp_prev_req",
               "dp_prev_res", "os"]
ALL_FEATURES = NUMERIC + CATEGORICAL + ["n_cs"]


def load(path, extra=("label", "service_id")):
    cols = list(dict.fromkeys(list(extra) + ALL_FEATURES))
    return pd.read_csv(path, usecols=lambda c: c in cols)


def numeric_summary(df):
    out = {}
    for col in NUMERIC:
        s = df[col]
        nn = s.dropna()
        out[col] = {
            "n": int(len(nn)), "na_pct": round(100 * (1 - len(nn) / len(df)), 3),
            "median": round(float(nn.median()), 6) if len(nn) else None,
            "mean": round(float(nn.mean()), 6) if len(nn) else None,
            "p95": round(float(nn.quantile(0.95)), 6) if len(nn) else None,
            "max": round(float(nn.max()), 6) if len(nn) else None,
        }
    return out


def os_rates(df):
    d = df.dropna(subset=["os"])
    if d.empty:
        return {}
    rates = d.groupby("service_id")["os"].apply(lambda s: round(100 * (s == 0).mean(), 3))
    return rates.to_dict()


def attack_flags(df, baseline_cs, ks_min, pp_min):
    """Compara label 0 vs 1; devolve lista de flags e detalhes."""
    flags, details = [], {}
    lab = df["label"]
    if (lab == 1).sum() == 0 or (lab == 0).sum() == 0:
        return ["SEM_LABELS"], {"erro": "label 0 ou 1 vazio"}

    for col in NUMERIC:
        x = df.loc[lab == 0, col].dropna()
        y = df.loc[lab == 1, col].dropna()
        if len(x) < 2 or len(y) < 2:
            continue
        ks = ks_2samp(x, y)
        d = {"ks": round(float(ks.statistic), 4), "p": float(ks.pvalue),
             "n0": int(len(x)), "n1": int(len(y)),
             "median0": round(float(x.median()), 6),
             "median1": round(float(y.median()), 6)}
        details[col] = d
        if d["ks"] >= ks_min:
            flags.append(f"{col}:KS={d['ks']}")

    for col in CATEGORICAL:
        if col in ("dp_prev_req", "dp_prev_res", "os"):
            a = pd.to_numeric(df.loc[lab == 0, col], errors="coerce").dropna()
            b = pd.to_numeric(df.loc[lab == 1, col], errors="coerce").dropna()
            if a.empty or b.empty:
                continue
            ra, rb = (a == 1).mean() * 100, (b == 1).mean() * 100
            d = {"rate0_pct": round(float(ra), 3), "rate1_pct": round(float(rb), 3),
                 "diff_pp": round(abs(float(rb - ra)), 3)}
            details[col] = d
            if d["diff_pp"] >= pp_min:
                flags.append(f"{col}:{d['diff_pp']}pp")
            continue
        a = df.loc[lab == 0, col].dropna().astype(str)
        b = df.loc[lab == 1, col].dropna().astype(str)
        if a.empty or b.empty:
            continue
        vals = sorted(set(a) | set(b))
        ra = a.value_counts(normalize=True).reindex(vals, fill_value=0) * 100
        rb = b.value_counts(normalize=True).reindex(vals, fill_value=0) * 100
        d = {"max_diff_pp": round(float((rb - ra).abs().max()), 3),
             "dist0": {v: round(float(ra[v]), 2) for v in vals},
             "dist1": {v: round(float(rb[v]), 2) for v in vals}}
        details[col] = d
        if d["max_diff_pp"] >= pp_min:
            flags.append(f"{col}:{d['max_diff_pp']}pp")

    cs = df.groupby("service_id")["n_cs"].max().to_dict()
    details["n_cs_max"] = {str(k): int(v) for k, v in cs.items()}
    exceeded = {str(k): [int(v), baseline_cs.get(str(k))]
                for k, v in cs.items()
                if baseline_cs.get(str(k)) is not None and v > baseline_cs[str(k)]}
    if exceeded:
        details["n_cs_vs_baseline"] = {k: {"attack": v[0], "normal_baseline": v[1]}
                                       for k, v in exceeded.items()}
        flags.append(f"n_cs>{exceeded}")
    return flags, details


def main():
    ap = argparse.ArgumentParser(description="Sanity check das features (sem IDS).")
    ap.add_argument("--features-dir", default="features")
    ap.add_argument("--ks", type=float, default=0.10,
                    help="limiar de KS (label0 vs label1) [default 0.10]")
    ap.add_argument("--pp", type=float, default=5.0,
                    help="limiar de diferenca categorica em p.p. [default 5.0]")
    ap.add_argument("--only", action="append", default=[], metavar="NOME")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    fdir = root / args.features_dir
    files = sorted(p for p in fdir.glob("*.csv"))
    if args.only:
        files = [p for p in files if p.stem in set(args.only)]
    if not files:
        sys.exit(f"ERRO: nenhum CSV de features em {fdir}")

    normal_files = [p for p in files if p.stem.startswith("normal")]
    attack_files = [p for p in files if not p.stem.startswith("normal")]
    if not normal_files:
        sys.exit("ERRO: precisa de ao menos 1 features/normal_*.csv p/ baseline")

    manifest_path = fdir / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}

    # --- baselines dos normais
    print("=" * 78)
    print("BASELINE (datasets normais)")
    print("=" * 78)
    baseline_cs, normal_reports = {}, {}
    for path in normal_files:
        df = load(path)
        cs = {str(k): int(v) for k, v in df.groupby("service_id")["n_cs"].max().items()}
        for k, v in cs.items():
            baseline_cs[k] = max(baseline_cs.get(k, 0), v)
        summ = numeric_summary(df)
        osr = os_rates(df)
        normal_reports[path.stem] = {"n_cs_max": cs, "os0_rate_pct": osr,
                                     "numeric": summ}
        print(f"\n{path.stem}: {len(df)} linhas")
        print(f"  n_cs max/svc: {cs}")
        print(f"  os=0 rate %/svc: {osr}")
        for col in NUMERIC:
            s = summ[col]
            print(f"  {col:18s} n={s['n']:<9} na={s['na_pct']:>6}% "
                  f"med={s['median']} mean={s['mean']} p95={s['p95']} max={s['max']}")
    print(f"\nbaseline n_cs combinado: {baseline_cs}")

    # --- ataques
    attack_reports = {}
    n_signal = 0
    for path in attack_files:
        df = load(path)
        flags, details = attack_flags(df, baseline_cs, args.ks, args.pp)
        verdict = "SIGNAL" if flags != ["SEM_LABELS"] else "NONE"
        if verdict == "SIGNAL":
            n_signal += 1
        attack_reports[path.stem] = {"verdict": verdict, "flags": flags,
                                     "details": details}
        print("\n" + "-" * 78)
        lab = df["label"]
        print(f"{path.stem}: {len(df)} linhas "
              f"(label0={int((lab == 0).sum())}, label1={int((lab == 1).sum())})"
              f" -> {verdict}")
        if flags == ["SEM_LABELS"]:
            print("  !! labels insuficientes")
            continue
        if not flags:
            print("  nenhuma feature sinalizou")
        for f in flags:
            print(f"  FLAG {f}")
        for col in NUMERIC:
            if col in details:
                d = details[col]
                print(f"  {col:18s} ks={d['ks']:<7} p={d['p']:.3g} "
                      f"med0={d['median0']} med1={d['median1']}")
        for col in CATEGORICAL:
            if col in details:
                d = details[col]
                if "diff_pp" in d:
                    print(f"  {col:18s} rate0={d['rate0_pct']}% rate1={d['rate1_pct']}%"
                          f" diff={d['diff_pp']}pp")
                else:
                    print(f"  {col:18s} maxdiff={d['max_diff_pp']}pp "
                          f"dist0={d['dist0']} dist1={d['dist1']}")
        print(f"  n_cs max/svc: {details.get('n_cs_max')}")
        if "n_cs_vs_baseline" in details:
            print(f"  n_cs vs baseline: {details['n_cs_vs_baseline']}")

    # --- manifesto
    manifest["sanity"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "tools/validate_features.py",
        "gate": {"ks_min": args.ks, "categorical_pp_min": args.pp,
                 "rule": "sinal se >=1 feature sinaliza (label0 vs label1; "
                         "n_cs vs baseline normal)"},
        "baselines_normal": normal_reports,
        "attacks": attack_reports,
        "n_attack_signal": n_signal,
        "n_attack_total": len(attack_files),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print("\n" + "=" * 78)
    print(f"RESUMO: {n_signal}/{len(attack_files)} datasets de ataque com sinal "
          f"(KS>={args.ks} ou diff>={args.pp}pp ou n_cs>baseline)")
    print(f"[manifest] sanity gravado em {manifest_path}")
    if attack_files and n_signal == 0:
        print("ERRO: nenhum ataque sinalizou - pipeline quebrado")
        sys.exit(1)


if __name__ == "__main__":
    main()
