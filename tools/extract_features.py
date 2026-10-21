#!/usr/bin/env python3
"""
tools/extract_features.py -- Fase 4 someip-ids: extrai features de transicao
de estado (Tabela IV de Koyama et al., VTC2022-Spring) dos CSVs ja gerados
(datasets/normal/*.csv e datasets/attack/*.csv), sem treinar modelo nenhum.

Saida: features/<nome>.csv = colunas originais + features + label (inalterado),
       features/thresholds.json (limiares de discretizacao aprendidos SO nos
       datasets normais) e contagens em features/MANIFEST.json.

Uso:
    python3 tools/extract_features.py [--only normal_rr --only ARR-Req-a1]
        [--out-dir features] [--thresholds features/thresholds.json]
        [--learn-only]

Sem --thresholds, os limiares sao aprendidos (passo 1) nos datasets NORMAIS e
gravaados em <out-dir>/thresholds.json; depois todos os CSVs escolhidos sao
processados (passo 2). Com --thresholds PATH existente, o passo 1 e' pulado.

Design (detalhes e decisoes em docs/feature_model.md):
  - chave de transicao (stream_key) = (Service ID, tipo, remetente);
    tipo = nome da Message Type para SOME/IP ou "SD:<entry>" para SD;
  - dt_prev_req: vs REQUEST anterior do MESMO remetente (linha REQUEST) ou do
    mesmo Service ID, qualquer remetente (linhas RESPONSE/NOTIFICATION);
  - dt_prev_res: vs pacote anterior do MESMO tipo+remetente+servico;
  - medias moveis: janela W=10 dos ultimos valores NAO-nulos da MESMA feature
    na MESMA stream_key (valor atual excluido);
  - discretizacao dt: anchors (min, mediana, max) aprendidos por
    (Service ID, tipo) SO nos normais; limites = pontos medios entre anchors;
  - dp: diferenca de payload em L1 (bytes sobreposicao) + categorica
    com/sem mudanca sobre os campos CONTINUOS do payload (docs/payload_model.md);
  - n_cs: numero de streams de sessao abertas do Service ID ate ao momento;
  - os: Session-ID em ordem estrita (prev+1 ou wrap 0xFFFF->0/1) na stream_key;
  - primeiro pacote de uma stream: features de referencia = vazio (N/A).
"""
import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from feature_logic import (  # noqa: E402
    FEATURE_COLS,
    WINDOW_W,
    Extractor,
    fmt,
)


def _count_rows(path):
    """Numero de linhas de dados (sem cabecalho)."""
    with open(path, newline="") as fh:
        return sum(1 for _ in fh) - 1


def learn_thresholds(csv_paths, holdout=0.0):
    """Passo 1: coleta dTs nos NORMAIS e devolve anchors por (svc|tipo).

    E1b: com `holdout > 0` os limiares sao aprendidos SO nos primeiros
    (1 - holdout) de cada CSV normal -- o mesmo corte temporal do treino de E1
    (`evaluate_ids.py --holdout`). Por omissao (0.0) usa 100% dos normais, como
    a Fase 4 original.
    """
    collect = {"dt_prev_req": defaultdict(list), "dt_prev_res": defaultdict(list)}
    learned_rows = {}
    for path in csv_paths:
        total = _count_rows(path)
        cut = int(total * (1.0 - holdout)) if holdout > 0 else total
        ex = Extractor(collect=collect)
        with open(path, newline="") as fh:
            for i, row in enumerate(csv.DictReader(fh)):
                if i >= cut:
                    break
                ex.process(row)
        learned_rows[path.name] = {"rows_total": total, "rows_learned": cut}
        print(f"[learn] {path.name}: {cut}/{total} linhas"
              + (f" (holdout={holdout})" if holdout > 0 else "")
              + f" | dT_req={sum(len(v) for v in collect['dt_prev_req'].values())} "
              f"dT_res={sum(len(v) for v in collect['dt_prev_res'].values())}",
              file=sys.stderr)

    thresholds = {"window_w": WINDOW_W,
                  "method": ("anchors (min, mediana, max) sobre dTs dos datasets "
                             "NORMAIS; limites = pontos medios entre anchors"),
                  "learned_on": [p.name for p in csv_paths],
                  "learn_holdout": holdout,
                  "learned_rows": learned_rows,
                  "dt_prev_req": {}, "dt_prev_res": {}}
    for feat in ("dt_prev_req", "dt_prev_res"):
        for key, vals in sorted(collect[feat].items()):
            mn = min(vals)
            mx = max(vals)
            md = statistics.median(vals)
            thresholds[feat][key] = {
                "n": len(vals), "min": mn, "median": md, "max": mx,
                "b1": (mn + md) / 2.0, "b2": (md + mx) / 2.0,
            }
    return thresholds


def extract_one(path, out_dir, thresholds):
    """Passo 2: grava features/<nome>.csv e devolve contagens p/ MANIFEST."""
    out_path = out_dir / (path.stem + ".csv")
    ex = Extractor(thresholds=thresholds)
    n = 0
    with open(path, newline="") as fh, open(out_path, "w", newline="") as out:
        reader = csv.DictReader(fh)
        orig_cols = list(reader.fieldnames or [])
        writer = csv.writer(out)
        writer.writerow(orig_cols + FEATURE_COLS)
        for row in reader:
            feats = ex.process(row)
            writer.writerow([row[c] for c in orig_cols]
                            + [fmt(c, feats[c]) for c in FEATURE_COLS])
            n += 1
    return out_path, {
        "source": str(path),
        "file": out_path.name,
        "rows": n,
        "na": dict(ex.na_counts),
    }


def main():
    ap = argparse.ArgumentParser(
        description="Extrai features de transicao (Tabela IV) dos datasets CSV.")
    ap.add_argument("--normal-dir", default="datasets/normal")
    ap.add_argument("--attack-dir", default="datasets/attack")
    ap.add_argument("--out-dir", default="features")
    ap.add_argument("--only", action="append", default=[], metavar="NOME",
                    help="processa so estes datasets (stem do CSV); repetivel")
    ap.add_argument("--thresholds", default=None, metavar="PATH",
                    help="reusa limiares deste JSON (pula o aprendizado)")
    ap.add_argument("--learn-holdout", type=float, default=0.0, metavar="FRAC",
                    help="E1b: aprender os limiares de discretizacao SO nos "
                         "primeiros (1-FRAC) de cada normal (0.3 = treino de E1)")
    ap.add_argument("--learn-only", action="store_true",
                    help="so aprende e grava thresholds.json, nao extrai")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    normal_dir = root / args.normal_dir
    attack_dir = root / args.attack_dir
    out_dir = root / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    normal_csvs = sorted(normal_dir.glob("*.csv"))
    attack_csvs = sorted(attack_dir.glob("*.csv"))
    if not normal_csvs:
        sys.exit(f"ERRO: nenhum CSV normal em {normal_dir}")
    if args.only:
        wanted = set(args.only)
        normal_csvs = [p for p in normal_csvs if p.stem in wanted]
        attack_csvs = [p for p in attack_csvs if p.stem in wanted]
        missing = wanted - {p.stem for p in normal_csvs + attack_csvs}
        if missing:
            sys.exit(f"ERRO: --only desconhecido: {sorted(missing)}")
    targets = normal_csvs + attack_csvs

    # --- passo 1: limiares (SO nos normais)
    if args.thresholds:
        thresholds = json.loads(Path(args.thresholds).read_text())
        print(f"[thresholds] reutilizados de {args.thresholds}", file=sys.stderr)
    else:
        print(f"[learn] aprendendo limiares em {len(normal_csvs)} dataset(s) normal(is)"
              + (f" -- so os primeiros {1 - args.learn_holdout:.0%}"
                 if args.learn_holdout > 0 else ""), file=sys.stderr)
        thresholds = learn_thresholds(normal_csvs, holdout=args.learn_holdout)
        (out_dir / "thresholds.json").write_text(
            json.dumps(thresholds, indent=2, ensure_ascii=False) + "\n")
        print(f"[thresholds] gravados em {out_dir / 'thresholds.json'}", file=sys.stderr)

    if args.learn_only:
        return

    # --- passo 2: extracao
    manifest_path = out_dir / "MANIFEST.json"
    manifest = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError:
            manifest = {}
    manifest.setdefault("datasets", {})
    for path in targets:
        out_path, info = extract_one(path, out_dir, thresholds)
        manifest["datasets"][path.stem] = info
        total = info["rows"]
        nas = ", ".join(f"{c}={n}" for c, n in sorted(info["na"].items()) if n)
        print(f"[extract] {path.stem}: {total} linhas -> {out_path.name}"
              + (f"  (N/A: {nas})" if nas else ""))
    manifest["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest["tool"] = "tools/extract_features.py"
    manifest["window_w"] = WINDOW_W
    manifest["thresholds_file"] = "thresholds.json"
    manifest["thresholds_learned_on"] = thresholds.get("learned_on", [])
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(f"[manifest] atualizado: {manifest_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
