#!/usr/bin/env python3
"""Validacao de equivalencia: modo online (`tools/ids_live.py`) vs. `baseline_v3`.

Corre o modo online em replay deterministico (`--pcap`, timestamps originais,
sem dormir) para cada dataset pedido e compara OS DOIS CSVs de saida
(`realtime_*` e `retro_*`) com os congelados em
`results/baseline_v3/ip/`, pacote a pacote e coluna a coluna.

Porque e' importante (ver docs/ids_live.md sec. 6): o bug silencioso a evitar e'
ter a logica de features/deteccao sido REIMPLEMENTADA e divergir do que foi
validado offline. Este teste nao mede metricas -- exige equivalencia exacta.

Colunas consideradas "metadados" e EXCLUIDAS do critério de passagem:
  * `src_mac` -- o CSV normal da Fase 2 (`datasets/normal/*.csv`) nao tem
    coluna MAC, portanto o offline escreve '' e o online escreve o MAC real do
    pacote. Nao entra na identidade (`identity=ip`) nem na tupla de estado.
  * `label` -- verdade de terreno; so e' usada nas metricas.

Uso:
    # default: ANEpc-a1 + ARR-Res-a1 + ANEc-a1 (ataques) e normal_rr
    python3 tools/validate_ids_live.py

    # explicito (cada --attack e' repetivel)
    python3 tools/validate_ids_live.py \
        --attack ANEpc-a1 --attack ARR-Res-a1 --attack ANEc-a1 \
        --normal normal_rr --out results/ids_live_validation/report.json

Nota: `ARR-Req-a1` NAO serve para este teste -- o pcap em disco nao e' o da
execucao congelada (ver `docs/nota_divergencia_arrreqa1.md`).
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
METADATA_COLS = ("src_mac", "label")
# Metadata da PARTICAO das sessoes: com `--session-max-age` as sessoes sao
# cortadas, logo o `session_key` e a `session_mean_dt_res` mudam. O que nao
# pode mudar e' a CLASSIFICACAO (alert_transition, retro_anomaly,
# final_anomaly, poisoned_by, session_deviates, ...).
SESSION_META_COLS = ("session_key", "session_mean_dt_res")
# Colunas do Algoritmo 1: NAO podem mudar com o corte de sessoes (o
# Algoritmo 1 nao conhece sessoes).
ALG1_COLS = ("alert_transition", "alert_flag", "state", "in_model", "checkable",
             "avg_full", "n_cs", "sender_count", "cs_max", "is_new_stream",
             "dt_prev_res", "type_label", "stream_key", "service_id", "src_ip",
             "timestamp", "idx")
# Colunas do Algoritmo 2: podem mudar NA FRONTEIRA do corte, porque cortar
# uma sessao parte a janela retroactiva V-C 2 (os hits de um lado da
# fronteira ja' nao contaminam as linhas do outro lado).
ALG2_COLS = ("session_deviates", "retro_anomaly", "final_anomaly",
             "poisoned_by")


def load_csv(path: Path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def compare(base_path: Path, live_path: Path, strict_cols=None):
    """Compara dois CSVs por pacote (alinhados pelo campo `idx`).

    O `retro_*.csv` do modo online e' escrito por ordem de DECISAO (sessao
    fechada), nao por ordem global de `idx` -- a ordem global nao e'
    necessaria em operacao (a marca retroativa e' por sessao). Por isso as
    duas tabelas sao ordenadas por `idx` antes de comparar: e' o comparador
    (artefacto de validacao) que reintroduz a ordem, nao o caminho ao vivo.

    Se o numero de linhas DIFER (dataset substituido, ver
    `docs/nota_divergencia_arrreqa1.md`), compara na mesma o prefixo comum e
    sinaliza `rows_equal=False`; `ok` so' e' True se as linhas batem E nao ha
    diffs estritas.
    """
    base = load_csv(base_path)
    live = load_csv(live_path)
    base_by_idx = {r["idx"]: r for r in base}
    live_by_idx = {r["idx"]: r for r in live}
    common = sorted(set(base_by_idx) & set(live_by_idx),
                    key=lambda x: (len(x), x))
    out = {
        "baseline": str(base_path),
        "live": str(live_path),
        "comparison_order": "idx (ordenado antes de comparar)",
        "rows_baseline": len(base),
        "rows_live": len(live),
        "rows_compared": len(common),
        "rows_equal": len(base) == len(live) and len(common) == len(base),
        "columns_baseline": list(base[0].keys()) if base else [],
        "columns_live": list(live[0].keys()) if live else [],
        "strict_diffs": 0,
        "metadata_diffs": 0,
        "per_column": {},
        "first_diffs": [],
        "row_diff_indices": [],
    }
    if not out["rows_equal"]:
        out["note"] = ("linhas diferentes -> comparacao apenas sobre o "
                       "prefixo comum (idx alinhado); nao e' equivalencia")
        if len(base) > len(live):
            out["missing_in_live"] = [i for i in base_by_idx
                                      if i not in live_by_idx][:50]
        else:
            out["extra_in_live"] = [i for i in live_by_idx
                                    if i not in base_by_idx][:50]

    cols = [c for c in (list(base[0].keys()) if base else [])]
    strict = strict_cols or [c for c in cols if c not in METADATA_COLS]
    for i, idx in enumerate(common):
        b, l = base_by_idx[idx], live_by_idx[idx]
        row_diff = []
        for c in cols:
            if b.get(c) != l.get(c):
                d = out["per_column"].setdefault(
                    c, {"n": 0, "strict": c in strict})
                d["n"] += 1
                if c in strict:
                    out["strict_diffs"] += 1
                    if len(out["first_diffs"]) < 20:
                        out["first_diffs"].append(
                            {"idx": b.get("idx"), "row": i, "column": c,
                             "baseline": b.get(c), "live": l.get(c)})
                else:
                    out["metadata_diffs"] += 1
                row_diff.append(c)
        if row_diff and len(out["row_diff_indices"]) < 200:
            out["row_diff_indices"].append(
                {"idx": b.get("idx"), "columns": row_diff})
    out["ok"] = out["rows_equal"] and out["strict_diffs"] == 0
    return out


def selftest_hold_cap(hold: float = 5.0):
    """Auto-teste do teto de seguranca das sessoes EM ESPERA (V-C 1+3).

    Nos datasets avaliados o caminho raramente dispara (o V-C 1+3 exige uma
    media de intervalo fora do anchor num servico que NUNCA excedeu os CSs),
    por isso este mini-teste dirige o estado directamente: fecha uma sessao
    com a media fora do anchor, espera que entre em espera e avanca o relogio
    alem do teto. Prova que o teto existe, que e' rijo e que liberta o estado.
    """
    sys.path.insert(0, str(ROOT / "tools"))
    from ids_live import (DEFAULT_MODEL, LiveIDS, _load_thresholds,
                          load_json)

    model = load_json(ROOT / DEFAULT_MODEL)
    thresholds = _load_thresholds(model, None, ROOT)
    eng = LiveIDS(model, thresholds,
                  ROOT / "results" / "ids_live_validation",
                  session_hold_timeout=hold, write_outputs=False,
                  alert_stream=None)

    svc, tl, sender = "0x1234", "NOTIFICATION", "192.168.1.50"
    key = f"{svc}|{sender}#0"
    anchor = eng.interval.get(f"{svc}|{tl}", {})
    s = eng._session(key, svc, f"{svc}|{sender}")
    s["by_type"][tl] = [max(anchor.get("max", 0.0) * 3, 999.0)]
    s["last_ts"] = 100.0
    s["first_ts"] = 100.0

    steps = {}
    eng._close_session(key, now=100.0)
    steps["sessao_fechada_com_desvio"] = bool(s["closed"] and s["deviates"])
    steps["entrou_em_espera"] = key in eng.waiting_cs[svc]
    steps["prazo_no_teto"] = (s["hold_deadline"] == 100.0 + hold
                              and eng.session_hold_timeout == hold)

    eng._expire_holds(100.0 + hold - 0.1)
    steps["aguarda_antes_do_teto"] = not s["hold_expired"]

    eng._expire_holds(100.0 + hold + 0.1)
    steps["forcada_no_teto"] = bool(s["hold_expired"])
    steps["removida_da_espera"] = key not in eng.waiting_cs[svc]
    steps["sem_envenenamento"] = not s["interval_poisoned"]
    steps["contada"] = eng.counts["sessions_hold_expired"] == 1

    # e' mesmo finalizada (flush) e libertada?
    s["pending"].append((0, 100.0, "100.000000", "0", svc, sender, "", tl,
                         "", 0, 0))
    eng.pending_rows += 1
    rows = eng.flush_ready(now=100.0 + hold + 10.0)
    steps["finalizada_sem_envenenar"] = (
        len(rows) == 1 and rows[0]["final_anomaly"] == 0
        and rows[0]["session_deviates"] == 1
        and rows[0]["session_mean_dt_res"] != "")
    steps["estado_libertado"] = key not in eng.sessions

    return {"ok": all(steps.values()), "hold_timeout_s": hold,
            "steps": steps}


def metrics(path: Path, label_col="label"):
    rows = load_csv(path)
    atk = [r for r in rows if r.get(label_col) == "1"]
    nor = [r for r in rows if r.get(label_col) == "0"]
    final = [r for r in rows if r.get("final_anomaly") == "1"]
    rt = [r for r in rows if r.get("alert_transition") == "1"]
    return {
        "rows": len(rows),
        "attack": len(atk),
        "normal": len(nor),
        "alert_transition": len(rt),
        "final_flagged": len(final),
        "tp_final": sum(1 for r in atk if r.get("final_anomaly") == "1"),
        "fp_final": sum(1 for r in nor if r.get("final_anomaly") == "1"),
        "tpr_final": (sum(1 for r in atk if r.get("final_anomaly") == "1")
                      / len(atk)) if atk else None,
        "fpr_final": (sum(1 for r in nor if r.get("final_anomaly") == "1")
                      / len(nor)) if nor else None,
    }


def diff_columns(base_path: Path, live_path: Path):
    """Conta as diferencas celula-a-celula por coluna (alinhado pelo `idx`)."""
    base = {r["idx"]: r for r in load_csv(base_path)}
    live = {r["idx"]: r for r in load_csv(live_path)}
    common = sorted(set(base) & set(live), key=lambda x: (len(x), x))
    cols = list(next(iter(base.values())).keys()) if base else []
    per = {}
    for idx in common:
        b, l = base[idx], live[idx]
        for c in cols:
            if b.get(c) != l.get(c):
                per[c] = per.get(c, 0) + 1
    return {"rows_baseline": len(base), "rows_live": len(live),
            "rows_compared": len(common), "per_column": per,
            "columns_with_diff": sorted(per)}


def run_live(dataset: str, out_dir: Path, emit_from: int, labels_csv=None,
             quiet=True, extra=None):
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(ROOT / "tools" / "ids_live.py"),
           "--pcap", str(ROOT / "datasets" /
                         ("normal" if dataset.startswith("normal")
                          else "attack") / f"{dataset}.pcap"),
           "--out-dir", str(out_dir), "--name", dataset,
           "--emit-from-index", str(emit_from)]
    if labels_csv:
        cmd += ["--labels-csv", str(ROOT / labels_csv)]
    if extra:
        cmd += list(extra)
    if quiet:
        cmd += ["--quiet-alerts"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0:
        raise SystemExit(f"ids_live falhou p/ {dataset}:\n{proc.stderr}")
    return proc.stderr.strip().splitlines()[-1] if proc.stderr else ""


def check_max_age(dataset, emit_from, labels, baseline, max_age, out_root):
    """Valida a variante de operacao `--session-max-age <max_age>`.

    Criterio (formal, o mesmo padrao de evidencia dos restantes):
      * `realtime_*.csv` tem de ser IDENTICO ao baseline (0 diffs estritas) --
        o Algoritmo 1 nao conhece sessoes;
      * no `retro_*.csv`, as colunas do **Algoritmo 1** tem de ser identicas;
        as colunas do **Algoritmo 2** podem mudar na fronteira do corte (cortar
        uma sessao parte a janela retroactiva V-C 2) e a metadata da particao
        das sessoes muda por definicao -- ambas sao quantificadas;
      * as metricas (TP/FP/TPR/FPR) sao reportadas com o delta.
    """
    live_dir = out_root / f"{dataset}_maxage{int(max_age)}"
    run_live(dataset, live_dir, emit_from, labels_csv=labels,
             extra=["--session-max-age", str(max_age)])

    entry = {"max_age_s": max_age,
             "out_dir": str(live_dir.relative_to(ROOT))}
    b_rt = sorted(baseline.glob(f"realtime_use_ip_*_{dataset}.csv"))[0]
    entry["realtime"] = compare(b_rt, live_dir / f"realtime_{dataset}.csv")

    b_ro = sorted(baseline.glob(f"retro_use_ip_*_{dataset}.csv"))[0]
    per = diff_columns(b_ro, live_dir / f"retro_{dataset}.csv")
    alg1 = {c: n for c, n in per["per_column"].items() if c in ALG1_COLS}
    alg2 = {c: n for c, n in per["per_column"].items() if c in ALG2_COLS}
    meta = {c: n for c, n in per["per_column"].items()
            if c in SESSION_META_COLS}
    other = {c: n for c, n in per["per_column"].items()
             if c not in ALG1_COLS and c not in ALG2_COLS
             and c not in SESSION_META_COLS and c not in METADATA_COLS}
    entry["retro"] = {
        "rows_compared": per["rows_compared"],
        "per_column": per["per_column"],
        "columns_with_diff": per["columns_with_diff"],
        "alg1_diffs": alg1,
        "alg1_diff_count": sum(alg1.values()),
        "alg2_diffs": alg2,
        "alg2_diff_count": sum(alg2.values()),
        "session_metadata_diffs": meta,
        "other_diffs": other,
    }
    entry["metrics"] = {
        "baseline": metrics(b_ro),
        "max_age": metrics(live_dir / f"retro_{dataset}.csv"),
    }
    entry["metrics_equal"] = (entry["metrics"]["baseline"]
                              == entry["metrics"]["max_age"])
    entry["metrics_delta"] = {
        k: (entry["metrics"]["max_age"][k] - entry["metrics"]["baseline"][k])
        for k in ("final_flagged", "tp_final", "fp_final")
    }
    stats_path = live_dir / f"stats_{dataset}.json"
    entry["live_stats"] = (json.loads(stats_path.read_text())
                           if stats_path.exists() else None)
    entry["ok"] = (entry["realtime"]["ok"] and entry["retro"]["alg1_diff_count"] == 0
                   and not entry["retro"]["other_diffs"])
    return entry


def main():
    ap = argparse.ArgumentParser(
        description="Valida que o modo online reproduz o baseline_v3 pacote a "
                    "pacote.")
    ap.add_argument("--attack", action="append", default=None,
                    help="dataset de ataque (repetivel; default: ANEpc-a1, "
                         "ARR-Res-a1 e ANEc-a1. ARR-Req-a1 NAO serve: o pcap "
                         "em disco nao e' o congelado, ver "
                         "nota_divergencia_arrreqa1.md)")
    ap.add_argument("--normal", action="append", default=None)
    ap.add_argument("--max-age", type=float, default=60.0,
                    help="idade maxima de sessao a validar como variante de "
                         "operacao (--session-max-age). 0 = nao validar")
    ap.add_argument("--skip-max-age", action="store_true",
                    help="nao corre a variante --session-max-age")
    ap.add_argument("--identity", default="ip")
    ap.add_argument("--baseline", default="results/baseline_v3/ip")
    ap.add_argument("--out", default="results/ids_live_validation/report.json")
    args = ap.parse_args()

    baseline = ROOT / args.baseline
    if not baseline.exists():
        raise SystemExit(f"ERRO: {baseline} nao existe")

    attacks = args.attack or ["ANEpc-a1", "ARR-Res-a1", "ANEc-a1"]
    normals = args.normal or ["normal_rr"]

    # holdout E1 do baseline_v3: deteccao so nos ultimos 30% de cada normal.
    cases = []
    for dataset in attacks:
        labels = f"datasets/attack/{dataset}.csv"
        if not (ROOT / labels).exists():
            raise SystemExit(f"ERRO: {labels} nao existe (labels p/ metricas)")
        cases.append((dataset, 0, labels))
    for dataset in normals:
        rows_normal = sum(1 for _ in open(ROOT / "features" /
                                          f"{dataset}.csv")) - 1
        cases.append((dataset, int(rows_normal * 0.7), None))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "tools/validate_ids_live.py",
        "mode": "replay deterministico (--pcap, timestamps originais, "
                "sem jitter de rede)",
        "baseline": str(baseline.relative_to(ROOT)),
        "model": f"{args.baseline}/realtime_model_use_ip_h30.json",
        "identity": args.identity,
        "datasets": {},
        "hold_cap_selftest": selftest_hold_cap(),
        "ok": True,
    }
    if not report["hold_cap_selftest"]["ok"]:
        report["ok"] = False

    for dataset, emit_from, labels in cases:
        live_dir = ROOT / "results" / "ids_live_validation" / dataset
        run_live(dataset, live_dir, emit_from, labels_csv=labels)

        entry = {"emit_from_index": emit_from, "rows_warmed": emit_from}
        for kind in ("realtime", "retro"):
            # nomes: realtime_use_ip_h30_<ds>.csv / retro_use_ip_h30_<ds>.csv
            matches = sorted(baseline.glob(f"{kind}_use_ip_*_{dataset}.csv"))
            if not matches:
                raise SystemExit(
                    f"ERRO: sem baseline para {dataset} ({kind}) em "
                    f"{baseline}; o dataset nao foi avaliado no baseline_v3?")
            bpath = matches[0]
            lpath = live_dir / f"{kind}_{dataset}.csv"
            entry[kind] = compare(bpath, lpath)
        matches = sorted(baseline.glob(f"retro_use_ip_*_{dataset}.csv"))
        b_retro = matches[0]
        entry["metrics"] = {
            "baseline": metrics(b_retro),
            "live": metrics(live_dir / f"retro_{dataset}.csv"),
        }
        entry["metrics_equal"] = (
            entry["metrics"]["baseline"] == entry["metrics"]["live"])
        # uso de memoria/tempo do motor (teto de seguranca de sessoes em espera)
        stats_path = live_dir / f"stats_{dataset}.json"
        entry["live_stats"] = (json.loads(stats_path.read_text())
                               if stats_path.exists() else None)
        ok = (entry["realtime"]["ok"] and entry["retro"]["ok"]
              and entry["metrics_equal"])
        report["datasets"][dataset] = {"ok": ok, **entry}
        if not ok:
            report["ok"] = False

    # --- variante de operacao: --session-max-age (corte das sessoes) --------
    # O default do ids_live.py e' 0 (sem corte, equivalencia exacta). Esta
    # variante e' a recomendacao para operacao longa: formaliza-se aqui o que
    # muda (metadata da particao das sessoes) e o que NAO muda (classificacao
    # e metricas).
    if not args.skip_max_age and args.max_age > 0:
        ma = {"max_age_s": args.max_age,
              "rationale": "variante de operacao de longa duracao; o default "
                           "do ids_live.py continua a ser 0 (equivalencia "
                           "exacta com o baseline_v3)",
              "expected_deviation": "cortar uma sessao PARTE a janela "
                                    "retroactiva V-C 2: os hits de um lado da "
                                    "fronteira ja' nao contaminam as linhas do "
                                    "outro lado. Afeta so' as linhas a menos de "
                                    "T=3 s da fronteira; o Algoritmo 1 e' "
                                    "inalterado.",
              "datasets": {}, "ok": True}
        for dataset, emit_from, labels in cases:
            entry = check_max_age(dataset, emit_from, labels, baseline,
                                  args.max_age,
                                  ROOT / "results" / "ids_live_validation")
            ma["datasets"][dataset] = entry
            if not entry["ok"]:
                ma["ok"] = False
        report["session_max_age"] = ma
        if not ma["ok"]:
            report["ok"] = False

    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    for name, d in report["datasets"].items():
        rt, ro = d["realtime"], d["retro"]
        status = "EQUIVALENTE" if d["ok"] else "DIVERGE"
        st = d.get("live_stats") or {}
        print(f"[validate] {name}: {status} | "
              f"realtime rows={rt['rows_live']} strict_diffs={rt['strict_diffs']} "
              f"| retro rows={ro['rows_live']} strict_diffs={ro['strict_diffs']} "
              f"| comparadas={rt['rows_compared']}"
              f"| metrics_equal={d['metrics_equal']}")
        if rt.get("note"):
            print(f"    !! {rt['note']}")
        for kind in ("realtime", "retro"):
            n = d[kind].get("per_column") or {}
            if n:
                top = sorted(n.items(), key=lambda kv: -kv[1]["n"])[:6]
                print(f"    {kind} diffs por coluna: "
                      + ", ".join(f"{c}={v['n']}" for c, v in top))
        print(f"    sessoes={st.get('sessions')} "
              f"pruned={st.get('sessions_pruned')} "
              f"hold_expired={st.get('sessions_hold_expired')} "
              f"cut={st.get('sessions_cut')} "
              f"max_registos_buffer={st.get('max_records_buffered')} "
              f"escritos_em_fluxo={st.get('retro_rows_streamed')} "
              f"teto={st.get('session_hold_timeout_s')}s "
              f"max_idade={st.get('session_max_age_s')}s")
        if not d["ok"]:
            for kind in ("realtime", "retro"):
                if not d[kind]["ok"]:
                    for x in d[kind]["first_diffs"][:5]:
                        print(f"    {kind}: {x}")
    hc = report["hold_cap_selftest"]
    print(f"[validate] teto de sessoes em espera (--session-hold-timeout): "
          f"{'OK' if hc['ok'] else 'FALHOU'} "
          f"({hc['hold_timeout_s']:.0f}s, "
          f"{sum(hc['steps'].values())}/{len(hc['steps'])} passos)")
    if not hc["ok"]:
        print(f"    passos falhados: "
              f"{[k for k, v in hc['steps'].items() if not v]}")

    ma = report.get("session_max_age")
    if ma:
        print(f"[validate] variante --session-max-age {ma['max_age_s']:.0f}s "
              f"(operacao longa; default do ids_live.py continua 0):")
        for name, d in ma["datasets"].items():
            st = d.get("live_stats") or {}
            print(f"    {name}: {'OK' if d['ok'] else 'FALHOU'} | "
                  f"realtime strict_diffs={d['realtime']['strict_diffs']} | "
                  f"retro: A1={d['retro']['alg1_diff_count']} "
                  f"A2(fronteira)={d['retro']['alg2_diff_count']} "
                  f"meta_sessao={d['retro']['session_metadata_diffs']} "
                  f"outros={d['retro']['other_diffs']} | "
                  f"metrics_equal={d['metrics_equal']} "
                  f"delta={d['metrics_delta']} | "
                  f"sessoes_cortadas={st.get('sessions_cut')} "
                  f"escritas_em_fluxo={st.get('retro_rows_streamed')}")
    print(f"[validate] relatorio -> {out}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
