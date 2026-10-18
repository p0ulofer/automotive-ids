#!/usr/bin/env python3
"""Diagnosticos D1 e M1 da Fase 5 -- NAO alteram o detetor.

Le apenas os CSVs por-pacote ja produzidos por `ids_realtime.py` (Algoritmo 1) e
`ids_retroactive.py` (Algoritmo 2) num diretorio de resultados congelado.

D1a) Classificacao dos falsos positivos do Algoritmo 1 no holdout dos normais:
       (i)   arranque da media movel (`avg_full=0`, janela W incompleta);
       (ii)  tupla de estado que existe no treino de 100% mas nao no de 70%;
       (iii) tupla de estado nunca vista em nenhum treino.
     Agrupados por (service|tipo, tupla) com contagem e posicao temporal.

D1b) Pacotes SD com o MAC do atacante nos 11 ataques (Subscribe/Offer/SubAck):
     o atacante estabelece sessao SD ou apenas encaminha/adultera? E o estado
     do gatilho de CS (n.o de remetentes) por identidade.

M1a) Separacao da deteccao final em "direta" (o pacote teve hit do Algoritmo 1)
     e "por contagio" (marcado so porque a sessao foi marcada). Idem para FPR.

M1b) TPR/FPR POR SESSAO (sessoes marcadas / total), por classe de sessao
     (ataque pura, normal pura, mistas).

Uso:
    python3 tools/diagnose_ids.py \
        --results-dir results/baseline_v2/ip \
        --results-dir-alt results/baseline_v2/ip_client \
        --model-100 results/baseline_v1/realtime_model_use.json \
        --out results/baseline_v2/diagnose.json
"""
from __future__ import annotations

import argparse
import csv
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ids_common import (  # noqa: E402
    ATTACK_DATASETS,
    DEFAULT_FEATURES_DIR,
    NORMAL_DATASETS,
    load_json,
    save_json,
)

# --- parser SD minimo (copia de tools/pcap_to_csv.py, sem scapy) -------------
_SD_ENTRY = {0x00: "Find", 0x01: "Offer", 0x02: "RequestSvc",
             0x04: "FindEventgroup", 0x05: "PublishEventgroup",
             0x06: "Subscribe", 0x07: "SubAck"}


def _sd_entries(payload_hex):
    """Devolve [(type_name, ttl, service_id)] das entries do payload SD."""
    try:
        b = bytes.fromhex(payload_hex or "")
    except ValueError:
        return []
    if len(b) < 8:
        return []
    elen = struct.unpack(">I", b[4:8])[0]
    off, end = 8, min(8 + elen, len(b))
    out = []
    while off + 16 <= end:
        e = b[off:off + 16]
        out.append((_SD_ENTRY.get(e[0], f"0x{e[0]:02X}"),
                    int.from_bytes(e[9:12], "big"),
                    struct.unpack(">H", e[4:6])[0]))
        off += 16
    return out


def _single(results_dir, pattern, name):
    hits = sorted(Path(results_dir).glob(pattern.format(name=name)))
    if len(hits) != 1:
        raise SystemExit(f"ERRO: esperava 1 ficheiro {pattern.format(name=name)} "
                         f"em {results_dir}, encontrei {len(hits)}: {hits}")
    return hits[0]


def detect_path(results_dir, name):
    return _single(results_dir, "realtime_*_{name}.csv", name)


def retro_path(results_dir, name):
    return _single(results_dir, "retro_*_{name}.csv", name)


# --------------------------------------------------------------------------- #
# D1a
# --------------------------------------------------------------------------- #
def d1a(results_dir, model100):
    tr100 = {k: set(v) for k, v in model100["transitions"].items()}
    classes = Counter()
    cold_in100 = cold_never = 0
    groups = defaultdict(lambda: {"n": 0, "cls": "", "svc_type": "", "state": "",
                                  "ts_min": None, "ts_max": None,
                                  "idx_min": None, "idx_max": None})
    per_ds = {}

    for name in NORMAL_DATASETS:
        rows = list(csv.DictReader(open(detect_path(results_dir, name), newline="")))
        base_ts = float(rows[0]["timestamp"]) if rows else 0.0
        checkable = sum(1 for r in rows if r["checkable"] == "1")
        fp = 0
        for r in rows:
            if not (r["label"] == "0" and r["alert_transition"] == "1"):
                continue
            fp += 1
            svc, tl = r["service_id"], r["type_label"]
            st, af = r["state"], r["avg_full"]
            key = f"{svc}|{tl}"
            in100 = st in tr100.get(key, set())
            if af == "0":
                cls = "i_cold_start"
                cold_in100 += in100
                cold_never += (not in100)
            elif in100:
                cls = "ii_in100_not_in70"
            else:
                cls = "iii_never_seen"
            classes[cls] += 1
            g = groups[(key, st)]
            g["n"] += 1
            g["cls"] = cls
            g["svc_type"] = key
            g["state"] = st
            ts = float(r["timestamp"]) - base_ts
            idx = int(r["idx"])
            g["ts_min"] = ts if g["ts_min"] is None else min(g["ts_min"], ts)
            g["ts_max"] = ts if g["ts_max"] is None else max(g["ts_max"], ts)
            g["idx_min"] = idx if g["idx_min"] is None else min(g["idx_min"], idx)
            g["idx_max"] = idx if g["idx_max"] is None else max(g["idx_max"], idx)
        per_ds[name] = {"checkable": checkable, "a1_fp": fp,
                        "a1_fpr": (fp / checkable) if checkable else None}

    total_fp = sum(per_ds[n]["a1_fp"] for n in per_ds)
    glist = sorted(groups.values(), key=lambda g: (-g["n"], g["svc_type"]))
    dom = max(classes, key=classes.get) if classes else None
    return {
        "per_dataset": per_ds,
        "total_a1_fp": total_fp,
        "classes": dict(classes),
        "dominant": dom,
        "cold_start_breakdown": {"in_100pct_model": cold_in100,
                                 "never_seen": cold_never},
        "groups": glist,
    }


# --------------------------------------------------------------------------- #
# M1
# --------------------------------------------------------------------------- #
def m1(results_dir):
    agg = Counter()
    per_ds = {}
    mixed_all = []
    for name in ATTACK_DATASETS:
        rows = list(csv.DictReader(open(retro_path(results_dir, name), newline="")))
        sessions = defaultdict(lambda: {"n0": 0, "n1": 0, "marked": False,
                                        "trigger": "", "hits1": 0, "hits0": 0})
        c = Counter()
        for r in rows:
            lab = r["label"]
            direct = r["alert_transition"] == "1"
            final = r["final_anomaly"] == "1"
            contagion = final and not direct
            if lab == "1":
                c["attack"] += 1
                if direct:
                    c["attack_direct"] += 1
                if contagion:
                    c["attack_contagion"] += 1
            elif lab == "0":
                c["normal"] += 1
                if direct:
                    c["normal_direct"] += 1
                if contagion:
                    c["normal_contagion"] += 1
            s = sessions[r["session_key"]]
            if lab == "1":
                s["n1"] += 1
            elif lab == "0":
                s["n0"] += 1
            if final:
                s["marked"] = True
            if r["poisoned_by"]:
                s["trigger"] = r["poisoned_by"]
            if direct:
                if lab == "1":
                    s["hits1"] += 1
                else:
                    s["hits0"] += 1

        # contagio TPR/FP repartido pela origem do envenenamento da sessao
        for r in rows:
            if r["final_anomaly"] != "1" or r["alert_transition"] == "1":
                continue
            s = sessions[r["session_key"]]
            origin = "attack" if s["hits1"] > 0 else ("normal" if s["hits0"] > 0 else "none")
            if r["label"] == "1":
                c[f"attack_contagion_{origin}"] += 1
            elif r["label"] == "0":
                c[f"normal_contagion_{origin}"] += 1

        pure_att = [s for s in sessions.values() if s["n1"] > 0 and s["n0"] == 0]
        pure_nrm = [s for s in sessions.values() if s["n0"] > 0 and s["n1"] == 0]
        mixed = [s for s in sessions.values() if s["n0"] > 0 and s["n1"] > 0]
        c["sess_pure_attack"] = len(pure_att)
        c["sess_pure_attack_marked"] = sum(1 for s in pure_att if s["marked"])
        c["sess_pure_normal"] = len(pure_nrm)
        c["sess_pure_normal_marked"] = sum(1 for s in pure_nrm if s["marked"])
        c["sess_mixed"] = len(mixed)
        c["sess_mixed_marked"] = sum(1 for s in mixed if s["marked"])
        per_ds[name] = dict(c)
        for sk, s in sessions.items():
            if s["n0"] > 0 and s["n1"] > 0:
                mixed_all.append({"dataset": name, "session_key": sk, **s})
        agg.update(c)

    return {"aggregate": dict(agg), "per_dataset": per_ds, "mixed_sessions": mixed_all}


# --------------------------------------------------------------------------- #
# D1b
# --------------------------------------------------------------------------- #
def d1b(results_dirs, features_dir):
    feat = Path(features_dir)
    out = {}
    for name in ATTACK_DATASETS:
        att_macs = set()
        sd_total = 0
        sd_by_mac = Counter()
        entries = Counter()
        for r in csv.DictReader(open(feat / f"{name}.csv", newline="")):
            if r["label"] == "1" and r.get("src_mac"):
                att_macs.add(r["src_mac"])
            if r["is_sd"] == "1":
                sd_total += 1
                mac = r.get("src_mac", "")
                sd_by_mac["attacker" if mac in att_macs else "legit"] += 1
                for tn, ttl, _svc in _sd_entries(r["payload_hex"]):
                    entries[(tn, "ttl0" if ttl == 0 else "ttl>0")] += 1
        cs = {}
        for label, d in results_dirs.items():
            if d is None:
                continue
            mx = defaultdict(int)
            armed = set()
            mode = defaultdict(int)
            for r in csv.DictReader(open(detect_path(d, name), newline="")):
                svc = r["service_id"]
                cnt = int(r["sender_count"])
                mx[svc] = max(mx[svc], cnt)
                if r["cs_armed"] == "1":
                    armed.add(svc)
                mode[svc] = max(mode[svc], cnt - int(r["cs_max"]))
            cs[label] = {"max_senders_per_svc": dict(mx),
                         "services_cs_armed": sorted(armed)}
        out[name] = {"attacker_macs": sorted(att_macs),
                     "sd_packets_total": sd_total,
                     "sd_packets_by_origin": dict(sd_by_mac),
                     "sd_entries": {f"{k[0]}/{k[1]}": v for k, v in entries.items()},
                     "cs_trigger": cs}
    return out


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--results-dir-alt", default=None)
    ap.add_argument("--model-100", default="results/baseline_v1/realtime_model_use.json",
                    help="modelo treinado com 100%% dos normais (referencia D1a-ii)")
    ap.add_argument("--features-dir", default=DEFAULT_FEATURES_DIR)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    model100 = load_json(args.model_100)
    dirs = {"ip": args.results_dir}
    if args.results_dir_alt:
        dirs["ip_client"] = args.results_dir_alt

    report = {
        "results_dir": args.results_dir,
        "model_100": args.model_100,
        "D1a": d1a(args.results_dir, model100),
        "D1b": d1b(dirs, args.features_dir),
        "M1": {label: m1(d) for label, d in dirs.items()},
    }

    # ---- impressao -----------------------------------------------------------
    print("=" * 78)
    print("D1a -- Falsos positivos do Algoritmo 1 no holdout dos normais")
    a = report["D1a"]
    for n, v in a["per_dataset"].items():
        print(f"  {n:12s} checkable={v['checkable']:8d} A1_FP={v['a1_fp']:6d} "
              f"A1_FPR={v['a1_fpr']:.4f}")
    print(f"  TOTAL A1_FP={a['total_a1_fp']}  classes={a['classes']}  "
          f"dominante={a['dominant']}")
    print(f"  cold-start breakdown: {a['cold_start_breakdown']}")
    print("  top grupos (service|tipo, tupla):")
    for g in a["groups"][:15]:
        print(f"    n={g['n']:4d} {g['cls']:18s} {g['svc_type']:10s} "
              f"ts[{g['ts_min']:.1f},{g['ts_max']:.1f}] idx[{g['idx_min']},{g['idx_max']}] "
              f"state={g['state']}")

    print("=" * 78)
    print("D1b -- pacotes SD do atacante e gatilho de CS")
    for n, v in report["D1b"].items():
        print(f"  {n:12s} SD={v['sd_packets_total']:4d} "
              f"origem={v['sd_packets_by_origin']} macs_atk={v['attacker_macs']}")
        for lbl, cs in v["cs_trigger"].items():
            print(f"          [{lbl}] max_senders={cs['max_senders_per_svc']} "
                  f"cs_armed={cs['services_cs_armed']}")

    print("=" * 78)
    print("M1 -- direta vs contagio e metricas por sessao")
    for lbl, mm in report["M1"].items():
        c = mm["aggregate"]
        tp = c.get("attack_direct", 0) + c.get("attack_contagion", 0)
        fp = c.get("normal_direct", 0) + c.get("normal_contagion", 0)
        print(f"\n  --- identidade: {lbl} ---")
        print(f"    TPR direta={c.get('attack_direct',0)} "
              f"contagio={c.get('attack_contagion',0)} (total={tp}, "
              f"{100*tp/c['attack']:.1f}%)")
        print(f"    FPR direta={c.get('normal_direct',0)} "
              f"contagio={c.get('normal_contagion',0)} (total={fp}, "
              f"{100*fp/c['normal']:.1f}%)")
        print(f"    contagio TP por origem: ataque="
              f"{c.get('attack_contagion_attack',0)} normal="
              f"{c.get('attack_contagion_normal',0)} "
              f"none={c.get('attack_contagion_none',0)}")
        print(f"    contagio FP por origem: ataque="
              f"{c.get('normal_contagion_attack',0)} normal="
              f"{c.get('normal_contagion_normal',0)} "
              f"none={c.get('normal_contagion_none',0)}")
        print(f"    sessoes ataque-puras marcadas: "
              f"{c.get('sess_pure_attack_marked',0)}/{c.get('sess_pure_attack',0)}")
        print(f"    sessoes normal-puras marcadas: "
              f"{c.get('sess_pure_normal_marked',0)}/{c.get('sess_pure_normal',0)}")
        print(f"    sessoes mistas marcadas: "
              f"{c.get('sess_mixed_marked',0)}/{c.get('sess_mixed',0)}")

    if args.out:
        save_json(report, args.out)
        print(f"\n[diagnose] -> {args.out}")


if __name__ == "__main__":
    main()
