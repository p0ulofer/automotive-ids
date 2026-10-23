#!/usr/bin/env python3
"""Fase 6 (extensao) -- compara o IDS no host vs. o IDS dentro do ecu2.

As duas execucoes sao AO VIVO e veem a mesma perna net1:

  * host    : ids_live.py no host (veth peer da interface net1 do ecu2);
  * sidecar : ids_live.py dentro do network namespace do ecu2.

O objectivo NAO e' 0/0 bit-a-bit: os timestamps sao de captura e o jitter de
agendamento entra nas features discretizadas (ver docs/ids_live.md sec. 8,
Estagio B). O criterio e' "mesmas classificacoes dentro do envelope de jitter":

  - >= 99% das linhas emparelhadas (a mesma mensagem dos dois lados);
  - <= 0,5% de linhas com `state` diferente (Estagio B: 0,06-0,24%);
  - <= 5 alertas de diferenca no Algoritmo 1 (Estagio B: 2-3);
  - <= 10% de linhas com `final_anomaly` diferente (Estagio B: 7,6%);
  - TPR com diferenca absoluta <= 0,02.

As metricas usam o MAC do atacante (como o `pcap_to_csv --attacker-mac`), e
NAO a coluna `label` por indice: numa captura ao vivo com SD e possiveis
duplicacoes, a atribuicao por indice do CSV do dataset nao e' fiavel.

Uso:
    python3 tools/compare_ids_location.py \
        --host-dir results/ids_live_ecu2/ANEpc-a1/host \
        --sidecar-dir results/ids_live_ecu2/ANEpc-a1/sidecar \
        --name ANEpc-a1 \
        --attacker-mac d6:12:d3:af:c3:10 \
        --reference-pcap results/ids_live_ecu2/ANEpc-a1/mirror_host.pcap \
        --out-json results/ids_live_ecu2/ANEpc-a1/compare_ANEpc-a1.json
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))

CLASS_COLS = {
    "realtime": ["state", "in_model", "alert_transition"],
    "retro": ["alert_transition", "retro_anomaly", "final_anomaly",
              "cs_armed", "session_deviates", "poisoned_by", "session_key"],
}
NUMERIC_COLS = {
    "realtime": ["dt_prev_res", "n_cs", "sender_count", "checkable",
                 "avg_full", "is_new_stream", "cs_armed"],
    "retro": ["session_mean_dt_res", "cs_armed", "session_deviates",
              "retro_anomaly", "final_anomaly"],
}
ALL_COLS = {
    "realtime": ["state", "in_model", "alert_transition", "n_cs",
                 "sender_count", "cs_armed", "is_new_stream", "checkable",
                 "avg_full", "dt_prev_res", "src_mac"],
    "retro": ["alert_transition", "cs_armed", "session_key",
              "session_mean_dt_res", "session_deviates", "poisoned_by",
              "retro_anomaly", "final_anomaly", "src_mac"],
}


def _ts(row):
    try:
        return float(row.get("timestamp", ""))
    except (TypeError, ValueError):
        return float("nan")


def _mac(value):
    return str(value or "").strip().lower()


def _label(row, attacker_mac):
    """1 se a linha foi originada pelo MAC do atacante (como no dataset)."""
    if attacker_mac:
        return 1 if _mac(row.get("src_mac")) == attacker_mac else 0
    return 1 if str(row.get("label", "")).strip() == "1" else 0


def _load_csv(path):
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    rows.sort(key=_ts)
    return rows


def _find_file(directory, kind, name):
    path = Path(directory)
    if name:
        cand = path / f"{kind}_{name}.csv"
        if cand.exists():
            return cand
    matches = sorted(path.glob(f"{kind}_*.csv"))
    if not matches:
        raise FileNotFoundError(f"sem {kind}_*.csv em {directory}")
    if len(matches) > 1:
        raise RuntimeError(
            f"mais de um {kind}_*.csv em {directory}: "
            f"{[m.name for m in matches]}; use --name")
    return matches[0]


def _align(host_rows, side_rows, tol=0.005):
    """Emparelha a mesma mensagem dos dois lados, por stream_key e timestamp.

    A ordenacao e' feita por stream: uma linha em falta numa stream nao
    desloca as restantes. A tolerancia de 5 ms cobre a diferenca de ponto de
    captura (veth peer vs. interface dentro do netns) sem confundir mensagens
    periodicas (10 ms no pior caso, notificacoes).
    """
    by_stream = defaultdict(list)
    for row in sorted(side_rows, key=_ts):
        by_stream[row.get("stream_key", "")].append(row)
    ptr = defaultdict(int)
    unmatched_side = set()
    pairs, unmatched_host = [], []
    for h in sorted(host_rows, key=_ts):
        sk = h.get("stream_key", "")
        arr = by_stream.get(sk, [])
        i = ptr[sk]
        while i < len(arr) and _ts(arr[i]) < _ts(h) - tol:
            unmatched_side.add(id(arr[i]))
            i += 1
        if i < len(arr) and abs(_ts(arr[i]) - _ts(h)) <= tol:
            pairs.append((h, arr[i]))
            i += 1
        else:
            unmatched_host.append(h)
        ptr[sk] = i
    for sk, arr in by_stream.items():
        for row in arr[ptr[sk]:]:
            unmatched_side.add(id(row))
    unmatched = [r for r in side_rows if id(r) in unmatched_side]
    return pairs, unmatched_host, unmatched


def _pct(n, d):
    return round(100.0 * n / d, 4) if d else None


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _compare_columns(pairs, kind):
    result = {}
    for col in ALL_COLS[kind]:
        diffs = []
        vals = []
        for h, s in pairs:
            hv, sv = h.get(col, ""), s.get(col, "")
            if hv != sv:
                diffs.append({
                    "idx_host": h.get("idx"), "idx_side": s.get("idx"),
                    "timestamp_host": h.get("timestamp"),
                    "timestamp_side": s.get("timestamp"),
                    "stream_key": h.get("stream_key", ""),
                    "host": hv, "side": sv,
                })
            hn, sn = _num(hv), _num(sv)
            if hn is not None and sn is not None:
                vals.append(abs(hn - sn))
        item = {
            "column": col,
            "diff_rows": len(diffs),
            "diff_pct": _pct(len(diffs), len(pairs)),
            "classification": col in CLASS_COLS[kind],
            "examples": diffs[:8],
        }
        if vals:
            vals.sort()
            item.update({
                "numeric_rows": len(vals),
                "numeric_median_abs_diff": round(statistics.median(vals), 9),
                "numeric_p95_abs_diff": round(
                    vals[int(0.95 * (len(vals) - 1))], 9),
                "numeric_max_abs_diff": round(vals[-1], 9),
            })
        result[col] = item
    return result


def _metrics(rows, attacker_mac, pred_col):
    tp = fp = tn = fn = 0
    for row in rows:
        y = _label(row, attacker_mac)
        yhat = 1 if str(row.get(pred_col, "")).strip() == "1" else 0
        if y == 1 and yhat == 1:
            tp += 1
        elif y == 1 and yhat == 0:
            fn += 1
        elif y == 0 and yhat == 1:
            fp += 1
        else:
            tn += 1
    attack, normal = tp + fn, fp + tn
    return {
        "rows": len(rows), "attack": attack, "normal": normal,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "tpr": round(tp / attack, 6) if attack else None,
        "fpr": round(fp / normal, 6) if normal else None,
    }


def _alert_set(rows):
    return sorted(
        (round(_ts(r), 6), r.get("stream_key", ""),
         r.get("state", "") if "state" in r else r.get("poisoned_by", ""))
        for r in rows if str(r.get("alert_transition", "")).strip() == "1"
    )


def _msg_key(row):
    """Chave estavel para a mesma mensagem nos dois formatos de CSV.

    O ids_live.py escreve `type_label`/`stream_key`; o pcap_to_csv escreve
    `message_type_name` e nao escreve `stream_key`. O triplo
    (src_mac, src_ip, service_id) existe nos dois e identifica a mensagem sem
    depender do formato (o objectivo e' provar que o sidecar VE' as mesmas
    mensagens que o pcap de referencia).
    """
    return (str(row.get("src_mac", "")).strip().lower(),
            str(row.get("src_ip", "")).strip(),
            str(row.get("service_id", "")).strip())


def _pcap_check(pcap_path, side_rows):
    """Confronta o pcap de referencia (mirror do host) com o CSV do sidecar.

    Prova, de forma independente do IDS, que o sidecar ve' as MESMAS mensagens
    que a testemunha passiva no host: a captura e' feita no par de veth
    `mirrorh`/`mirror0`, que recebe uma copia por trama (ao contrario da
    bridge, que duplica). Nao entra no veredicto de classificacao, mas e' a
    evidencia directa de que a localizacao nao muda o trafego observado.
    """
    if not pcap_path:
        return {"available": False, "reason": "sem --reference-pcap"}
    pcap = Path(pcap_path)
    if not pcap.exists():
        return {"available": False, "reason": f"pcap nao encontrado: {pcap}"}
    try:
        from scapy.all import PcapReader
        from pcap_to_csv import packet_to_rows
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"scapy indisponivel: {exc}"}

    pcap_rows = []
    with PcapReader(str(pcap)) as reader:
        for pkt in reader:
            pcap_rows.extend(packet_to_rows(pkt))
    if not pcap_rows:
        return {"available": False, "reason": "pcap sem mensagens SOME/IP"}
    pcap_rows.sort(key=_ts)
    lo, hi = _ts(pcap_rows[0]), _ts(pcap_rows[-1])
    side_in = sorted(
        [r for r in side_rows if lo - 0.05 <= _ts(r) <= hi + 0.05], key=_ts)

    side_seq = [_msg_key(r) for r in side_in]
    pcap_seq = [_msg_key(r) for r in pcap_rows]
    side_counts = Counter(side_seq)
    pcap_counts = Counter(pcap_seq)
    missing = pcap_counts - side_counts   # no pcap, ausente no sidecar
    extra = side_counts - pcap_counts     # no sidecar, ausente no pcap

    ts_diff = None
    if side_seq == pcap_seq:
        diffs = [abs(_ts(a) - _ts(b)) for a, b in zip(side_in, pcap_rows)]
        if diffs:
            ts_diff = {
                "max_ms": round(max(diffs) * 1000.0, 6),
                "median_ms": round(statistics.median(diffs) * 1000.0, 6),
            }

    return {
        "available": True,
        "pcap": str(pcap),
        "pcap_rows": len(pcap_rows),
        "sidecar_rows_in_pcap_window": len(side_in),
        "count_equal": len(side_in) == len(pcap_rows),
        "message_multiset_equal": not missing and not extra,
        "sequence_order_equal": side_seq == pcap_seq,
        "missing_in_sidecar": [
            {"key": list(k), "count": v} for k, v in missing.most_common(5)],
        "extra_in_sidecar": [
            {"key": list(k), "count": v} for k, v in extra.most_common(5)],
        "timestamp_diff": ts_diff,
        "pcap_window": {"first": pcap_rows[0].get("timestamp"),
                        "last": pcap_rows[-1].get("timestamp")},
    }


def main():
    ap = argparse.ArgumentParser(
        description="Compara o IDS online no host vs. dentro do ecu2 "
                    "(mesmo trafego, localizacao diferente).")
    ap.add_argument("--host-dir", required=True)
    ap.add_argument("--sidecar-dir", required=True)
    ap.add_argument("--name", default=None,
                    help="prefixo dos ficheiros (ex.: ANEpc-a1)")
    ap.add_argument("--attacker-mac", default=None,
                    help="MAC do atacante; a label e' derivada de src_mac")
    ap.add_argument("--reference-pcap", default=None,
                    help="pcap do MESMO stream (ex.: mirror do host), para "
                         "provar que o sidecar ve' as mesmas mensagens")
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--time-margin", type=float, default=1.0,
                    help="margem (s) em volta da janela de ataque (default 1.0)")
    ap.add_argument("--align-tol-ms", type=float, default=5.0,
                    help="tolerancia de emparelhamento (ms, default 5)")
    args = ap.parse_args()

    attacker = _mac(args.attacker_mac)
    name = args.name
    if not name:
        matches = sorted(Path(args.host_dir).glob("realtime_*.csv"))
        if matches:
            name = matches[0].stem.replace("realtime_", "", 1)

    host_r = _load_csv(_find_file(args.host_dir, "realtime", name))
    side_r = _load_csv(_find_file(args.sidecar_dir, "realtime", name))
    host_t = _load_csv(_find_file(args.host_dir, "retro", name))
    side_t = _load_csv(_find_file(args.sidecar_dir, "retro", name))

    # --- janela de ataque: linhas cujo src_mac e' o do atacante ------------
    host_atk = [r for r in host_r if _label(r, attacker) == 1]
    side_atk = [r for r in side_r if _label(r, attacker) == 1]
    if host_atk or side_atk:
        firsts = [_ts(r) for r in (host_atk + side_atk)]
        lasts = [_ts(r) for r in (host_atk + side_atk)]
        t0 = min(firsts) - args.time_margin
        t1 = max(lasts) + args.time_margin
        window_source = "attacker-mac"
    else:
        t0 = max(min(_ts(r) for r in host_r), min(_ts(r) for r in side_r))
        t1 = min(max(_ts(r) for r in host_r), max(_ts(r) for r in side_r))
        window_source = "common-capture"
    host_rw = [r for r in host_r if t0 <= _ts(r) <= t1]
    side_rw = [r for r in side_r if t0 <= _ts(r) <= t1]
    host_tw = [r for r in host_t if t0 <= _ts(r) <= t1]
    side_tw = [r for r in side_t if t0 <= _ts(r) <= t1]

    tol = args.align_tol_ms / 1000.0
    r_pairs, r_uh, r_us = _align(host_rw, side_rw, tol)
    t_pairs, t_uh, t_us = _align(host_tw, side_tw, tol)

    r_cols = _compare_columns(r_pairs, "realtime")
    t_cols = _compare_columns(t_pairs, "retro")

    r_metrics = {
        "host": _metrics([h for h, _ in r_pairs], attacker, "alert_transition"),
        "sidecar": _metrics([s for _, s in r_pairs], attacker,
                            "alert_transition"),
    }
    t_metrics = {
        "host": _metrics([h for h, _ in t_pairs], attacker, "final_anomaly"),
        "sidecar": _metrics([s for _, s in t_pairs], attacker,
                            "final_anomaly"),
    }

    host_alerts = _alert_set(host_rw)
    side_alerts = _alert_set(side_rw)
    alert_delta = len(side_alerts) - len(host_alerts)
    final_diff = t_cols.get("final_anomaly", {}).get("diff_rows", 0)
    state_diff = r_cols.get("state", {}).get("diff_rows", 0)
    paired = min(len(r_pairs), len(t_pairs))
    union_rows = max(len(host_rw), len(side_rw))
    paired_pct = _pct(len(r_pairs), union_rows)
    state_pct = _pct(state_diff, len(r_pairs))
    final_pct = _pct(final_diff, len(t_pairs))
    tpr_h = r_metrics["host"]["tpr"]
    tpr_s = r_metrics["sidecar"]["tpr"]
    tpr_delta = (abs(tpr_h - tpr_s)
                 if tpr_h is not None and tpr_s is not None else None)

    pcap_check = _pcap_check(args.reference_pcap, side_r)

    cond = {
        "paired_pct_ge_99": (paired_pct is not None and paired_pct >= 99.0),
        "state_diff_pct_le_0_5": (state_pct is not None and state_pct <= 0.5),
        "alert_delta_le_5": abs(alert_delta) <= 5,
        "final_diff_pct_le_10": (final_pct is not None and final_pct <= 10.0),
        "tpr_delta_le_0_02": (tpr_delta is not None and tpr_delta <= 0.02),
    }
    equivalent = all(cond.values())
    report = {
        "tool": "tools/compare_ids_location.py",
        "phase": "6-extension-ids-in-ecu2",
        "name": name,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "host_dir": str(Path(args.host_dir).resolve()),
            "sidecar_dir": str(Path(args.sidecar_dir).resolve()),
            "attacker_mac": attacker,
            "reference_pcap": str(Path(args.reference_pcap).resolve())
            if args.reference_pcap else None,
        },
        "window": {
            "source": window_source,
            "first": t0, "last": t1, "margin_s": args.time_margin,
            "host_realtime_rows": len(host_rw),
            "sidecar_realtime_rows": len(side_rw),
            "host_retro_rows": len(host_tw),
            "sidecar_retro_rows": len(side_tw),
        },
        "alignment": {
            "tolerance_ms": args.align_tol_ms,
            "realtime_pairs": len(r_pairs),
            "realtime_unmatched_host": len(r_uh),
            "realtime_unmatched_sidecar": len(r_us),
            "retro_pairs": len(t_pairs),
            "retro_unmatched_host": len(t_uh),
            "retro_unmatched_sidecar": len(t_us),
            "unmatched_host_examples": [
                {"timestamp": r.get("timestamp"),
                 "stream_key": r.get("stream_key", "")} for r in r_uh[:8]],
            "unmatched_sidecar_examples": [
                {"timestamp": r.get("timestamp"),
                 "stream_key": r.get("stream_key", "")} for r in r_us[:8]],
        },
        "realtime_columns": r_cols,
        "retro_columns": t_cols,
        "metrics_algorithm1": r_metrics,
        "metrics_algorithm2": t_metrics,
        "alerts": {
            "host_count": len(host_alerts),
            "sidecar_count": len(side_alerts),
            "delta": alert_delta,
            "paired_disagreements": [
                {"timestamp": h.get("timestamp"),
                 "stream_key": h.get("stream_key", ""),
                 "host": h.get("alert_transition"),
                 "sidecar": s.get("alert_transition")}
                for h, s in r_pairs
                if h.get("alert_transition") != s.get("alert_transition")
            ][:8],
        },
        "pcap_check": pcap_check,
        "verdict": {
            "equivalent_within_jitter": equivalent,
            "criteria": cond,
            "summary": (
                f"pares={paired} ({paired_pct}%) | "
                f"state_diff={state_diff} ({state_pct}%) | "
                f"alertas host={len(host_alerts)} sidecar={len(side_alerts)} "
                f"(delta={alert_delta:+d}) | "
                f"final_diff={final_diff} ({final_pct}%) | "
                f"TPR {tpr_h} -> {tpr_s}"),
            "note": (
                "Criterio do Estagio B: ao vivo nao e' 0/0 bit-a-bit. "
                "Os limites sao os do envelope de jitter ja' documentado "
                "(0,06-0,24% state; 2-3 alertas; 7,6% final)."),
        },
    }

    out = Path(args.out_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")

    print(f"[compare_ids_location] {report['verdict']['summary']}")
    print(f"[compare_ids_location] equivalente={equivalent} -> {out}")
    if pcap_check.get("available"):
        print("[compare_ids_location] pcap referencia: "
              f"rows={pcap_check['pcap_rows']} "
              f"sidecar={pcap_check['sidecar_rows_in_pcap_window']} "
              f"count_equal={pcap_check['count_equal']} "
              f"multiset_equal={pcap_check['message_multiset_equal']}")
    return 0 if equivalent else 2


if __name__ == "__main__":
    sys.exit(main())
