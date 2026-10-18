#!/usr/bin/env python3
"""S1 -- smoke test diagnostico do R3 (nao e' dataset; nao se publica).

Injeta pacotes SOME/IP-SD (OfferService + SubscribeEventgroup) emitidos pelo
ATACANTE (src_ip=192.168.1.50 / MAC do atacante de ARR-Req-a1) num dataset
pequeno (`ARR-Req-a1` truncado a 10 % da duracao, ~= `--scale 0.10`), para
verificar se o gatilho V-C 1 (contagem de CS por servico) arma e se o caminho
V-C 1+3 (desvio de intervalo medio do SD no fim da sessao) dispara.

Nao toca em `datasets/` nem no baseline: escreve os CSVs brutos em
`<out-dir>/raw/`. A Fase 4 e' corrida a seguir com os limiares existentes
(`features/thresholds.json`) e a Fase 5 com o modelo congelado
(`results/baseline_v3/ip|ip_client/realtime_model_use_*_h30.json`).

Uso:
    python3 tools/smoke_s1_sd_injection.py --out-dir /tmp/opencode/s1
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

RAW_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "service_id",
    "instance_id", "method_event_id", "client_id", "session_id", "message_type",
    "message_type_name", "return_code", "return_code_name", "protocol_version",
    "payload_hex", "payload_len", "is_sd", "sd_entries", "sd_options",
    "sd_entry_types", "src_mac", "label",
]

SD_DST = "224.224.224.245"
SD_PORT = "30490"
ATTACKER_IP = "192.168.1.50"


def sd_payload(entry_type, ip, port, eventgroup=None):
    """Frame SD minimo no mesmo layout dos CSVs reais (2.4 -- 40 bytes).

    header(4) + entries_len(4) + entry(16) + options_len(4) + option(12).
    `entry_type`: 0x01 Offer / 0x06 SubscribeEventgroup.
    """
    ip_hex = "".join(f"{int(o):02x}" for o in ip.split("."))
    port_hex = f"{int(port):04x}"
    minor = "00000000" if eventgroup is None else f"{eventgroup:08x}"
    entry = ("%02x" % entry_type) + "00" + "00" + "10" + "1234" + "0001" \
        + "01" + "000003" + minor
    option = "0009" + "04" + "00" + ip_hex + "00" + "11" + port_hex
    payload = "c0000000" + "00000010" + entry + "0000000c" + option
    return payload, len(payload) // 2


def sd_row(ts, entry_type, label_name, session_id, mac):
    """Uma linha bruta de SD do atacante (Offer ou Subscribe)."""
    payload, plen = sd_payload(entry_type, ATTACKER_IP, SD_PORT,
                               eventgroup=1 if entry_type == 0x06 else None)
    return {
        "timestamp": f"{ts:.6f}", "src_ip": ATTACKER_IP, "dst_ip": SD_DST,
        "src_port": SD_PORT, "dst_port": SD_PORT, "service_id": "0xFFFF",
        "instance_id": "0x0001", "method_event_id": "0x8100",
        "client_id": "0x0000", "session_id": f"0x{session_id:04x}",
        "message_type": "0x02", "message_type_name": "NOTIFICATION",
        "return_code": "0x00", "return_code_name": "E_OK",
        "protocol_version": "0x01", "payload_hex": payload, "payload_len": str(plen),
        "is_sd": "1", "sd_entries": "1", "sd_options": "1",
        "sd_entry_types": label_name, "src_mac": mac, "label": "1",
    }


def load_raw(path):
    rows = list(csv.DictReader(open(path, newline="")))
    return rows


def write_rows(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=RAW_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in RAW_COLUMNS})
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", default="datasets/attack/ARR-Req-a1.csv")
    ap.add_argument("--out-dir", default="/tmp/opencode/s1")
    ap.add_argument("--scale", type=float, default=0.10)
    args = ap.parse_args()

    src = Path(args.source)
    rows = load_raw(src)
    ts = [float(r["timestamp"]) for r in rows]
    t0, t1 = min(ts), max(ts)
    cut = t0 + args.scale * (t1 - t0)
    base = [r for r in rows if float(r["timestamp"]) <= cut]

    atk_macs = sorted({r["src_mac"] for r in rows if r["label"] == "1" and r["src_mac"]})
    mac = atk_macs[0] if atk_macs else "ae:10:c5:48:47:b3"

    out = Path(args.out_dir) / "raw"
    print(f"[S1] fonte={src} dur={t1-t0:.1f}s scale={args.scale} "
          f"cut={cut-t0:.1f}s linhas={len(base)}/{len(rows)} "
          f"ataque={sum(1 for r in base if r['label']=='1')} mac_atacante={mac}")

    # controlo: so' a truncagem (sem SD do atacante)
    write_rows(out / "S1-ARR-Req-a1-ctrl.csv", base)

    # variantes com SD do atacante, a cada `interval` s.
    # Session-ID consecutivo DENTRO de cada stream (Offer / Subscribe), como nos
    # capturas normais -- evita um falso `os=0` que seria artefacto da injecao.
    for interval in (1.5, 8.0):
        inj = []
        sid = {0x01: 1, 0x06: 1}
        t = t0
        while t <= cut:
            for et, label in ((0x01, "Offerx1"), (0x06, "Subscribex1")):
                inj.append(sd_row(t, et, label, sid[et], mac))
                sid[et] += 1
            t += interval
        merged = sorted(base + inj, key=lambda r: float(r["timestamp"]))
        name = f"S1-ARR-Req-a1-sd{int(interval*10)}.csv"
        write_rows(out / name, merged)
        print(f"[S1] {name}: +{len(inj)} pacotes SD do atacante, total={len(merged)}")


if __name__ == "__main__":
    main()
