#!/usr/bin/env python3
"""Reenvia um pcap para a rede com o TEMPORISMO ORIGINAL (Estagio B).

Este script e' o "sender" do teste ao vivo: le um pcap congelado e reenvia
cada pacote por um socket AF_PACKET (raw), respeitando os timestamps
originais -- o instante previsto de cada envio e' `t0 + (ts_pcap - ts_inicio)`
e o script dorme ate' la' (com um ultimo passo em busy-wait para ter
precisao de sub-milissegundo).

Assim, o observador (ecu4) ve' o mesmo trafego e na mesma cadencia do dataset
-- mas **atravessando a stack de rede real**, com o respectivo jitter de
agendamento, que e' exactamente a variavel que o replay deterministico
(`--pcap` do `ids_live.py`) nao consegue medir.

Os MACs sao reescritos (destino = MAC do receptor, origem = MAC do emissor)
porque as bridges Docker so entregam ao contentor as tramas cujo MAC de
destino e' o seu. A reescrita de MAC **nao** afecta a classificacao
(`identity=ip` nao usa MAC); afecta apenas a coluna de metadados `src_mac`.

O script mede o *jitter do emissor* (real - previsto), para quantificar a
fidelidade do replay.

Uso (dentro do contentor, na rede do lab):
    python3 tools/replay_pcap_live.py \
        --pcap datasets/attack/ANEpc-a1.pcap \
        --interface eth0 --dst-mac aa:bb:cc:dd:ee:ff \
        --out-json results/ids_live_stageB/replay_sender.json
"""
from __future__ import annotations

import argparse
import json
import socket
import statistics
import sys
import time
from pathlib import Path

# Margem de "sono": abaixo deste resto, o script espera em busy-wait para
# nao perder a precisao do agendamento.
SPIN_S = 0.0005


def main():
    ap = argparse.ArgumentParser(
        description="Reenvia um pcap respeitando os timestamps originais.")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--interface", required=True)
    ap.add_argument("--dst-mac", default=None,
                    help="MAC de destino de todas as tramas (o do receptor). "
                         "Sem este argumento, o MAC original e' mantido.")
    ap.add_argument("--src-mac", default=None,
                    help="MAC de origem de todas as tramas (o do emissor). "
                         "Por omissao, o MAC da interface.")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="factor de velocidade (1.0 = cadencia original)")
    ap.add_argument("--limit", type=int, default=None,
                    help="numero maximo de pacotes a enviar")
    ap.add_argument("--out-json", default=None)
    args = ap.parse_args()

    from scapy.all import Ether, PcapReader

    src_mac = args.src_mac
    dst_mac = args.dst_mac.lower() if args.dst_mac else None
    if not src_mac:
        import subprocess
        src_mac = subprocess.run(
            ["cat", f"/sys/class/net/{args.interface}/address"],
            capture_output=True, text=True).stdout.strip()

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.interface, 0))

    sent = 0
    jitters_ms = []
    t_pcap0 = None
    t_start = None
    t_first = None
    t_last = None
    with PcapReader(args.pcap) as reader:
        for pkt in reader:
            if Ether in pkt:
                pkt[Ether].src = src_mac
                if dst_mac:
                    pkt[Ether].dst = dst_mac
            ts = float(pkt.time)
            if t_pcap0 is None:
                t_pcap0 = ts
                t_start = time.time()
            target = t_start + (ts - t_pcap0) / args.speed
            now = time.time()
            if target > now:
                rest = target - now
                if rest > SPIN_S:
                    time.sleep(rest - SPIN_S)
                while time.time() < target:      # busy-wait final
                    pass
            actual = time.time()
            jitters_ms.append((actual - target) * 1000.0)
            sock.send(bytes(pkt))
            sent += 1
            if t_first is None:
                t_first = actual
            t_last = actual
            if args.limit and sent >= args.limit:
                break

    stats = {
        "pcap": str(args.pcap),
        "interface": args.interface,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "speed": args.speed,
        "packets_sent": sent,
        "wall_time_s": ((t_last - t_first) if (t_first and t_last) else 0.0),
        "jitter_ms": {
            "mean": statistics.fmean(jitters_ms) if jitters_ms else None,
            "median": statistics.median(jitters_ms) if jitters_ms else None,
            "p95_abs": (sorted(abs(j) for j in jitters_ms)[
                int(0.95 * (len(jitters_ms) - 1))] if jitters_ms else None),
            "max_abs": max((abs(j) for j in jitters_ms), default=None),
        },
    }
    print(f"[replay] {sent} pacotes enviados para {args.interface} "
          f"(src={src_mac} dst={dst_mac})", file=sys.stderr)
    print(f"[replay] jitter do emissor (ms): "
          f"mediana={stats['jitter_ms']['median']:.3f} "
          f"p95|.|={stats['jitter_ms']['p95_abs']:.3f} "
          f"max|.|={stats['jitter_ms']['max_abs']:.3f}", file=sys.stderr)
    if args.out_json:
        out = Path(args.out_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(stats, indent=2) + "\n")
        print(f"[replay] -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
