#!/usr/bin/env python3
"""
tools/merge_captures.py -- Junta multiplas capturas tcpdump e remove duplicatas
do mesmo pacote roteado entre sub-redes.

Uso:
    python3 tools/merge_captures.py <out.pcap> <in1.pcap> [in2.pcap ...] [--report]

Chave de deduplicacao (conforme especificacao Fase 2):
    IP origem | IP destino | PORTA origem | PORTA destino | IP ID | hash(UDP payload)

Porque nao usar so IP ID?
    - IP ID e' um campo de 16 bits: da a volta ~65536 vezes durante 1.7M pacotes.
    - RR/NEpc/NEc rodam em paralelo entre os MESMOS pares de IP.
    - Um IP ID reaproveitado por um pacote de outro fluxo (portas diferentes)
      geraria falsa deduplicacao sem a porta na chave.

A chave inclui as portas, logo pacotes com o mesmo IP ID mas portas diferentes
(fluxos diferentes) nao sao confundidos.

Ignora TTL e checksum do payload UDP (o pacote roteado tem TTL diferente do
original, mas o payload e identico).
"""
import argparse
import hashlib
import sys
from pathlib import Path

try:
    from scapy.all import PcapReader, IP, UDP, Ether, wrpcap, conf
    conf.verb = 0
except ImportError:
    sys.exit("ERRO: scapy nao encontrado. Instale com: pip install scapy")


def pkt_key(pkt):
    """Chave de deduplicacao: 5-tuple IP/UDP + IP ID + hash do payload UDP."""
    if IP not in pkt:
        return None
    ip = pkt[IP]
    if UDP in pkt:
        udp = pkt[UDP]
        sport = udp.sport
        dport = udp.dport
        payload = bytes(udp.payload) if udp.payload else b""
    else:
        # Pacote IP sem UDP (ex.: ICMP) -- usa protocolo como porta
        sport = dport = 0
        payload = bytes(pkt.payload) or b""
    return (
        ip.src,
        ip.dst,
        sport,
        dport,
        ip.id,                                   # 16-bit IP ID
        hashlib.sha256(payload).digest(),        # hash do payload UDP (sem checksum/TTL)
    )


def main():
    ap = argparse.ArgumentParser(description="Merge e deduplicate pcaps.")
    ap.add_argument("output", help="pcap de saida")
    ap.add_argument("inputs", nargs="+", help="pcaps de entrada")
    ap.add_argument("--report", action="store_true",
                    help="imprime contagens por ficheiro")
    args = ap.parse_args()

    seen = set()
    merged = []
    stats = {}
    dup_total = 0

    for f in args.inputs:
        path = Path(f)
        if not path.exists():
            print(f"[WARN] nao existe: {f}", file=sys.stderr)
            stats[f] = {"total": 0, "novos": 0, "dups": 0}
            continue
        total = novos = dups = 0
        try:
            for pkt in PcapReader(str(path)):
                total += 1
                k = pkt_key(pkt)
                if k is None:
                    # Pacote sem IP: mantem sempre (ex.: cabo local, ARP)
                    merged.append(pkt)
                    novos += 1
                    continue
                if k in seen:
                    dups += 1
                    continue
                seen.add(k)
                merged.append(pkt)
                novos += 1
        except Exception as exc:
            print(f"[WARN] erro ao ler {f}: {exc}", file=sys.stderr)
        stats[f] = {"total": total, "novos": novos, "dups": dups}
        dup_total += dups

    # Ordenar por timestamp (ordem de chegada global)
    merged.sort(key=lambda p: float(p.time))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), merged)

    # Relatorio
    if args.report:
        print("=" * 72)
        print("MERGE CAPTURAS -- relatorio de deduplicacao")
        print("=" * 72)
        print(f"{'ficheiro':<40} {'total':>7} {'novos':>7} {'dups':>7}")
        print("-" * 72)
        for f, s in stats.items():
            print(f"{f:<40} {s['total']:>7} {s['novos']:>7} {s['dups']:>7}")
        print("-" * 72)
        print(f"{'TOTAL':<40} {sum(s['total'] for s in stats.values()):>7} "
              f"{len(merged):>7} {dup_total:>7}")
        print("=" * 72)
        print(f"pacotes descartados como duplicata: {dup_total}")
        print(f"pacotes escritos em {args.output}: {len(merged)}")
    else:
        print(f"[merge_captures] {len(merged)} pacotes escritos em {args.output} "
              f"({dup_total} duplicatas removidas)")


if __name__ == "__main__":
    main()