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


def someip_logical_key(pkt):
    """Identidade logica SOME/IP (nao-SD): 5-tuple + cabecalho de mensagem.

    A copia original e a copia reemitida pelo atacante (tamper ou fabricacao)
    partilham TUDO isto e diferem apenas em payload/IP ID; por isso a chave
    exata (pkt_key) nao as liga e o merge contava-as como pacotes distintos.
    """
    if IP not in pkt or UDP not in pkt:
        return None
    payload = bytes(pkt[UDP].payload)
    if len(payload) < 16:
        return None
    svc = int.from_bytes(payload[0:2], "big")
    if svc == 0xFFFF:            # SD: sessao pode repetir-se; nao deduplicar
        return None
    mtd = int.from_bytes(payload[2:4], "big")
    client = int.from_bytes(payload[8:10], "big")
    session = int.from_bytes(payload[10:12], "big")
    mtype = payload[14]
    ip, udp = pkt[IP], pkt[UDP]
    return (ip.src, ip.dst, udp.sport, udp.dport, svc, mtd, client, session, mtype)


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
    ap.add_argument("--attacker-mac", default=None, metavar="MAC",
                    help="modo ataque: dedup LOGICA entre a copia original "
                         "(label0, vista a montante) e a copia reemitida pelo "
                         "atacante (label1) -- mesmo 5-tuple/svc/mtd/client/"
                         "session/mtype, payload e IP ID diferentes (tamper/"
                         "fabricacao nao sao dedupaveis pela chave exata)")
    args = ap.parse_args()

    attacker_mac = args.attacker_mac.lower() if args.attacker_mac else None
    seen = {}                    # pkt_key -> (indice em merged, e_label1)
    label1_keys = set()          # chaves logicas de copias ja mantidas (label1)
    merged = []
    stats = {}
    dup_total = 0
    logical_dup_total = [0]      # mutavel: fechado no loop de leitura
    replaced_total = [0]         # vista label0 substituida pela label1

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
                is_label1 = (attacker_mac is not None and Ether in pkt
                             and pkt[Ether].src.lower() == attacker_mac)
                lk = (someip_logical_key(pkt)
                      if attacker_mac is not None else None)
                if lk is not None and not is_label1 and lk in label1_keys:
                    logical_dup_total[0] += 1
                    # original de um evento que o atacante reemitiu (tamper/
                    # fabricacao): o cliente so viu a copia label1; a vista a
                    # montante do original e' um duplicado LOGICO.
                    continue
                k = pkt_key(pkt)
                if k is None:
                    # Pacote sem IP: mantem sempre (ex.: cabo local, ARP)
                    merged.append(pkt)
                    novos += 1
                    continue
                if k in seen:
                    idx, kept_l1 = seen[k]
                    if is_label1 and not kept_l1:
                        # mesma observacao vista em dois pontos: na net1 com
                        # src MAC do atacante (label1) e ja roteada pelo ecu2
                        # (src MAC reescrito -> label0). A eth0/eth1 <-> net1/
                        # net2 alterna por recriacao, por isso a ORDEM dos
                        # ficheiros nao garante qual vem primeiro -- a copia
                        # label1 e' a que identifica o ataque: substitui.
                        merged[idx] = pkt
                        seen[k] = (idx, True)
                        if lk is not None:
                            label1_keys.add(lk)
                        novos += 1
                        replaced_total[0] += 1
                    else:
                        dups += 1
                    continue
                seen[k] = (len(merged), is_label1)
                if lk is not None and is_label1:
                    label1_keys.add(lk)
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
    if attacker_mac:
        print(f"descartados como duplicada LOGICA (original de copia "
              f"label1): {logical_dup_total[0]}")
        print(f"observacoes label0 substituidas pela copia label1: "
              f"{replaced_total[0]}")
        print(f"pacotes escritos em {args.output}: {len(merged)}")
    else:
        print(f"[merge_captures] {len(merged)} pacotes escritos em {args.output} "
              f"({dup_total} duplicatas removidas"
              + (f", {logical_dup_total[0]} logicas" if attacker_mac else "")
              + ")")


if __name__ == "__main__":
    main()