#!/usr/bin/env python3
# =============================================================================
# verify_pcap.py -- validacao do smoke test lendo os pcaps com scapy
#
# Le todos os pcaps gerados pelo smoke test (capturas tcpdump em ecu1..ecu5),
# decodifica o cabecalho SOME/IP (16 bytes) de cada datagrama UDP e confirma
# que, na topologia roteada:
#
#   C1  existe trafego SOME/IP-SD (service 0xFFFF / method 0x8100);
#   C2  ecu1 recebeu um SOME/IP-SD originado em 192.168.2.4  (ou seja: o
#       OFFER do servidor atravessou o roteador ecu2);
#   C3  existe um SOME/IP REQUEST  192.168.1.2 -> 192.168.2.4 (0x1234/0x0001);
#   C4  existe um SOME/IP RESPONSE 192.168.2.4 -> 192.168.1.2 (0x1234/0x0001);
#   C5  existe uma SOME/IP NOTIFICATION do evento 0x8001 do servico 0x1235.
#
# Uso:  verify_pcap.py pcaps/*.pcap
# Codigo de saide: 0 = todas as verificacoes passaram, 1 = alguma falhou.
# =============================================================================
from __future__ import annotations

import argparse
import glob
import os
import sys
from collections import Counter, defaultdict

try:
    from scapy.all import IP, PcapReader, Raw, UDP
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "ERRO: scapy nao encontrado. Instale com:  python3 -m pip install --user scapy\n"
    )
    sys.exit(2)

SD_SERVICE = 0xFFFF
SD_METHOD = 0x8100

SERVICE_REQRESP = 0x1234
METHOD_ECHO = 0x0001
SERVICE_EVENTS = 0x1235
EVENT_TELEMETRY = 0x8001

SD_PORTS = {30490, 30509, 30510}

MSG_TYPE_NAMES = {
    0x00: "REQUEST",
    0x01: "REQUEST_NO_RETURN",
    0x02: "NOTIFICATION",
    0x80: "RESPONSE",
    0x81: "ERROR",
}

CLIENT_IP = "192.168.1.2"
SERVER_IP = "192.168.2.4"


def parse_someip(payload: bytes) -> dict | None:
    """Decodifica o cabecalho SOME/IP (16 bytes). Devolve None se nao for."""
    if len(payload) < 16:
        return None
    service = int.from_bytes(payload[0:2], "big")
    method = int.from_bytes(payload[2:4], "big")
    length = int.from_bytes(payload[4:8], "big")
    client = int.from_bytes(payload[8:10], "big")
    session = int.from_bytes(payload[10:12], "big")
    protocol_version = payload[12]
    interface_version = payload[13]
    message_type = payload[14]
    return_code = payload[15]
    # O payload de um SOME/IP-SD tem 8 bytes "someip_sd" a mais; nao precisamos.
    if protocol_version != 0x01:
        return None
    if service == 0x0000:
        return None
    return {
        "service": service,
        "method": method,
        "length": length,
        "client": client,
        "session": session,
        "interface_version": interface_version,
        "message_type": message_type,
        "return_code": return_code,
    }


def scan(path: str) -> dict:
    """Percorre um pcap e junta estatisticas + registos de interesse."""
    result = {
        "path": path,
        "packets": 0,
        "someip": 0,
        "sd": 0,
        "by_type": Counter(),
        "by_service": Counter(),
        # (src, dst, service, method, message_type)
        "records": [],
        "sd_by_src": Counter(),
    }
    try:
        reader = PcapReader(path)
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    with reader:
        for pkt in reader:
            result["packets"] += 1
            if IP not in pkt or UDP not in pkt or Raw not in pkt:
                continue
            ip, udp = pkt[IP], pkt[UDP]
            if not (udp.sport in SD_PORTS or udp.dport in SD_PORTS):
                continue
            hdr = parse_someip(bytes(pkt[Raw].load))
            if hdr is None:
                continue

            result["someip"] += 1
            rec = (ip.src, ip.dst, hdr["service"], hdr["method"], hdr["message_type"])
            result["records"].append(rec)

            if hdr["service"] == SD_SERVICE and hdr["method"] == SD_METHOD:
                result["sd"] += 1
                result["sd_by_src"][ip.src] += 1
            else:
                result["by_type"][MSG_TYPE_NAMES.get(hdr["message_type"], f"0x{hdr['message_type']:02x}")] += 1
                result["by_service"][hdr["service"]] += 1

    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcaps", nargs="+", help="ficheiros pcap a analisar")
    args = ap.parse_args()

    files = []
    for pattern in args.pcaps:
        files.extend(sorted(glob.glob(pattern)) or [pattern])
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        print("ERRO: nenhum pcap encontrado.")
        return 1

    scans = [scan(f) for f in files]

    # ---- resumo por ficheiro ------------------------------------------------
    print("=" * 78)
    print("RESUMO DOS PCAPS (leitura com scapy)")
    print("=" * 78)
    header = f"{'ficheiro':<28} {'pkts':>6} {'SOME/IP':>8} {'SD':>5}  tipos"
    print(header)
    print("-" * 78)
    for s in scans:
        name = os.path.basename(s["path"])
        if "error" in s:
            print(f"{name:<28} ERRO: {s['error']}")
            continue
        tipos = ", ".join(f"{k}:{v}" for k, v in sorted(s["by_type"].items())) or "-"
        print(f"{name:<28} {s['packets']:>6} {s['someip']:>8} {s['sd']:>5}  {tipos}")
    print("-" * 78)

    # ---- agregados ----------------------------------------------------------
    all_records = [r for s in scans for r in s["records"]]
    sd_records = [r for r in all_records if r[2] == SD_SERVICE and r[3] == SD_METHOD]

    total_sd = len(sd_records)
    print(f"SOME/IP-SD total : {total_sd}")
    if sd_records:
        por_origem = Counter(r[0] for r in sd_records)
        for src, n in sorted(por_origem.items()):
            print(f"    origem {src:<15} {n:>5} pacotes SD")

    ecu1 = next((s for s in scans if os.path.basename(s["path"]).startswith("ecu1")), None)
    ecu1_sd_remoto = []
    if ecu1:
        ecu1_sd_remoto = [
            r
            for r in ecu1["records"]
            if r[2] == SD_SERVICE and r[3] == SD_METHOD and r[0] == SERVER_IP
        ]

    def has(predicate) -> bool:
        return any(predicate(r) for r in all_records)

    checks = []

    checks.append(("C1 existe trafego SOME/IP-SD", total_sd > 0,
                   f"{total_sd} pacotes SD"))

    checks.append((
        "C2 ecu1 recebeu SOME/IP-SD vindo de 192.168.2.4 (SD roteado via ecu2)",
        len(ecu1_sd_remoto) > 0,
        f"{len(ecu1_sd_remoto)} pacotes",
    ))

    n_req = has(lambda r: r[0] == CLIENT_IP and r[1] == SERVER_IP
                 and r[2] == SERVICE_REQRESP and r[3] == METHOD_ECHO
                 and r[4] == 0x00)
    checks.append((
        "C3 SOME/IP REQUEST  192.168.1.2 -> 192.168.2.4 (servico 0x1234 metodo 0x0001)",
        n_req,
        "presente" if n_req else "ausente",
    ))

    n_res = has(lambda r: r[0] == SERVER_IP and r[1] == CLIENT_IP
                 and r[2] == SERVICE_REQRESP and r[3] == METHOD_ECHO
                 and r[4] == 0x80)
    checks.append((
        "C4 SOME/IP RESPONSE 192.168.2.4 -> 192.168.1.2 (servico 0x1234 metodo 0x0001)",
        n_res,
        "presente" if n_res else "ausente",
    ))

    n_not = has(lambda r: r[0] == SERVER_IP and r[1] == CLIENT_IP
                 and r[2] == SERVICE_EVENTS and r[3] == EVENT_TELEMETRY
                 and r[4] == 0x02)
    checks.append((
        "C5 SOME/IP NOTIFICATION do evento 0x8001 do servico 0x1235",
        n_not,
        "presente" if n_not else "ausente",
    ))

    print()
    print("=" * 78)
    print("VERIFICACOES")
    print("=" * 78)
    failed = 0
    for label, ok, detail in checks:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"  [{mark}] {label}   ({detail})")

    print("-" * 78)
    if failed:
        print(f"RESULTADO: FALHOU ({failed} verificacao(oes) em {len(checks)})")
        return 1
    print(f"RESULTADO: OK (todas as {len(checks)} verificacoes passaram)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
