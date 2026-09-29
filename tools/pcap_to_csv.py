#!/usr/bin/env python3
"""
tools/pcap_to_csv.py -- Extrai campos SOME/IP de um pcap e grava CSV com label=0.

Uso:
    python3 tools/pcap_to_csv.py <entrada.pcap> [--out saida.csv] [--label N]

Extrai por pacote:
    timestamp, src_ip, dst_ip, src_port, dst_port, service_id, instance_id,
    method_event_id, client_id, session_id, message_type, return_code,
    payload_hex, is_sd, sd_entries, sd_options, sd_entry_types, label.

O tcpdump so decodifica SOME/IP na porta 30490 (SD). Nas portas unicast dos
servicos (30509, 30510, ...) mostra so "UDP". Este parser trata todas as portas
de servico como SOME/IP com parser manual do header de 16 bytes.

Formato do header SOME/IP (big-endian, 16 bytes, AUTOSAR SOME/IP-SDP):
    [0..1]   uint16  Service ID
    [2..3]   uint16  Method/Event ID (eventos com bit 0x8000; SD usa 0x8100)
    [4..7]   uint32  Length (bytes a seguir do byte 8 do header)
    [8..9]   uint16  Client ID
    [10..11] uint16  Session ID
    [12]     uint8   Protocol Version (0x01)
    [13]     uint8   Interface Version (0x01)
    [14]     uint8   Message Type (0x00 REQ, 0x01 REQ_NO_RET, 0x02 NOTIFICATION,
                                   0x80 RESPONSE, 0x81 NOTIFICATION_NO_RET)
    [15]     uint8   Return Code (0x00=E_OK, 0x01=E_NOT_OK, ...)
    [16..]   payload

NOTA: o header SOME/IP nao contem instance ID. Neste projeto todos os
servicos usam instance 0x0001 (SERVICE_INSTANCES); para SD o instance vem da
entry (bytes 6..7 da entry de 16 bytes).

Payload SOME/IP-SD (serializacao do vsomeip, implementation/service_discovery):
    [0]      uint8   flags
    [1..3]   3 bytes reserved
    [4..7]   uint32  entries_length
    [8..]    entries, cada uma exatamente 16 bytes:
        [0]     uint8  type (0x00 Find, 0x01 Offer, 0x06 Subscribe, 0x07 SubAck)
        [1]     uint8  index1
        [2]     uint8  index2
        [3]     uint8  num_options (nibble alto = run0, nibble baixo = run1)
        [4..5]  uint16 service_id
        [6..7]  uint16 instance_id
        ServiceEntry:   [8] major, [9..11] ttl (3B), [12..15] minor (uint32)
        EventgroupEntry:[8] major, [9..11] ttl (3B), [12..13] reserved,
                        [14..15] eventgroup_id
    + uint32 options_length
    + options, cada uma: uint16 length | uint8 type | uint8 reserved | data
      (a option ocupa length+3 bytes no total; ex.: IPv4 Endpoint length=9 =
       type + addr4 + reserved + protocol + port2, 12 bytes com o header)
"""
import argparse
import csv
import struct
import sys
from pathlib import Path

try:
    from scapy.all import PcapReader, IP, UDP, conf
    conf.verb = 0
except ImportError:
    sys.exit("ERRO: scapy nao encontrado. Instale com: pip install scapy")

# Portas que conteem SOME/IP (unicast de servicos + SD)
SD_PORT = 30490
KNOWN_SERVICE_PORTS = {30490, 30509, 30510, 30511, 30520, 30530}

# Todos os servicos deste deploy usam instance 0x0001 (o header SOME/IP nao
# transporta instance ID; o valor vem da configuracao vsomeip).
SERVICE_INSTANCES = {0x1234: 0x0001, 0x1235: 0x0001, 0x1236: 0x0001}

# Nomes de Message Type SOME/IP
MSG_TYPES = {
    0x00: "REQUEST",
    0x01: "REQUEST_NO_RET",
    0x02: "NOTIFICATION",
    0x80: "RESPONSE",
    0x81: "NOTIFICATION_NO_RET",
}

# Nomes de Return Code SOME/IP
RETURN_CODES = {
    0x00: "E_OK",
    0x01: "E_NOT_OK",
    0x02: "E_UNKNOWN_SERVICE",
    0x03: "E_UNKNOWN_METHOD",
    0x04: "E_NOT_READY",
    0x05: "E_NOT_REQUESTED",
    0x06: "E_ALREADY_STARTED",
    0x07: "E_NOT_SUBSCRIBED",
    0x08: "E_NO_AVAILABILITY",
    0x09: "E_WRONG_PROTOCOL",
    0x0A: "E_WRONG_PROTOCOL_VERSION",
    0x0B: "E_WRONG_INTERFACE_VERSION",
    0x0C: "E_MALFORMED_MESSAGE",
    0x0D: "E_WRONG_MESSAGE_TYPE",
    0x0E: "E_REACHED_MAX_RETRANSMISSIONS",
    0x0F: "E_CONNECTION_LOST",
    0x10: "E_ACK_OK",
    0x11: "E_ACK_MAX_RETRANSMISSIONS_REACHED",
    0x12: "E_ACK_UNKNOWN_ENTRY",
    0x13: "E_ACK_ERROR",
}

# Tipos de entry SD (vsomeip entry_type_e)
SD_ENTRY_TYPES = {
    0x00: "Find",
    0x01: "Offer",
    0x02: "RequestSvc",
    0x04: "FindEventgroup",
    0x05: "PublishEventgroup",
    0x06: "Subscribe",
    0x07: "SubAck",
}

# Tipos de option SD (vsomeip option_type_e)
SD_OPTION_TYPES = {
    0x01: "Configuration",
    0x02: "LoadBalancing",
    0x03: "Protection",
    0x04: "IPv4Endpoint",
    0x06: "IPv6Endpoint",
    0x14: "IPv4Multicast",
    0x16: "IPv6Multicast",
    0x20: "Selective",
}


def parse_someip(payload):
    """Parser manual do header SOME/IP de 16 bytes. Devolve dict ou None."""
    if len(payload) < 16:
        return None
    service_id = struct.unpack(">H", payload[0:2])[0]
    method_event_id = struct.unpack(">H", payload[2:4])[0]
    length = struct.unpack(">I", payload[4:8])[0]
    client_id = struct.unpack(">H", payload[8:10])[0]
    session_id = struct.unpack(">H", payload[10:12])[0]
    proto_ver = payload[12]
    iface_ver = payload[13]
    msg_type = payload[14]
    ret_code = payload[15]
    data = payload[16:]
    return {
        "service_id": service_id,
        "method_event_id": method_event_id,
        "message_type": msg_type,
        "return_code": ret_code,
        "length": length,
        "client_id": client_id,
        "session_id": session_id,
        "protocol_version": proto_ver,
        "interface_version": iface_ver,
        "data": data,
    }


def parse_sd_payload(sd_data):
    """
    Parse do payload SOME/IP-SD (depois do header SOME/IP de 16 bytes).
    Estrutura (serializacao do vsomeip 3.7.6):
      [0] flags, [1..3] reserved, [4..7] entries_length (uint32),
      entries (16 bytes cada), uint32 options_length, options.
    Devolve (entries, options) com tipos nomeados.
    """
    entries = []
    options = []
    if len(sd_data) < 8:
        return entries, options

    entries_len = struct.unpack(">I", sd_data[4:8])[0]
    off = 8
    end = min(8 + entries_len, len(sd_data))
    while off + 16 <= end:
        body = sd_data[off:off + 16]
        etype = body[0]
        num_options = ((body[3] >> 4) & 0x0F) + (body[3] & 0x0F)
        entries.append({
            "type": SD_ENTRY_TYPES.get(etype, f"Unknown_0x{etype:02X}"),
            "type_raw": etype,
            "service_id": struct.unpack(">H", body[4:6])[0],
            "instance_id": struct.unpack(">H", body[6:8])[0],
            "num_options": num_options,
        })
        off += 16

    if off + 4 <= len(sd_data):
        options_len = struct.unpack(">I", sd_data[off:off + 4])[0]
        ooff = off + 4
        oend = min(ooff + options_len, len(sd_data))
        while ooff + 4 <= oend:
            olen = struct.unpack(">H", sd_data[ooff:ooff + 2])[0]
            otype = sd_data[ooff + 2]
            options.append({
                "type": SD_OPTION_TYPES.get(otype, f"Unknown_0x{otype:02X}"),
                "type_raw": otype,
                "length": olen,
            })
            ooff += olen + 3
    return entries, options


def main():
    ap = argparse.ArgumentParser(description="Extrai SOME/IP de pcap para CSV.")
    ap.add_argument("pcap", help="pcap de entrada")
    ap.add_argument("--out", help="CSV de saida (default: <pcap>.csv)")
    ap.add_argument("--label", type=int, default=0, help="label por omissao 0")
    args = ap.parse_args()

    out_path = Path(args.out) if args.out else Path(args.pcap).with_suffix(".csv")

    fields = [
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "service_id", "instance_id", "method_event_id", "client_id",
        "session_id", "message_type", "message_type_name",
        "return_code", "return_code_name", "protocol_version",
        "payload_hex", "payload_len",
        "is_sd", "sd_entries", "sd_options", "sd_entry_types",
        "label",
    ]

    n_total = n_someip = n_sd = 0
    n_skipped = 0

    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()

        for pkt in PcapReader(args.pcap):
            n_total += 1
            if IP not in pkt or UDP not in pkt:
                n_skipped += 1
                continue
            ip = pkt[IP]
            udp = pkt[UDP]
            if (udp.sport not in KNOWN_SERVICE_PORTS
                    and udp.dport not in KNOWN_SERVICE_PORTS):
                n_skipped += 1
                continue
            raw = bytes(udp.payload) if udp.payload else b""
            # O datagrama UDP pode convar VARIAS mensagens SOME/IP
            # concatenadas (vsomeip junta, ex.: notificacao + resposta).
            # Percorre: tamanho = 8 + campo length (uint32 no offset 4).
            pos = 0
            n_msgs = 0
            while pos + 8 <= len(raw):
                length = struct.unpack(">I", raw[pos + 4:pos + 8])[0]
                msg_size = 8 + length
                if length < 8 or pos + msg_size > len(raw):
                    break
                msg = raw[pos:pos + msg_size]
                pos += msg_size
                if len(msg) < 16:
                    break

                siap = parse_someip(msg)
                if siap is None:
                    continue
                n_msgs += 1
                n_someip += 1
                is_sd = (udp.dport == SD_PORT or udp.sport == SD_PORT
                         or siap["service_id"] == 0xFFFF)

                sd_entries = sd_options = 0
                sd_entry_types = ""
                instance_id = SERVICE_INSTANCES.get(siap["service_id"], 0x0000)
                if is_sd:
                    n_sd += 1
                    entries, options = parse_sd_payload(siap["data"])
                    sd_entries = len(entries)
                    sd_options = len(options)
                    sd_entry_types = ";".join(
                        f"{e['type']}x{e['num_options']}" for e in entries
                    )
                    if entries:
                        instance_id = entries[0]["instance_id"]

                w.writerow({
                    "timestamp": f"{float(pkt.time):.6f}",
                    "src_ip": ip.src,
                    "dst_ip": ip.dst,
                    "src_port": udp.sport,
                    "dst_port": udp.dport,
                    "service_id": f"0x{siap['service_id']:04X}",
                    "instance_id": f"0x{instance_id:04X}",
                    "method_event_id": f"0x{siap['method_event_id']:04X}",
                    "client_id": f"0x{siap['client_id']:04X}",
                    "session_id": f"0x{siap['session_id']:04X}",
                    "message_type": f"0x{siap['message_type']:02X}",
                    "message_type_name": MSG_TYPES.get(siap["message_type"], "UNKNOWN"),
                    "return_code": f"0x{siap['return_code']:02X}",
                    "return_code_name": RETURN_CODES.get(siap["return_code"], "UNKNOWN"),
                    "protocol_version": f"0x{siap['protocol_version']:02X}",
                    "payload_hex": msg[16:].hex(),
                    "payload_len": len(msg) - 16,
                    "is_sd": int(is_sd),
                    "sd_entries": sd_entries,
                    "sd_options": sd_options,
                    "sd_entry_types": sd_entry_types,
                    "label": args.label,
                })
            if n_msgs == 0:
                n_skipped += 1

    print(f"[pcap_to_csv] {n_total} pacotes lidos -> {n_someip} SOME/IP "
          f"({n_sd} SD) -> {out_path}")
    if n_skipped:
        print(f"[pcap_to_csv] ignorados (nao-UDP/fora de portas/curtos): {n_skipped}")


if __name__ == "__main__":
    main()
