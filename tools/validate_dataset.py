#!/usr/bin/env python3
"""
tools/validate_dataset.py -- Valida um dataset normal contra os alvos do artigo
e emite/atualiza datasets/normal/MANIFEST.json.

Uso:
    python3 tools/validate_dataset.py <entrada.pcap> [--dataset normal_rr]
        [--scale 0.05] [--removed-dups N] [--update-manifest]

Valida:
    - total de pacotes vs alvo do artigo (tolerancia +-10% do alvo efetivo;
      com --scale N o alvo efetivo = alvo * N, para runs reduzidos)
    - SD vs nao-SD
    - contagem por Service ID / Message Type / return code (respostas NG)
    - continuidade do Session ID por fluxo
      (remetente, destino, tipo de mensagem, SD/dados) -- os contadores
      de session sao GLOBAIS por aplicacao (nao por servico/metodo),
      tratando wraparound 0xFFFF -> 0x0001 como transicao valida;
      breaks de dados > 1.14% = falha (gate = 0.639% observado no
      reduced NEpc + 0.5 p.p.; todos os breaks observados sao
      reordenacoes ECHO<->SetMode / RR<->NEPC com mensagens presentes);
      perda REAL (sessoes ausentes) separada, gate <= 0.5% (observado 0%)
    - duplicatas APOS o merge (recontadas com a mesma chave do
      tools/merge_captures.py; deve ser zero)
    - duracao, taxa media de pacotes
    - pacotes truncados (payload SOME/IP menor que o length declarado)
Exit code 0 = todos os criticos OK; 1 = falha critica.

Notas:
    --removed-dups e' so relatorio (pacotes descartados pelo merge por
    captarem o mesmo datagrama em varios interfaces/ECUs); nao afeta o exit.
"""
import argparse
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    from scapy.all import PcapReader, IP, UDP, conf
    conf.verb = 0
except ImportError:
    sys.exit("ERRO: scapy nao encontrado. Instale com: pip install scapy")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from merge_captures import pkt_key  # noqa: E402  (chave de dedup == a do merge)

# Alvos do artigo (Koyama et al. VTC2022-Spring)
TARGETS = {
    "normal_rr": 6455,
    "normal_nepc": 255128,
    "normal_nec": 1722011,
}

SD_PORT = 30490
TOLERANCE = 0.10  # +-10%
# Gate baseado na taxa REAL observada no run reduced NEpc (scale=0.05):
#   breaks = 81/12678 = 0.639% (todos reordenacoes ECHO<->SetMode /
#   RR<->NEPC, nenhuma mensagem ausente) -> 0.64% + 0.5 p.p. = 1.14%
BREAK_TOLERANCE = 0.0114
# perda real (sessoes ausentes de verdade) observada = 0.00% -> + 0.5 p.p.
LOSS_TOLERANCE = 0.005

MSG_TYPES = {
    0x00: "REQUEST", 0x01: "REQUEST_NO_RET", 0x02: "NOTIFICATION",
    0x80: "RESPONSE", 0x81: "NOTIFICATION_NO_RET",
}


def parse_someip(payload):
    """Header SOME/IP de 16 bytes (AUTOSAR). Devolve dict ou None."""
    if len(payload) < 16:
        return None
    service_id = struct.unpack(">H", payload[0:2])[0]
    method_event_id = struct.unpack(">H", payload[2:4])[0]
    length = struct.unpack(">I", payload[4:8])[0]
    client_id = struct.unpack(">H", payload[8:10])[0]
    session_id = struct.unpack(">H", payload[10:12])[0]
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
        "data_len": len(data),
    }


def check_session_continuity(session_seq):
    """
    Devolve (n_breaks, wraparounds, missing).
    Regra: proximo = anterior+1, OU wraparound 0xFFFF -> 0x0001.
    O valor 0x0000 e reservado: se aparecer entre 0xFFFF e 0x0001,
    conta como parte do wraparound.
    missing = sessoes referenciadas por um gap forward mas ABSENTES da
    flow (perda real); sessao ausente num gap que reaparece depois =
    reordenacao, nao conta como missing.
    """
    breaks = wraps = missing = 0
    present = set(session_seq)
    for a, b in zip(session_seq, session_seq[1:]):
        if b == (a + 1) & 0xFFFF:
            continue
        if a == 0xFFFF and b in (0x0000, 0x0001):
            wraps += 1
            continue
        breaks += 1
        gap = (b - a) & 0xFFFF
        if 1 < gap < 0x8000:  # gap forward: sessoes puladas
            for i in range(1, gap):
                if (a + i) & 0xFFFF not in present:
                    missing += 1
    return breaks, wraps, missing


def main():
    ap = argparse.ArgumentParser(description="Valida dataset normal.")
    ap.add_argument("pcap", help="pcap do dataset")
    ap.add_argument("--dataset", default=None,
                    help="nome do dataset (normal_rr|normal_nepc|normal_nec)")
    ap.add_argument("--scale", type=float, default=1.0,
                    help="fracao do run full (0.05 = alvo efetivo 5%%)")
    ap.add_argument("--removed-dups", type=int, default=0,
                    help="duplicatas removidas pelo merge (so relatorio)")
    ap.add_argument("--update-manifest", action="store_true",
                    help="atualiza datasets/normal/MANIFEST.json")
    args = ap.parse_args()

    ds_name = args.dataset or Path(args.pcap).stem
    target_full = TARGETS.get(ds_name, 0)
    target = int(round(target_full * args.scale)) if target_full else 0

    total = 0
    sd_count = 0
    non_sd = 0
    truncated = 0
    svc_counter = Counter()
    mt_counter = Counter()
    ng_responses = 0
    responses = 0
    # continuidade: fluxo = (src, dst, msgtype, is_sd) -- contadores de
    # session sao globais por aplicacao (requisicoes ECHO e SetMode
    # intercalam; respostas ecoam o contador do cliente)
    session_seqs = defaultdict(list)
    # duplicatas pos-merge (mesma chave do merge_captures)
    seen_keys = set()
    dup_count = 0

    t_first = t_last = None

    for pkt in PcapReader(args.pcap):
        total += 1
        ts = float(pkt.time)
        if t_first is None:
            t_first = ts
        t_last = ts

        k = pkt_key(pkt)
        if k is not None:
            if k in seen_keys:
                dup_count += 1
            else:
                seen_keys.add(k)

        if IP not in pkt or UDP not in pkt:
            continue
        raw = bytes(pkt[UDP].payload) if pkt[UDP].payload else b""
        # datagrama UDP pode conter VARIAS mensagens SOME/IP concatenadas
        # (vsomeip junta, ex.: notificacao + resposta); percorre todas.
        pos = 0
        while pos + 8 <= len(raw):
            length = struct.unpack(">I", raw[pos + 4:pos + 8])[0]
            msg_size = 8 + length
            if length < 8:
                break  # restantes bytes = padding/garbage
            if pos + msg_size > len(raw):
                truncated += 1  # length declara mais do que existe
                break
            msg = raw[pos:pos + msg_size]
            pos += msg_size
            if len(msg) < 16:
                break

            siap = parse_someip(msg)
            if siap is None:
                continue
            is_sd = (pkt[UDP].dport == SD_PORT or pkt[UDP].sport == SD_PORT
                     or siap["service_id"] == 0xFFFF)
            if is_sd:
                sd_count += 1
            else:
                non_sd += 1

            svc_counter[siap["service_id"]] += 1
            mt_counter[siap["message_type"]] += 1

            if siap["message_type"] == 0x80:
                responses += 1
                if siap["return_code"] != 0x00:
                    ng_responses += 1

            key = (pkt[IP].src, pkt[IP].dst, siap["message_type"], is_sd)
            session_seqs[key].append(siap["session_id"])

    # ---- session continuity ----
    total_breaks = 0
    total_wraps = 0
    total_missing = 0
    sd_breaks = 0
    data_msgs = 0
    breaks_by_mt = Counter()   # quebras por message type (nao-SD)
    msgs_by_mt = Counter()     # mensagens por message type (nao-SD)
    for key, seq in sorted(session_seqs.items(), key=lambda kv: str(kv[0])):
        breaks, wraps, missing = check_session_continuity(seq)
        total_wraps += wraps
        if key[3]:  # fluxo SD: informativo (vsomeip pode re-emitar sessoes)
            sd_breaks += breaks
        else:
            data_msgs += len(seq)
            total_breaks += breaks
            total_missing += missing
            breaks_by_mt[key[2]] += breaks
            msgs_by_mt[key[2]] += len(seq)
            if breaks:
                print(f"[AVISO] Session ID breaks em src={key[0]} dst={key[1]} "
                      f"msgtype=0x{key[2]:02X}: {breaks} de {len(seq)} "
                      f"(reordenacao ou perda; ver perda real abaixo)")
    break_rate = (total_breaks / data_msgs) if data_msgs else 0.0
    breaks_ok = break_rate <= BREAK_TOLERANCE
    loss_rate = (total_missing / data_msgs) if data_msgs else 0.0
    loss_ok = loss_rate <= LOSS_TOLERANCE

    duration = (t_last - t_first) if t_first and t_last else 0.0
    rate = (total / duration) if duration > 0 else 0.0

    # ---- checagem contra alvo efetivo ----
    if target:
        diff_pct = abs(total - target) / target * 100.0
        in_tolerance = diff_pct <= TOLERANCE * 100
    else:
        diff_pct = 0.0
        in_tolerance = True

    ng_pct = (ng_responses / responses * 100.0) if responses else 0.0

    # ---- relatorio ----
    print("=" * 72)
    print(f"VALIDACAO DO DATASET: {ds_name}  (scale={args.scale})")
    print("=" * 72)
    print(f"  total de pacotes        : {total}")
    if target_full:
        print(f"  alvo do artigo          : {target_full}"
              + (f"  (scale={args.scale} -> {target})"
                 if args.scale != 1.0 else ""))
    else:
        print(f"  alvo do artigo          : (desconhecido)")
    print(f"  diferenca               : {diff_pct:.1f}%  "
          f"({'OK +-10%' if in_tolerance else 'FORA DA TOLERANCIA'})")
    print(f"  SD                      : {sd_count}")
    print(f"  nao-SD (dados)          : {non_sd}")
    print(f"  respostas NG (rc!=0)    : {ng_responses} de {responses} "
          f"({ng_pct:.1f}%)")
    print(f"  duracao                 : {duration:.1f}s")
    print(f"  taxa media              : {rate:.0f} pkt/s")
    print(f"  pacotes truncados       : {truncated}  "
          f"({'OK' if truncated == 0 else 'FALHA'})")
    print(f"  duplicatas (pos-merge)  : {dup_count}  "
          f"({'OK' if dup_count == 0 else 'FALHA'})")
    print(f"  duplicatas removidas    : {args.removed_dups} "
          f"(merge, so relatorio)")
    print(f"  session ID breaks       : {total_breaks} "
          f"({break_rate * 100:.3f}% dos dados)  "
          f"[{'OK' if breaks_ok else 'FALHA'} <= {BREAK_TOLERANCE * 100:.2f}%]")
    print(f"  por Message Type (nao-SD):")
    for mt in sorted(msgs_by_mt):
        b, n = breaks_by_mt.get(mt, 0), msgs_by_mt[mt]
        print(f"    0x{mt:02X} ({MSG_TYPES.get(mt, '?')}): {b} breaks de {n} "
              f"({(b / n * 100) if n else 0:.3f}%)")
    print(f"  perda real (sessoes ausentes): {total_missing} "
          f"({loss_rate * 100:.3f}% dos dados)  "
          f"[{'OK' if loss_ok else 'FALHA'} <= {LOSS_TOLERANCE * 100:.2f}%]")
    print(f"  session ID breaks (SD)  : {sd_breaks} (informativo)")
    print(f"  session ID wraparounds  : {total_wraps} (transicoes validas)")
    print(f"  por Service ID:")
    for sid, cnt in sorted(svc_counter.items()):
        print(f"    0x{sid:04X}: {cnt}")
    print(f"  por Message Type:")
    for mt, cnt in sorted(mt_counter.items()):
        print(f"    0x{mt:02X} ({MSG_TYPES.get(mt, '?')}): {cnt}")
    print("=" * 72)

    # ---- manifest ----
    if args.update_manifest:
        manifest_path = Path(__file__).resolve().parent.parent / "datasets/normal/MANIFEST.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest = {}
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text())
            except json.JSONDecodeError:
                manifest = {}
        manifest[ds_name] = {
            "file": str(Path(args.pcap).name),
            "total_packets": total,
            "target_packets": target_full,
            "scale": args.scale,
            "target_effective": target,
            "diff_pct": round(diff_pct, 2),
            "in_tolerance_10pct": in_tolerance,
            "sd_packets": sd_count,
            "non_sd_packets": non_sd,
            "responses": responses,
            "ng_responses": ng_responses,
            "ng_pct": round(ng_pct, 2),
            "by_service_id": {f"0x{k:04X}": v for k, v in sorted(svc_counter.items())},
            "by_message_type": {f"0x{k:02X}": v for k, v in sorted(mt_counter.items())},
            "duration_s": round(duration, 3),
            "rate_pkt_s": round(rate, 1),
            "session_id_breaks": total_breaks,
            "session_id_break_rate": round(break_rate, 4),
            "session_id_breaks_by_msgtype": {
                f"0x{k:02X}": v for k, v in sorted(breaks_by_mt.items())},
            "session_id_missing": total_missing,
            "session_id_loss_rate": round(loss_rate, 4),
            "session_id_breaks_sd": sd_breaks,
            "session_id_wraparounds": total_wraps,
            "truncated_packets": truncated,
            "duplicate_packets": dup_count,
            "duplicates_removed": args.removed_dups,
        }
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
        print(f"[manifest] atualizado: {manifest_path}")

    # ---- exit code ----
    ok = (in_tolerance and truncated == 0 and dup_count == 0
          and breaks_ok and loss_ok)
    if not ok:
        print("[VALIDACAO] FALHA")
        sys.exit(1)
    print("[VALIDACAO] OK")
    sys.exit(0)


if __name__ == "__main__":
    main()
