#!/usr/bin/env python3
"""
tools/extract_features.py -- Fase 4 someip-ids: extrai features de transicao
de estado (Tabela IV de Koyama et al., VTC2022-Spring) dos CSVs ja gerados
(datasets/normal/*.csv e datasets/attack/*.csv), sem treinar modelo nenhum.

Saida: features/<nome>.csv = colunas originais + features + label (inalterado),
       features/thresholds.json (limiares de discretizacao aprendidos SO nos
       datasets normais) e contagens em features/MANIFEST.json.

Uso:
    python3 tools/extract_features.py [--only normal_rr --only ARR-Req-a1]
        [--out-dir features] [--thresholds features/thresholds.json]
        [--learn-only]

Sem --thresholds, os limiares sao aprendidos (passo 1) nos datasets NORMAIS e
gravaados em <out-dir>/thresholds.json; depois todos os CSVs escolhidos sao
processados (passo 2). Com --thresholds PATH existente, o passo 1 e' pulado.

Design (detalhes e decisoes em docs/feature_model.md):
  - chave de transicao (stream_key) = (Service ID, tipo, remetente);
    tipo = nome da Message Type para SOME/IP ou "SD:<entry>" para SD;
  - dt_prev_req: vs REQUEST anterior do MESMO remetente (linha REQUEST) ou do
    mesmo Service ID, qualquer remetente (linhas RESPONSE/NOTIFICATION);
  - dt_prev_res: vs pacote anterior do MESMO tipo+remetente+servico;
  - medias moveis: janela W=10 dos ultimos valores NAO-nulos da MESMA feature
    na MESMA stream_key (valor atual excluido);
  - discretizacao dt: anchors (min, mediana, max) aprendidos por
    (Service ID, tipo) SO nos normais; limites = pontos medios entre anchors;
  - dp: diferenca de payload em L1 (bytes sobreposicao) + categorica
    com/sem mudanca sobre os campos CONTINUOS do payload (docs/payload_model.md);
  - n_cs: numero de streams de sessao abertas do Service ID ate ao momento;
  - os: Session-ID em ordem estrita (prev+1 ou wrap 0xFFFF->0/1) na stream_key;
  - primeiro pacote de uma stream: features de referencia = vazio (N/A).
"""
import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

WINDOW_W = 10  # janela deslizante das medias de dT (artigo nao especifica)

FEATURE_COLS = [
    "dt_prev_req", "dt_prev_res",
    "dt_prev_req_avg", "dt_prev_res_avg",
    "dt_prev_req_bin", "dt_prev_res_bin",
    "dp_prev_req", "dp_prev_res",
    "dp_prev_req_l1", "dp_prev_res_l1",
    "n_cs", "os", "stream_key",
]

SD_PORT_TYPES = ("Offer", "Find", "Subscribe", "SubAck")


def type_label(is_sd, message_type_name, sd_entry_types):
    """Tipo do pacote para a chave de transicao (Tabela IV / Sec. V-B)."""
    if is_sd:
        parts = [p for p in (sd_entry_types or "").split(";") if p]
        names = sorted({p.rsplit("x", 1)[0] for p in parts})
        return "SD:" + "+".join(names) if names else "SD:?"
    return message_type_name or "?"


def in_order_session(a, b):
    """Session-ID em ordem estrita: prev+1 ou wraparound 0xFFFF -> 0x0000/0x0001."""
    if b == (a + 1) & 0xFFFF:
        return True
    if a == 0xFFFF and b in (0x0000, 0x0001):
        return True
    return False


def continuous_range(payload_len, tl):
    """Bytes CONTINUOS do payload do pacote ATUAL (docs/payload_model.md §1-2).

    NOTIFICATION/REQUEST 16 B: Speed+Steering (bytes 0-3) / contador ECHO.
    RESPONSE 4 B: byte 0 (eco do contador). REQUEST 2 B (SetMode): nenhum
    campo continuo -> comparar payload completo (fallback).
    """
    if tl == "NOTIFICATION" and payload_len >= 4:
        return (0, 4)
    if tl == "REQUEST" and payload_len >= 4:
        return (0, 4)
    if tl == "RESPONSE" and payload_len >= 1:
        return (0, 1)
    return None


def dp_l1(cur, ref):
    """Soma L1 das diferencas de byte sobre a sobreposicao dos dois payloads."""
    n = min(len(cur), len(ref))
    return sum(abs(cur[i] - ref[i]) for i in range(n))


def dp_cat(cur, ref, tl):
    """0 = sem mudanca / 1 = com mudanca nos campos CONTINUOS do payload."""
    n = min(len(cur), len(ref))
    if n == 0:
        return None
    cont = continuous_range(len(cur), tl)
    if cont is None:
        idxs = range(n)
    else:
        idxs = [i for i in range(cont[0], cont[1]) if i < n]
        if not idxs:
            idxs = range(n)
    return 1 if any(cur[i] != ref[i] for i in idxs) else 0


class StreamState:
    """Estado por stream_key = (Service ID, tipo, remetente)."""

    __slots__ = ("last_t", "last_session", "last_payload",
                 "dt_req_deque", "dt_res_deque")

    def __init__(self):
        self.last_t = None
        self.last_session = None
        self.last_payload = None
        self.dt_req_deque = deque(maxlen=WINDOW_W)
        self.dt_res_deque = deque(maxlen=WINDOW_W)


class Extractor:
    def __init__(self, thresholds=None, collect=None):
        # thresholds: {"dt_prev_req": {"SVC|TIPO": {...}}, "dt_prev_res": {...}}
        self.thresholds = thresholds or {"dt_prev_req": {}, "dt_prev_res": {}}
        self.collect = collect  # {"dt_prev_req": {key: [vals]}, ...} p/ aprendizagem
        self.streams = {}
        self.last_req_svc = {}     # svc -> (t, payload)
        self.last_req_sender = {}  # (svc, src) -> (t, payload)
        self.open_keys = defaultdict(set)  # svc -> chaves de sessao abertas
        self.na_counts = defaultdict(int)

    def _bin(self, dt, feat, svc, tl):
        if dt is None:
            return ""
        th = self.thresholds.get(feat, {}).get(f"{svc}|{tl}")
        if th is None:
            return ""
        if dt <= th["b1"]:
            return "short"
        if dt <= th["b2"]:
            return "medium"
        return "long"

    def process(self, row):
        ts = float(row["timestamp"])
        svc = row["service_id"]
        src = row["src_ip"]
        tl = type_label(row["is_sd"] == "1", row.get("message_type_name"),
                        row.get("sd_entry_types"))
        session = int(row["session_id"], 16)
        payload = bytes.fromhex(row["payload_hex"]) if row["payload_hex"] else b""
        key = (svc, tl, src)

        st = self.streams.get(key)
        if st is None:
            st = self.streams[key] = StreamState()

        # --- dt_prev_res / os / sessao (referencia = pacote anterior da stream)
        if st.last_t is None:
            dt_res = None
            os_val = None
            session_start = True
            prev_payload = None
        else:
            dt_res = ts - st.last_t
            os_val = 1 if in_order_session(st.last_session, session) else 0
            session_start = (not in_order_session(st.last_session, session)
                             and session < st.last_session)
            prev_payload = st.last_payload

        # --- dt_prev_req / dp_prev_req (referencia = REQUEST anterior)
        if tl == "REQUEST":
            ref = self.last_req_sender.get((svc, src))
        else:
            ref = self.last_req_svc.get(svc)
        if ref is None:
            dt_req = None
            dp_req_cat = None
            dp_req_l1 = None
        else:
            dt_req = ts - ref[0]
            dp_req_cat = dp_cat(payload, ref[1], tl)
            dp_req_l1 = dp_l1(payload, ref[1])

        # --- dp_prev_res
        if prev_payload is None and st.last_t is not None:
            # stream existe mas payload de referencia ausente (nao ocorre aqui)
            dp_res_cat = None
            dp_res_l1 = None
        elif st.last_t is None:
            dp_res_cat = None
            dp_res_l1 = None
        else:
            dp_res_cat = dp_cat(payload, prev_payload, tl)
            dp_res_l1 = dp_l1(payload, prev_payload)

        # --- medias moveis (valor atual excluido; ultimos W nao-nulos da stream)
        avg_req = (sum(st.dt_req_deque) / len(st.dt_req_deque)
                   if st.dt_req_deque else None)
        avg_res = (sum(st.dt_res_deque) / len(st.dt_res_deque)
                   if st.dt_res_deque else None)

        # --- n_cs: streams de sessao abertas do Service ID
        if key not in self.open_keys[svc]:
            self.open_keys[svc].add(key)  # nova stream; restart nao altera (supersede)
        n_cs = len(self.open_keys[svc])

        # --- bins
        bin_req = self._bin(dt_req, "dt_prev_req", svc, tl)
        bin_res = self._bin(dt_res, "dt_prev_res", svc, tl)

        # --- aprendizagem (somente datasets normais)
        if self.collect is not None:
            if dt_req is not None:
                self.collect["dt_prev_req"].setdefault(f"{svc}|{tl}", []).append(dt_req)
            if dt_res is not None:
                self.collect["dt_prev_res"].setdefault(f"{svc}|{tl}", []).append(dt_res)

        # --- update de estado
        if tl == "REQUEST":
            self.last_req_svc[svc] = (ts, payload)
            self.last_req_sender[(svc, src)] = (ts, payload)
        if dt_req is not None:
            st.dt_req_deque.append(dt_req)
        if dt_res is not None:
            st.dt_res_deque.append(dt_res)
        st.last_t = ts
        st.last_session = session
        st.last_payload = payload

        feats = {
            "dt_prev_req": dt_req, "dt_prev_res": dt_res,
            "dt_prev_req_avg": avg_req, "dt_prev_res_avg": avg_res,
            "dt_prev_req_bin": bin_req, "dt_prev_res_bin": bin_res,
            "dp_prev_req": dp_req_cat, "dp_prev_res": dp_res_cat,
            "dp_prev_req_l1": dp_req_l1, "dp_prev_res_l1": dp_res_l1,
            "n_cs": n_cs, "os": os_val,
            "stream_key": f"{svc}|{tl}|{src}",
        }
        for col in FEATURE_COLS:
            if feats[col] is None:
                self.na_counts[col] += 1
        return feats


def fmt(col, val):
    if val is None:
        return ""
    if col in ("dt_prev_req", "dt_prev_res", "dt_prev_req_avg", "dt_prev_res_avg"):
        return f"{val:.6f}"
    return str(val)


def _count_rows(path):
    """Numero de linhas de dados (sem cabecalho)."""
    with open(path, newline="") as fh:
        return sum(1 for _ in fh) - 1


def learn_thresholds(csv_paths, holdout=0.0):
    """Passo 1: coleta dTs nos NORMAIS e devolve anchors por (svc|tipo).

    E1b: com `holdout > 0` os limiares sao aprendidos SO nos primeiros
    (1 - holdout) de cada CSV normal -- o mesmo corte temporal do treino de E1
    (`evaluate_ids.py --holdout`). Por omissao (0.0) usa 100% dos normais, como
    a Fase 4 original.
    """
    collect = {"dt_prev_req": defaultdict(list), "dt_prev_res": defaultdict(list)}
    learned_rows = {}
    for path in csv_paths:
        total = _count_rows(path)
        cut = int(total * (1.0 - holdout)) if holdout > 0 else total
        ex = Extractor(collect=collect)
        with open(path, newline="") as fh:
            for i, row in enumerate(csv.DictReader(fh)):
                if i >= cut:
                    break
                ex.process(row)
        learned_rows[path.name] = {"rows_total": total, "rows_learned": cut}
        print(f"[learn] {path.name}: {cut}/{total} linhas"
              + (f" (holdout={holdout})" if holdout > 0 else "")
              + f" | dT_req={sum(len(v) for v in collect['dt_prev_req'].values())} "
              f"dT_res={sum(len(v) for v in collect['dt_prev_res'].values())}",
              file=sys.stderr)

    thresholds = {"window_w": WINDOW_W,
                  "method": ("anchors (min, mediana, max) sobre dTs dos datasets "
                             "NORMAIS; limites = pontos medios entre anchors"),
                  "learned_on": [p.name for p in csv_paths],
                  "learn_holdout": holdout,
                  "learned_rows": learned_rows,
                  "dt_prev_req": {}, "dt_prev_res": {}}
    for feat in ("dt_prev_req", "dt_prev_res"):
        for key, vals in sorted(collect[feat].items()):
            mn = min(vals)
            mx = max(vals)
            md = statistics.median(vals)
            thresholds[feat][key] = {
                "n": len(vals), "min": mn, "median": md, "max": mx,
                "b1": (mn + md) / 2.0, "b2": (md + mx) / 2.0,
            }
    return thresholds


def extract_one(path, out_dir, thresholds):
    """Passo 2: grava features/<nome>.csv e devolve contagens p/ MANIFEST."""
    out_path = out_dir / (path.stem + ".csv")
    ex = Extractor(thresholds=thresholds)
    n = 0
    with open(path, newline="") as fh, open(out_path, "w", newline="") as out:
        reader = csv.DictReader(fh)
        orig_cols = list(reader.fieldnames or [])
        writer = csv.writer(out)
        writer.writerow(orig_cols + FEATURE_COLS)
        for row in reader:
            feats = ex.process(row)
            writer.writerow([row[c] for c in orig_cols]
                            + [fmt(c, feats[c]) for c in FEATURE_COLS])
            n += 1
    return out_path, {
        "source": str(path),
        "file": out_path.name,
        "rows": n,
        "na": dict(ex.na_counts),
    }


def main():
    ap = argparse.ArgumentParser(
        description="Extrai features de transicao (Tabela IV) dos datasets CSV.")
    ap.add_argument("--normal-dir", default="datasets/normal")
    ap.add_argument("--attack-dir", default="datasets/attack")
    ap.add_argument("--out-dir", default="features")
    ap.add_argument("--only", action="append", default=[], metavar="NOME",
                    help="processa so estes datasets (stem do CSV); repetivel")
    ap.add_argument("--thresholds", default=None, metavar="PATH",
                    help="reusa limiares deste JSON (pula o aprendizado)")
    ap.add_argument("--learn-holdout", type=float, default=0.0, metavar="FRAC",
                    help="E1b: aprender os limiares de discretizacao SO nos "
                         "primeiros (1-FRAC) de cada normal (0.3 = treino de E1)")
    ap.add_argument("--learn-only", action="store_true",
                    help="so aprende e grava thresholds.json, nao extrai")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    normal_dir = root / args.normal_dir
    attack_dir = root / args.attack_dir
    out_dir = root / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    normal_csvs = sorted(normal_dir.glob("*.csv"))
    attack_csvs = sorted(attack_dir.glob("*.csv"))
    if not normal_csvs:
        sys.exit(f"ERRO: nenhum CSV normal em {normal_dir}")
    if args.only:
        wanted = set(args.only)
        normal_csvs = [p for p in normal_csvs if p.stem in wanted]
        attack_csvs = [p for p in attack_csvs if p.stem in wanted]
        missing = wanted - {p.stem for p in normal_csvs + attack_csvs}
        if missing:
            sys.exit(f"ERRO: --only desconhecido: {sorted(missing)}")
    targets = normal_csvs + attack_csvs

    # --- passo 1: limiares (SO nos normais)
    if args.thresholds:
        thresholds = json.loads(Path(args.thresholds).read_text())
        print(f"[thresholds] reutilizados de {args.thresholds}", file=sys.stderr)
    else:
        print(f"[learn] aprendendo limiares em {len(normal_csvs)} dataset(s) normal(is)"
              + (f" -- so os primeiros {1 - args.learn_holdout:.0%}"
                 if args.learn_holdout > 0 else ""), file=sys.stderr)
        thresholds = learn_thresholds(normal_csvs, holdout=args.learn_holdout)
        (out_dir / "thresholds.json").write_text(
            json.dumps(thresholds, indent=2, ensure_ascii=False) + "\n")
        print(f"[thresholds] gravados em {out_dir / 'thresholds.json'}", file=sys.stderr)

    if args.learn_only:
        return

    # --- passo 2: extracao
    manifest_path = out_dir / "MANIFEST.json"
    manifest = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError:
            manifest = {}
    manifest.setdefault("datasets", {})
    for path in targets:
        out_path, info = extract_one(path, out_dir, thresholds)
        manifest["datasets"][path.stem] = info
        total = info["rows"]
        nas = ", ".join(f"{c}={n}" for c, n in sorted(info["na"].items()) if n)
        print(f"[extract] {path.stem}: {total} linhas -> {out_path.name}"
              + (f"  (N/A: {nas})" if nas else ""))
    manifest["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest["tool"] = "tools/extract_features.py"
    manifest["window_w"] = WINDOW_W
    manifest["thresholds_file"] = "thresholds.json"
    manifest["thresholds_learned_on"] = thresholds.get("learned_on", [])
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(f"[manifest] atualizado: {manifest_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
