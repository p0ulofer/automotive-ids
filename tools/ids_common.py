#!/usr/bin/env python3
"""Utilitarios partilhados da Fase 5 (IDS Koyama et al., VTC2022-Spring).

Este modulo NAO contem logica de deteccao: apenas carrega os artefactos
produzidos na Fase 4 (features/*.csv, features/thresholds.json,
features/MANIFEST.json) e formaliza a "tupla de estado" usada pelos dois
algoritmos (ids_realtime.py, ids_retroactive.py).

Decisoes de projeto (ver docs/ids_model.md):
  - A tupla de estado (a "transicao" da Fig. 7/8) e composta pelas features
    DISCRETIZADAS da Tabela IV: bins de dT_req/dT_res, bins das medias moveis,
    dP_req/dP_res (categorico) e OS. As features do CSV ja sao relativas ao
    pacote anterior da mesma stream_key (calculadas na Fase 4), pelo que a
    tupla do pacote E a transicao -- nada e recalculado aqui.
  - `n_cs` (# of CSs) NAO entra na tupla: e verificado separadamente pelo
    fluxo da Fig. 8 (deteccao de numero anomalo de CSs), tal como no artigo.
    Incluir `n_cs` na tupla faria com que TODOS os pacotes posteriores a uma
    subida do contador fossem marcados (falsos positivos em massa).
  - `os` e removido (componente "NA") nas duas stream_keys excluidas por
    decisao da Fase 4 (contador de Session-ID partilhado entre servicos).
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

NA = "NA"

#: Identidade do remetente usada para a chave de sessao e a contagem de CSs:
#:   * `mac`       -- (src_ip, src_mac). SO para o cenario-oraculo (o MAC nao
#:                    existe nos datasets normais da Fase 4 e nunca deve ser
#:                    usado pelo detetor; ver docs/ids_model.md, experimento E2).
#:   * `ip`        -- (src_ip). Cenario "sem MAC" principal.
#:   * `ip_client` -- (src_ip, client_id). Cenario "sem MAC" alternativo.
IDENTITIES = ("mac", "ip", "ip_client")

#: Componentes da tupla de estado, por ordem canonica.
TUPLE_FEATURES = [
    "dt_prev_req_bin",
    "dt_prev_res_bin",
    "dt_prev_req_avg_bin",
    "dt_prev_res_avg_bin",
    "dp_prev_req",
    "dp_prev_res",
    "os",
]

#: Ficheiros de entrada da Fase 4.
DEFAULT_FEATURES_DIR = "features"
DEFAULT_THRESHOLDS = "features/thresholds.json"
DEFAULT_MANIFEST = "features/MANIFEST.json"

#: Datasets normais (treino) e de ataque (teste) da Fase 2/3.
NORMAL_DATASETS = ["normal_rr", "normal_nepc", "normal_nec"]
ATTACK_DATASETS = [
    "ARR-Req-a1", "ARR-Res-a1",
    "ANEpc-a1", "ANEpc-a2", "ANEpc-a3", "ANEpc-a4",
    "ANEpc-a5", "ANEpc-a6", "ANEpc-a7", "ANEpc-a8",
    "ANEc-a1",
]


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())


def save_json(obj, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def split_stream_key(stream_key: str):
    """`svc|tipo|src` -> (svc, tipo, src). O src_ip nao contem '|'."""
    svc, tl, src = stream_key.split("|", 2)
    return svc, tl, src


def load_exclusions(manifest_path: str | Path = DEFAULT_MANIFEST) -> set:
    """Stream_keys para as quais a feature `os` foi excluida (Fase 4)."""
    try:
        manifest = load_json(manifest_path)
    except FileNotFoundError:
        return set()
    exc = manifest.get("exclusions", {}).get("os_feature", {})
    return set(exc.get("excluded_stream_keys", []))


def discretize(value, feat: str, svc: str, tl: str, thresholds: dict) -> str:
    """Discretiza um valor dT reutilizando os limiares da Fase 4 (sem os reaprender).

    Usado para as medias moveis (`dt_prev_req_avg` / `dt_prev_res_avg`), que a
    Fase 4 deixou continuas mas a Tabela IV lista como features de estado.
    """
    if value is None or value == "":
        return NA
    th = thresholds.get(feat, {}).get(f"{svc}|{tl}")
    if th is None:
        return NA
    v = float(value)
    if v <= th["b1"]:
        return "short"
    if v <= th["b2"]:
        return "medium"
    return "long"


def state_tuple(row: dict, thresholds: dict, excluded_os_keys: set) -> tuple:
    """Tupla de estado discretizada (sem `n_cs`) de uma linha de features/*.csv."""
    svc, tl, _src = split_stream_key(row["stream_key"])
    ov = row.get("os", "")
    os_comp = NA if row["stream_key"] in excluded_os_keys else (ov or NA)
    return (
        row.get("dt_prev_req_bin") or NA,
        row.get("dt_prev_res_bin") or NA,
        discretize(row.get("dt_prev_req_avg"), "dt_prev_req", svc, tl, thresholds),
        discretize(row.get("dt_prev_res_avg"), "dt_prev_res", svc, tl, thresholds),
        row.get("dp_prev_req") or NA,
        row.get("dp_prev_res") or NA,
        os_comp,
    )


def state_str(state: tuple) -> str:
    return "|".join(state)


def is_checkable(row: dict) -> bool:
    """True se o pacote tem pacote anterior na mesma stream_key.

    A Fase 4 deixa `dt_prev_res` vazio exactamente no 1.o pacote de cada
    stream. Sem referencia anterior nao ha transicao para comparar (o fluxo
    da Fig. 8 trata o 1.o pacote como inicio de sessao: so incrementa CSs).
    """
    return row.get("dt_prev_res", "") not in (None, "")


def sender_id(row: dict, identity: str) -> str:
    """Identidade do remetente (string estavel), segundo o cenario escolhido.

    NUNCA usa `src_mac` excepto no cenario-oraculo `mac`. Ver `IDENTITIES`.
    """
    ip = row.get("src_ip", "")
    if identity == "ip":
        return ip
    if identity == "ip_client":
        return f"{ip}|{row.get('client_id', '')}"
    return f"{ip}|{row.get('src_mac', '')}"      # mac (oraculo)


def count_rows(path: str | Path) -> int:
    """Numero de linhas de dados (sem cabecalho)."""
    with open(path, "r", newline="") as fh:
        return sum(1 for _ in fh) - 1


def iter_rows(path: str | Path, row_filter=None):
    """Itera `(idx, row)` de um CSV de features, opcionalmente filtrando por idx."""
    with open(path, newline="") as fh:
        for i, row in enumerate(csv.DictReader(fh)):
            if row_filter is None or row_filter(i):
                yield i, row
