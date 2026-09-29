#!/usr/bin/env bash
# =============================================================================
# scripts/gen_dataset.sh -- Gera datasets normais (Fase 2 someip-ids)
#
# Uso:
#   ./scripts/gen_dataset.sh <normal_rr|normal_nepc|normal_nec> [--scale 0.05]
#
# Orquestra:
#   1. regressao ANTES  (raw PREROUTING 2 ACCEPT + 6 DROP)
#   2. sobe ambiente com override docker-compose.datasets.yml (3 servicos)
#   3. capturas tcpdump POR INTERFACE (sem -i any; ecu2 eth0/eth1 separados)
#   4. roda ids_dataset_server (ecu5) + ids_dataset_client (ecu1)
#      NEpc EM PARALELO com RR; NEc EM PARALELO com RR + NEpc
#   5. para tudo, regressao DEPOIS
#   6. merge + dedup -> datasets/normal/<nome>.pcap
#   7. validacao -> MANIFEST.json
#
# --scale N: fracao do tempo total (0.05 = 5% do volume alvo).
# Seeds fixas no YAML => runs reprodutiveis.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

warn()  { echo "[gen_dataset] $*"; }
die()   { echo "[gen_dataset][ERRO] $*" >&2; exit 1; }

raw_counts() {
    docker run --rm --net=host --privileged --entrypoint sh \
        automotive-ids/vsomeip:latest -c \
        'a=$(iptables -t raw -S PREROUTING | grep -c -- "-j ACCEPT"); d=$(iptables -t raw -S PREROUTING | grep -c -- "-j DROP"); echo "$a $d"' \
        2>/dev/null || echo "? ?"
}

# --- argumentos --------------------------------------------------------------
SCALE=1.0
DATASET=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scale) SCALE="${2:?}"; shift 2 ;;
        normal_rr|normal_nepc|normal_nec) DATASET="$1"; shift ;;
        *) die "argumento desconhecido: $1 (uso: gen_dataset.sh <normal_rr|normal_nepc|normal_nec> [--scale 0.05])" ;;
    esac
done
[[ -n "$DATASET" ]] || die "uso: gen_dataset.sh <normal_rr|normal_nepc|normal_nec> [--scale 0.05]"

CONFIG_YAML="$ROOT/config/datasets/${DATASET}.yaml"
[[ -f "$CONFIG_YAML" ]] || die "config nao encontrada: $CONFIG_YAML"

# --- leitura do YAML ---------------------------------------------------------
eval "$(python3 - "$CONFIG_YAML" <<'PY'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))
for k, v in cfg.items():
    if isinstance(v, bool): v = 'true' if v else 'false'
    elif isinstance(v, float) and v == int(v): v = int(v)
    print(f"DS_{k.upper()}='{v}'")
PY
)" || die "falha ao ler $CONFIG_YAML"

DURATION_FULL="${DS_DURATION_S:?falta duration_s no yaml}"
DURATION=$(python3 -c "print(max(5, int($DURATION_FULL * $SCALE)))")
SEED="${DS_SEED:-42}"
P_NG="${DS_P_NG:-0}"
CYCLE_MS="${DS_REQUEST_CYCLE_MS:-100}"
NOTIFY_MS="${DS_NOTIFY_CYCLE_MS:-10}"
SETMODE_EVERY="${DS_SETMODE_EVERY_CYCLES:-50}"
TARGET_PKTS="${DS_TARGET_PACKETS:-0}"

warn "dataset=$DATASET scale=$SCALE duracao=${DURATION}s (full=${DURATION_FULL}s) seed=$SEED target=$TARGET_PKTS"

# --- flags por dataset (RR em paralelo em todos) -----------------------------
case "$DATASET" in
    normal_rr)   SRV_FLAGS="--rr"             ; CLI_FLAGS="--rr" ;;
    normal_nepc) SRV_FLAGS="--rr --nepc"       ; CLI_FLAGS="--rr --nepc" ;;
    normal_nec)  SRV_FLAGS="--rr --nepc --nec" ; CLI_FLAGS="--rr --nepc --nec" ;;
esac

# --- 1. regressao ANTES ------------------------------------------------------
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^ecu1$'; then
    RAW=$(raw_counts)
    warn "regressao ANTES: ACCEPT/DROP = $RAW"
    [[ "$RAW" == "2 6" ]] || warn "AVISO: esperado 2/6 antes do run"
else
    warn "ambiente em baixo; vamos subir"
fi

# --- 2. sobe ambiente com override -------------------------------------------
warn "docker compose up (override datasets)..."
docker compose -f docker-compose.yml -f docker-compose.datasets.yml \
    up -d --build 2>&1 | tail -3
sleep 12

./scripts/smoke_test.sh --host-raw up >/dev/null 2>&1 \
    || die "falha ao aplicar excecoes raw"

RAW=$(raw_counts)
[[ "$RAW" == "2 6" ]] || die "regressao DEPOIS do up: esperado 2/6, obtido: $RAW"
warn "regressao DEPOIS do up: $RAW OK"

# --- 3. capturas por interface -----------------------------------------------
mkdir -p "$ROOT/pcaps/ds" "$ROOT/datasets/normal" "$ROOT/logs/ds"
rm -f "$ROOT/pcaps/ds/"*.pcap "$ROOT/pcaps/ds/"*.pcap[0-9] "$ROOT/logs/ds/"*.log

FILTRO='udp and (port 30490 or port 30509 or port 30510 or port 30511)'

start_cap() { # $1=ecu $2=iface $3=ficheiro
    docker exec -d "$1" sh -c \
        "tcpdump -i '$2' -s 0 -U -w '/pcaps/ds/$3' '$FILTRO' > '/logs/ds/$3.log' 2>&1"
}

start_cap ecu1 eth0 ecu1_eth0.pcap
start_cap ecu2 eth0 ecu2_eth0.pcap   # lado net1
start_cap ecu2 eth1 ecu2_eth1.pcap   # lado net2 (arquivos SEPARADOS: nada de -i any)
start_cap ecu3 eth0 ecu3_eth0.pcap
start_cap ecu4 eth0 ecu4_eth0.pcap
start_cap ecu5 eth0 ecu5_eth0.pcap
sleep 1
for f in ecu1_eth0 ecu2_eth0 ecu2_eth1 ecu3_eth0 ecu4_eth0 ecu5_eth0; do
    docker exec ecu1 true 2>/dev/null
    ok=$(docker exec "${f%%_*}" pgrep -x tcpdump >/dev/null 2>&1 && echo sim || echo nao)
    [[ "$ok" == "sim" ]] || warn "AVISO: tcpdump nao arrancou em ${f}"
done
warn "capturas iniciadas (por interface)"

# --- 4. apps de dataset ------------------------------------------------------
warn "a iniciar servidor (ecu5) e cliente (ecu1)..."
docker exec -d ecu5 sh -c "exec ids_dataset_server $SRV_FLAGS \
    --p-ng $P_NG --notify-cycle $NOTIFY_MS --seed $SEED \
    --duration $DURATION > /logs/ds/server.log 2>&1" || die "falha ao iniciar servidor"
docker exec -d ecu1 sh -c "exec ids_dataset_client $CLI_FLAGS \
    --cycle $CYCLE_MS --setmode-every $SETMODE_EVERY --seed $SEED \
    --duration $DURATION > /logs/ds/client.log 2>&1" || die "falha ao iniciar cliente"

warn "a correr ${DURATION}s de trafego (datasets paralelos conforme $DATASET)..."
sleep "$DURATION"

# espera os apps terminarem (eles param sozinhos ao fim de --duration).
# NOTA: pgrep/pkill -x usa o "comm" (max 15 chars) e por isso NUNCA casava
# com "ids_dataset_server"/"ids_dataset_client"; usamos -f (cmdline).
waited=0
while [[ $waited -lt 60 ]]; do
    srv=$(docker exec ecu5 pgrep -f '^ids_dataset_server' >/dev/null 2>&1 && echo sim || echo nao)
    cli=$(docker exec ecu1 pgrep -f '^ids_dataset_client' >/dev/null 2>&1 && echo sim || echo nao)
    [[ "$srv" == "nao" && "$cli" == "nao" ]] && break
    sleep 5; waited=$((waited + 5))
done
if [[ "$srv" == "sim" || "$cli" == "sim" ]]; then
    warn "apps ainda ativos apos espera; a terminar..."
    docker exec ecu5 pkill -TERM -f '^ids_dataset_server' 2>/dev/null || true
    docker exec ecu1 pkill -TERM -f '^ids_dataset_client' 2>/dev/null || true
    sleep 5
fi
warn "apps terminados"

# --- 5. para capturas --------------------------------------------------------
for c in ecu1 ecu2 ecu3 ecu4 ecu5; do
    docker exec "$c" sh -c 'pkill -INT tcpdump' 2>/dev/null || true
done
sleep 3
warn "capturas paradas"

# --- 5b. regressao DEPOIS ----------------------------------------------------
RAW=$(raw_counts)
[[ "$RAW" == "2 6" ]] || die "regressao DEPOIS do run: esperado 2/6, obtido: $RAW"
warn "regressao DEPOIS do run: $RAW OK"

# --- 6. merge + dedup --------------------------------------------------------
OUT_PCAP="$ROOT/datasets/normal/${DATASET}.pcap"
warn "merge + dedup -> $OUT_PCAP"
MERGE_OUT=$(python3 "$ROOT/tools/merge_captures.py" "$OUT_PCAP" \
    "$ROOT/pcaps/ds/ecu1_eth0.pcap" \
    "$ROOT/pcaps/ds/ecu2_eth0.pcap" \
    "$ROOT/pcaps/ds/ecu2_eth1.pcap" \
    "$ROOT/pcaps/ds/ecu3_eth0.pcap" \
    "$ROOT/pcaps/ds/ecu4_eth0.pcap" \
    "$ROOT/pcaps/ds/ecu5_eth0.pcap" \
    --report 2>&1) || die "merge falhou"
echo "$MERGE_OUT"
DUPS=$(echo "$MERGE_OUT" | sed -n 's/.*descartados como duplicata: \([0-9]*\).*/\1/p')
DUPS="${DUPS:-0}"

# --- 7. extracao CSV ---------------------------------------------------------
warn "pcap_to_csv -> ${OUT_PCAP%.pcap}.csv"
python3 "$ROOT/tools/pcap_to_csv.py" "$OUT_PCAP" --label 0 \
    || warn "pcap_to_csv com avisos"

# --- 8. validacao + MANIFEST -------------------------------------------------
warn "validacao..."
VALID=0
python3 "$ROOT/tools/validate_dataset.py" "$OUT_PCAP" \
    --dataset "$DATASET" --scale "$SCALE" --removed-dups "$DUPS" \
    --update-manifest || VALID=1

# --- 9. resumo ---------------------------------------------------------------
SZ=$(du -h "$OUT_PCAP" | cut -f1)
warn "=== RESUMO $DATASET ==="
warn "  ficheiro : datasets/normal/${DATASET}.pcap ($SZ)"
warn "  duracao  : ${DURATION}s (scale=$SCALE, full=${DURATION_FULL}s)"
warn "  seed     : $SEED  p_ng=$P_NG  cycle=${CYCLE_MS}ms  notify=${NOTIFY_MS}ms"
warn "  dups removidas: $DUPS"
warn "  artefactos: datasets/normal/MANIFEST.json, ${OUT_PCAP%.pcap}.csv"
warn "  regressao : ACCEPT/DROP = $RAW"
if [[ "$VALID" -ne 0 ]]; then
    warn "  validacao: FALHA (ver saida acima)"
    exit 1
fi
warn "  validacao: OK"
