#!/usr/bin/env bash
# =============================================================================
# scripts/gen_attack_dataset.sh -- Gera datasets de ATAQUE (Fase 3 someip-ids)
#
# Uso:
#   ./scripts/gen_attack_dataset.sh <ARR-Req-a1|ARR-Res-a1|ANEpc-a1|ANEc-a1|...>
#       [--scale 0.05]
#
# Orquestra (padrao de gen_dataset.sh + atacante):
#   1. regressao ANTES  (raw PREROUTING 2 ACCEPT + 6 DROP)
#   2. sobe ambiente (datasets + attacker) com ecu6
#   3. setup bridge: FDB estatico ecu1/ecu2 + learning OFF na porta do ecu6
#   4. capturas tcpdump POR INTERFACE (6 ecus, ordem fixa para o dedup)
#   5. atacante (ecu6): poison ARP + args do YAML; --stats-file em logs
#   6. ids_dataset_server (ecu5) + ids_dataset_client (ecu1)
#   7. para apps; para atacante; teardown bridge (neigh flush, FDB, learning)
#   8. capturas para; regressao DEPOIS
#   9. merge + dedup -> datasets/attack/<id>.pcap
#  10. pcap_to_csv --attacker-mac (label=1 por src MAC do atacante)
#  11. validate --attack -> datasets/attack/MANIFEST.json
#
# --scale N: fracao do tempo total (0.05 = 5% do volume alvo).
# Seeds fixas no YAML => runs reprodutiveis.
#
# Variaveis de ambiente (opcionais; nao alteram o comportamento por omissao):
#   IDS_ECU2=1   inclui o sidecar ids-ecu2 (docker-compose.ids.yml) no up
#   NO_BUILD=1   nao rebuilda imagens (preserva a imagem do ecu2; usar --no-build)
#   SKIP_UP=1    nao faz compose up (laboratorio ja' levantado por outro script)
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- compose / build (env) ---------------------------------------------------
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.datasets.yml \
               -f docker-compose.attacker.yml)
if [[ "${IDS_ECU2:-0}" = "1" ]]; then
    COMPOSE_FILES+=(-f docker-compose.ids.yml)
fi
BUILD_FLAGS=(--build)
if [[ "${NO_BUILD:-0}" = "1" ]]; then
    BUILD_FLAGS=(--no-build)
fi

warn()  { echo "[gen_attack] $*"; }
die()   { echo "[gen_attack][ERRO] $*" >&2; exit 1; }

raw_counts() {
    docker run --rm --net=host --privileged --entrypoint sh \
        automotive-ids/vsomeip:latest -c \
        'a=$(iptables -t raw -S PREROUTING | grep -c -- "-j ACCEPT"); d=$(iptables -t raw -S PREROUTING | grep -c -- "-j DROP"); echo "$a $d"' \
        2>/dev/null || echo "? ?"
}

# regressao raw: 2 ACCEPT (smoke_test) + DROP anti-spoof por host com IP
# statico configurado (6 ECUs; +1 se o ecu6/atacante estiver up)
expected_raw() {
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'ecu6'; then
        echo "2 7"
    else
        echo "2 6"
    fi
}

# comando no host via container privilegiado (mesmo padrao do smoke_test.sh)
hostsh() {
    docker run --rm --net=host --privileged --entrypoint sh \
        automotive-ids/vsomeip:latest -c "$1"
}

# iface do HOST que e' o peer da iface do container (via iflink/ifindex)
# $1=container $2=iface (default eth0)
veth_of() {
    local ifc="${2:-eth0}" link
    link=$(docker exec "$1" cat "/sys/class/net/$ifc/iflink" 2>/dev/null) || return 1
    ip -o link | awk -F': ' -v i="$link" '$1==i {split($2,a,"@"); print a[1]; exit}'
}

# --- argumentos --------------------------------------------------------------
SCALE=1.0
DATASET=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scale) SCALE="${2:?}"; shift 2 ;;
        ARR-Req-*|ARR-Res-*|ANEpc-*|ANEc-*) DATASET="$1"; shift ;;
        *) die "argumento desconhecido: $1 (uso: gen_attack_dataset.sh <id> [--scale 0.05])" ;;
    esac
done
[[ -n "$DATASET" ]] || die "uso: gen_attack_dataset.sh <ARR-Req-a1|...> [--scale 0.05]"

# --- protecao contra sobrescrita do dataset completo -------------------------
# O dataset completo (scale 1.0) e' o que alimenta as Fases 4/5. Runs reduzidos
# (--scale != 1) servem so' para iterar: gravam em <id>_scale<N>.pcap|.csv e NAO
# tocam no MANIFEST canonico (datasets/attack/MANIFEST.json).
if [[ "$SCALE" != "1" && "$SCALE" != "1.0" ]]; then
    DATASET_ID="${DATASET}_scale${SCALE}"
    MANIFEST_ARGS=()
    warn "scale=$SCALE != 1 -> dataset reduzido '${DATASET_ID}' (NAO sobrescreve '${DATASET}')"
else
    DATASET_ID="$DATASET"
    MANIFEST_ARGS=(--update-manifest)
fi

CONFIG_YAML="$ROOT/config/datasets/attack/${DATASET}.yaml"
[[ -f "$CONFIG_YAML" ]] || die "config nao encontrada: $CONFIG_YAML"

# base (dataset de trafego de referencia) vem do proprio yaml de ataque;
# precisa de ser conhecido ANTES do merge
BASE=$(grep -E "^base:" "$CONFIG_YAML" | head -1 | awk '{print $2}')
[[ -n "$BASE" ]] || die "falta campo 'base' no yaml de ataque"
BASE_YAML="$ROOT/config/datasets/${BASE}.yaml"
[[ -f "$BASE_YAML" ]] || die "yaml base nao encontrado: $BASE_YAML"

# --- leitura do YAML (ataque por cima; chaves em falta vem do base) ---------
eval "$(python3 - "$CONFIG_YAML" "$BASE_YAML" <<'PY'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))
base = yaml.safe_load(open(sys.argv[2]))
merged = {**base, **cfg}          # o yaml de ataque tem prioridade
for k, v in merged.items():
    if isinstance(v, bool): v = 'true' if v else 'false'
    elif isinstance(v, float) and v == int(v): v = int(v)
    print(f"DS_{k.upper()}='{v}'")
PY
)" || die "falha ao ler $CONFIG_YAML"

DURATION_FULL="${DS_DURATION_S:?falta duration_s no yaml}"
DURATION=$(python3 -c "print(max(5, int($DURATION_FULL * $SCALE)))")
SEED="${DS_SEED:-42}"
BASE="${DS_BASE:?falta base no yaml}"
ATTACKER_ARGS="${DS_ATTACKER_ARGS:-}"
P_NG="${DS_P_NG:-0}"
CYCLE_MS="${DS_REQUEST_CYCLE_MS:-100}"
NOTIFY_MS="${DS_NOTIFY_CYCLE_MS:-10}"
SETMODE_EVERY="${DS_SETMODE_EVERY_CYCLES:-50}"

warn "dataset=$DATASET base=$BASE scale=$SCALE duracao=${DURATION}s (full=${DURATION_FULL}s) seed=$SEED"
warn "attacker_args: $ATTACKER_ARGS"

# --- flags por base (RR em paralelo em todos) --------------------------------
case "$BASE" in
    normal_rr)   SRV_FLAGS="--rr"             ; CLI_FLAGS="--rr" ;;
    normal_nepc) SRV_FLAGS="--rr --nepc"       ; CLI_FLAGS="--rr --nepc" ;;
    normal_nec)  SRV_FLAGS="--rr --nepc --nec" ; CLI_FLAGS="--rr --nepc --nec" ;;
    *) die "base desconhecida no yaml: $BASE" ;;
esac

# --- 1. regressao ANTES ------------------------------------------------------
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^ecu1$'; then
    RAW=$(raw_counts)
    warn "regressao ANTES: ACCEPT/DROP = $RAW"
    EXP=$(expected_raw)
    [[ "$RAW" == "$EXP" ]] || warn "AVISO: esperado $EXP antes do run"
else
    warn "ambiente em baixo; vamos subir"
fi

# --- 2. sobe ambiente (datasets + attacker) ----------------------------------
if [[ "${SKIP_UP:-0}" = "1" ]]; then
    warn "SKIP_UP=1 -> a assumir laboratorio ja' levantado (sem compose up)"
else
    warn "docker compose up (datasets + attacker)..."
    docker compose "${COMPOSE_FILES[@]}" up -d "${BUILD_FLAGS[@]}" 2>&1 | tail -3
    sleep 12
fi

./scripts/smoke_test.sh --host-raw up >/dev/null 2>&1 \
    || die "falha ao aplicar excecoes raw"

RAW=$(raw_counts)
EXP=$(expected_raw)
[[ "$RAW" == "$EXP" ]] || die "regressao DEPOIS do up: esperado $EXP, obtido: $RAW"
warn "regressao DEPOIS do up: $RAW OK"

docker ps --format '{{.Names}}' | grep -qx 'ecu6' || die "ecu6 (atacante) nao subiu"

# --- 3. setup bridge: FDB estatico + learning off na porta do atacante -------
# NOTA: a atribuicao eth0/eth1 <-> net1/net2 no ecu2 ALTERNA a cada
# recriacao do container; identificamos a iface da net1 PELO IP (192.168.1.1).
IF1=$(docker exec ecu1 sh -c "ip -o addr | grep -F 'inet 192.168.1.2/' | awk '{print \$2}'")
IF2=$(docker exec ecu2 sh -c "ip -o addr | grep -F 'inet 192.168.1.1/' | awk '{print \$2}'")
[[ -n "$IF1" && -n "$IF2" ]] \
    || die "ifaces net1 nao encontradas (ecu1='$IF1' ecu2='$IF2')"
MAC1=$(docker exec ecu1 cat "/sys/class/net/$IF1/address")
MAC2=$(docker exec ecu2 cat "/sys/class/net/$IF2/address")
MAC6=$(docker exec ecu6 cat /sys/class/net/eth0/address)
V1=$(veth_of ecu1 "$IF1") || true
V2=$(veth_of ecu2 "$IF2") || true
V6=$(veth_of ecu6 eth0) || true
[[ -n "$V1" && -n "$V2" && -n "$V6" ]] \
    || die "veth nao encontrados (v1='$V1' v2='$V2' v6='$V6')"
BR1=$(basename "$(readlink "/sys/class/net/$V1/brport/bridge" 2>/dev/null)" 2>/dev/null || echo "?")
[[ "$BR1" != "?" ]] || BR1=$(hostsh "basename \$(readlink /sys/class/net/$V1/brport/bridge)")
warn "bridge setup: br=$BR1 veths ecu1=$V1 ecu2=$V2 ecu6=$V6 macs $MAC1/$MAC2/$MAC6"

hostsh "
  # residuos de runs anteriores: MACs ecu1/ecu2 aprendidos na porta do atacante
  bridge fdb del $MAC1 dev $V6 dynamic 2>/dev/null
  bridge fdb del $MAC2 dev $V6 dynamic 2>/dev/null
  bridge fdb del $MAC1 dev $V6 static 2>/dev/null
  bridge fdb del $MAC2 dev $V6 static 2>/dev/null
  bridge fdb del $MAC1 dev $V1 master static 2>/dev/null
  bridge fdb del $MAC2 dev $V2 master static 2>/dev/null
  bridge fdb add $MAC1 dev $V1 master static
  bridge fdb add $MAC2 dev $V2 master static
  bridge link set dev $V6 learning off
" || die "setup bridge falhou"

# verifica: FDB tem os 2 estaticos e a porta do atacante com learning off
hostsh "bridge fdb show br $BR1" | grep -q "$MAC1.*static" \
    || die "FDB estatico de ecu1 nao aplicado"
hostsh "bridge fdb show br $BR1" | grep -q "$MAC2.*static" \
    || die "FDB estatico de ecu2 nao aplicado"
if hostsh "bridge fdb show br $BR1" | grep -E "$MAC1|$MAC2" | grep -q "$V6"; then
    die "residuo FDB: MAC ecu1/ecu2 ainda aponta para a porta do atacante ($V6)"
fi
hostsh "bridge -d link show dev $V6" | grep -q "learning off" \
    || die "learning off na porta do atacante nao aplicado"
warn "bridge OK (FDB statics + learning off em $V6)"

# primagem deterministica do MITM: as entradas de vizinho so aparecem com
# trafego (respostas ARP nao solicitadas nao criam entradas; arp_accept=0),
# e a 1.ª corrida ARP real-vs-atacante e' uma corrida -- o 1.º segundo de
# trafego escapa. Como o ecu1/ecu6 temos NET_ADMIN, fixamos a entrada ja com
# o MAC do atacante (equivalente ao estado apos o poison, sem corrida).
docker exec ecu1 ip neigh replace 192.168.1.1 lladdr "$MAC6" dev "$IF1" nud permanent \
    || die "neigh replace em ecu1 falhou"
docker exec ecu2 ip neigh replace 192.168.1.2 lladdr "$MAC6" dev "$IF2" nud permanent \
    || die "neigh replace em ecu2 falhou"
warn "neigh primado: ecu1->192.168.1.1 e ecu2->192.168.1.2 = $MAC6 (permanent)"

# --- 4. capturas por interface -----------------------------------------------
mkdir -p "$ROOT/pcaps/ds" "$ROOT/datasets/attack" "$ROOT/logs/ds"
rm -f "$ROOT/pcaps/ds/"*.pcap "$ROOT/pcaps/ds/"*.pcap[0-9] \
      "$ROOT/logs/ds/"*.log "$ROOT/logs/ds/"*_attacker_stats.json

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
    ok=$(docker exec "${f%%_*}" pgrep -x tcpdump >/dev/null 2>&1 && echo sim || echo nao)
    [[ "$ok" == "sim" ]] || warn "AVISO: tcpdump nao arrancou em ${f}"
done
warn "capturas iniciadas (por interface)"

# --- 5. atacante (ecu6) ------------------------------------------------------
ATK_STATS="$ROOT/logs/ds/${DATASET}_attacker_stats.json"
warn "a iniciar atacante (ecu6)..."
docker exec -d ecu6 sh -c "exec python3 /tools/attacker/attacker.py \
    --poison 192.168.1.2:192.168.1.1 --poison 192.168.1.1:192.168.1.2 \
    $ATTACKER_ARGS --duration $((DURATION + 60)) --seed $SEED \
    --stats-file '/logs/ds/${DATASET}_attacker_stats.json' \
    > /logs/ds/attacker.log 2>&1" \
    || die "falha ao iniciar atacante"
sleep 3
docker exec ecu6 pgrep -f 'attacker.py' >/dev/null 2>&1 \
    || { docker exec ecu6 cat /logs/ds/attacker.log 2>/dev/null; \
         die "atacante nao arrancou"; }
warn "atacante ativo (stats -> ${ATK_STATS#"$ROOT/"})"

# espera o poison estar ativo nos DOIS vizinhos antes do trafego (o
# learn_macs+primeiro poison pode demorar ~1s; sem isto o 1.º segundo
# de trafego escapa ao MITM e contamina as razoes de anomalia)
waited=0
while [[ $waited -lt 5 ]]; do
    n1=$(docker exec ecu1 ip neigh show 192.168.1.1 2>/dev/null | grep -c "$MAC6")
    n2=$(docker exec ecu2 ip neigh show 192.168.1.2 2>/dev/null | grep -c "$MAC6")
    if [[ "$n1" -ge 1 && "$n2" -ge 1 ]]; then
        break
    fi
    sleep 1; waited=$((waited + 1))
done
if [[ "$n1" -ge 1 && "$n2" -ge 1 ]]; then
    warn "poison confirmado em ecu1+ecu2 (apos ${waited}s)"
else
    die "poison NAO confirmado (ecu1=$n1 ecu2=$n2) apos ${waited}s"
fi

# --- 6. apps de dataset ------------------------------------------------------
warn "a iniciar servidor (ecu5) e cliente (ecu1)..."
docker exec -d ecu5 sh -c "exec ids_dataset_server $SRV_FLAGS \
    --p-ng $P_NG --notify-cycle $NOTIFY_MS --seed $SEED \
    --duration $DURATION > /logs/ds/server.log 2>&1" || die "falha ao iniciar servidor"
docker exec -d ecu1 sh -c "exec ids_dataset_client $CLI_FLAGS \
    --cycle $CYCLE_MS --setmode-every $SETMODE_EVERY --seed $SEED \
    --duration $DURATION > /logs/ds/client.log 2>&1" || die "falha ao iniciar cliente"

warn "a correr ${DURATION}s de trafego com ataque ($DATASET)..."
sleep "$DURATION"

# espera os apps terminarem (param sozinhos ao fim de --duration).
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

# --- 7. para atacante + teardown bridge --------------------------------------
docker exec ecu6 pkill -TERM -f 'attacker.py' 2>/dev/null || true
sleep 3
if [[ -f "$ATK_STATS" ]]; then
    warn "atacante stats: $(python3 -c "
import json,sys
s=json.load(open('$ATK_STATS'))
print(' '.join(f'{k}={v}' for k,v in sorted(s.items()) if v))
" 2>/dev/null || echo '(sem stats)')"
else
    warn "AVISO: $ATK_STATS nao gerado"
fi

# teardown: poe o ambiente como estava (se houver mais runs, o setup repoe).
# NOTA: `ip neigh flush all` NAO remove entradas PERMANENT (as que primamos);
# e' preciso delete explicito, senao fica blackhole nos runs seguintes.
docker exec ecu1 ip neigh del 192.168.1.1 dev "$IF1" 2>/dev/null || true
docker exec ecu2 ip neigh del 192.168.1.2 dev "$IF2" 2>/dev/null || true
hostsh "
  bridge fdb del $MAC1 dev $V1 master static 2>/dev/null
  bridge fdb del $MAC2 dev $V2 master static 2>/dev/null
  bridge link set dev $V6 learning on 2>/dev/null
" || warn "AVISO: teardown bridge com erros"
warn "teardown: neigh flush ecu1/ecu2 + FDB statics removidos + learning on"

# --- 8. para capturas --------------------------------------------------------
for c in ecu1 ecu2 ecu3 ecu4 ecu5; do
    docker exec "$c" sh -c 'pkill -INT tcpdump' 2>/dev/null || true
done
sleep 3
warn "capturas paradas"

# --- 8b. regressao DEPOIS ----------------------------------------------------
RAW=$(raw_counts)
EXP=$(expected_raw)
[[ "$RAW" == "$EXP" ]] || die "regressao DEPOIS do run: esperado $EXP, obtido: $RAW"
warn "regressao DEPOIS do run: $RAW OK"

# --- 9. merge + dedup --------------------------------------------------------
# ORDEM IMPORTA para o dedup: ver a nota em docs/attack_model.md -- a view em
# net1 (ecu1, ecu2_eth0) mostra os pacotes COM o src MAC do atacante antes de
# o ecu2 os re-encapsular ao rotear; o merge mantem a primeira vista de cada
# chave.
OUT_PCAP="$ROOT/datasets/attack/${DATASET_ID}.pcap"
warn "merge + dedup -> $OUT_PCAP"
MERGE_OUT=$(python3 "$ROOT/tools/merge_captures.py" "$OUT_PCAP" \
    "$ROOT/pcaps/ds/ecu1_eth0.pcap" \
    "$ROOT/pcaps/ds/ecu2_eth0.pcap" \
    "$ROOT/pcaps/ds/ecu2_eth1.pcap" \
    "$ROOT/pcaps/ds/ecu3_eth0.pcap" \
    "$ROOT/pcaps/ds/ecu4_eth0.pcap" \
    "$ROOT/pcaps/ds/ecu5_eth0.pcap" \
    --attacker-mac "$MAC6" --report 2>&1) || die "merge falhou"
echo "$MERGE_OUT"
DUPS=$(echo "$MERGE_OUT" | sed -n 's/.*descartados como duplicata: \([0-9]*\).*/\1/p')
DUPS="${DUPS:-0}"

# --- 10. extracao CSV com rotulo por MAC do atacante -------------------------
warn "pcap_to_csv --attacker-mac $MAC6 -> ${OUT_PCAP%.pcap}.csv"
python3 "$ROOT/tools/pcap_to_csv.py" "$OUT_PCAP" --attacker-mac "$MAC6" \
    || warn "pcap_to_csv com avisos"

# --- 11. validacao por rotulo + MANIFEST -------------------------------------
warn "validacao (modo ataque)..."
VALID=0
python3 "$ROOT/tools/validate_dataset.py" "$OUT_PCAP" \
    --dataset "$DATASET" --scale "$SCALE" --removed-dups "$DUPS" \
    --attack --attacker-mac "$MAC6" "${MANIFEST_ARGS[@]}" || VALID=1

# --- 12. resumo --------------------------------------------------------------
SZ=$(du -h "$OUT_PCAP" | cut -f1)
warn "=== RESUMO ${DATASET_ID} ==="
warn "  ficheiro : datasets/attack/${DATASET_ID}.pcap ($SZ)"
warn "  duracao  : ${DURATION}s (scale=$SCALE, full=${DURATION_FULL}s)"
warn "  seed     : $SEED  cycle=${CYCLE_MS}ms  notify=${NOTIFY_MS}ms"
warn "  attacker : $MAC6  args: $ATTACKER_ARGS"
warn "  stats    : logs/ds/${DATASET}_attacker_stats.json"
warn "  dups removidas: $DUPS"
if [[ "$DATASET_ID" == "$DATASET" ]]; then
    warn "  artefactos: datasets/attack/MANIFEST.json, ${OUT_PCAP%.pcap}.csv"
else
    warn "  artefactos: ${OUT_PCAP%.pcap}.csv (reduzido; MANIFEST NAO tocado)"
fi
warn "  regressao : ACCEPT/DROP = $RAW"
if [[ "$VALID" -ne 0 ]]; then
    warn "  validacao: FALHA (ver saida acima)"
    exit 1
fi
warn "  validacao: OK"
