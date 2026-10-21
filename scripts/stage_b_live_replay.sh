#!/usr/bin/env bash
# =============================================================================
# Estagio B -- replay AO VIVO pela rede + medicao do jitter
#
#   emissor  -- reenvia um pcap congelado com o TEMPORISMO ORIGINAL
#               (tools/replay_pcap_live.py) atraves da stack de rede real
#   receptor -- o IDS em modo online (tools/ids_live.py --interface eth9)
#
# Ao contrário do replay deterministico (--pcap do ids_live.py, que da 0/0),
# aqui os timestamps sao os de CAPTURA: o objectivo e' QUANTIFICAR o desvio
# introduzido pelo jitter de rede, nao elimina-lo.
#
# Uso:
#   ./scripts/stage_b_live_replay.sh [dataset]      # default: ANEpc-a1
# =============================================================================
set -euo pipefail

DATASET="${1:-ANEpc-a1}"
NET="${NET:-someip_stageb}"
IMG="${IMG:-automotive-ids/attacker:latest}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCAP="$ROOT/datasets/attack/${DATASET}.pcap"
LABELS="$ROOT/datasets/attack/${DATASET}.csv"
OUT="$ROOT/results/ids_live_stageB/${DATASET}"
SENDER="stageb_sender_${DATASET}"
RECV="stageb_recv_${DATASET}"

cleanup() {
    docker rm -f "$SENDER" "$RECV" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[ -f "$PCAP" ] || { echo "ERRO: sem pcap $PCAP" >&2; exit 1; }

if ! docker network inspect "$NET" >/dev/null 2>&1; then
    docker network create --driver bridge --subnet 192.168.2.0/24 "$NET" \
        >/dev/null
    echo "[stageb] rede $NET criada (192.168.2.0/24)"
fi

mkdir -p "$OUT"
docker run -d --name "$RECV"   --cap-add NET_ADMIN --network "$NET" \
    -v "$ROOT:/work" -w /work "$IMG" sleep infinity >/dev/null
docker run -d --name "$SENDER" --cap-add NET_ADMIN --network "$NET" \
    -v "$ROOT:/work" -w /work "$IMG" sleep infinity >/dev/null
sleep 1

# Link veth DIRECTO entre os dois contentores (eth9).
# Porquê nao a bridge? Porque o host tem net.ipv4.ip_forward=1 e reencaminha
# as tramas cujo IP de destino esta' na sub-rede da bridge de volta para a
# bridge -> o receptor via cada trama DUAS vezes (3060 mensagens extra em
# ANEpc-a1). Com o veth directo, a stack IP do host nao esta' no caminho e
# nao ha' reencaminhamento.
RECV_PID=$(docker inspect -f '{{.State.Pid}}' "$RECV")
SND_PID=$(docker inspect -f '{{.State.Pid}}' "$SENDER")
docker run --rm --privileged --pid=host --network host --entrypoint sh \
    "$IMG" -c "
    ip link del veths 2>/dev/null || true
    ip link del vethr 2>/dev/null || true
    ip link add veths type veth peer name vethr
    ip link set veths netns ${SND_PID}
    ip link set vethr netns ${RECV_PID}" >/dev/null
docker exec "$SENDER" sh -c "ip link set veths name eth9 && ip link set eth9 up"
docker exec "$RECV"   sh -c "ip link set vethr name eth9 && ip link set eth9 up"
sleep 1

RECV_MAC=$(docker exec "$RECV"   cat /sys/class/net/eth9/address | tr -d '\n')
SND_MAC=$(docker exec "$SENDER" cat /sys/class/net/eth9/address | tr -d '\n')
echo "[stageb] dataset=$DATASET  receptor=$RECV_MAC  emissor=$SND_MAC (eth9)"

# --- receptor: o IDS em modo online ---------------------------------------
# (dentro do contentor o repositorio esta' em /work -> caminhos relativos)
docker exec -d "$RECV" sh -c "python3 tools/ids_live.py --interface eth9 \
    --labels-csv 'datasets/attack/${DATASET}.csv' \
    --out-dir 'results/ids_live_stageB/${DATASET}' --name '$DATASET' \
    --dump-features 'results/ids_live_stageB/${DATASET}/features.csv' \
    > 'results/ids_live_stageB/${DATASET}/ids_live.log' 2>&1"
sleep 3   # deixa o sniffer instalar-se

# --- emissor: replay com o temporismo original ----------------------------
docker exec "$SENDER" python3 tools/replay_pcap_live.py \
    --pcap "datasets/attack/${DATASET}.pcap" --interface eth9 \
    --dst-mac "$RECV_MAC" --src-mac "$SND_MAC" \
    --out-json "results/ids_live_stageB/${DATASET}/replay_sender.json"

sleep 2
# O padrao usa a classe de caracteres para NAO casar com a propria linha de
# comando do `sh -c` (senao o pkill mata o shell -> exit 130).
docker exec "$RECV" sh -c "pkill -INT -f '[i]ds_live.py' || true"
sleep 3

# --- comparação com o baseline congelado -----------------------------------
python3 "$ROOT/tools/compare_live_replay.py" \
    --live-dir "$OUT" --dataset "$DATASET" \
    --features "features/${DATASET}.csv" \
    --live-features "$OUT/features.csv" \
    --out-json "$OUT/compare_${DATASET}.json"
