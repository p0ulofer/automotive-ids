#!/usr/bin/env bash
# =============================================================================
# scripts/ids_ecu2_validation.sh -- Fase 6 (extensao): validacao do IDS
# embarcado no ecu2 (sidecar) contra uma referencia "host" limpa.
#
# Porque nao basta escutar a interface do ecu2:
#   um veth so' ve' o trafego enderecado ao proprio contentor. A interface
#   net1 do ecu2 (192.168.1.1) NAO ve' o unicast ecu1<->ecu6 (atacante).
#   Escutar na bridge tambem nao serve: a bridge entrega a mesma trama duas
#   vezes (ingress + flood/forward), o que duplica as linhas do IDS.
#
# Montagem usada (uma copia por trama, nos dois lados):
#
#   * tc ingress mirror em cada veth do host (ecu1, ecu2, ecu6) -> `mirrorh`;
#   * par de veth `mirrorh` (host) <-> `mirror0` (movido para o netns do ecu2);
#   * referencia host : ids_live.py num contentor --net=host em `mirrorh`;
#   * pcap referencia : tcpdump num contentor --net=host em `mirrorh`;
#   * sidecar         : ids-ecu2 (netns do ecu2) em `mirror0`.
#
# Assim as duas testemunhas veem exactamente as mesmas tramas net1, incluindo
# o trafego do atacante, sem duplicacao e sem sudo interactivo.
#
# Depois corre o gerador de ataque normal (gen_attack_dataset.sh) em modo
# SKIP_UP=1 (o laboratorio ja' esta' levantado por este script) e compara as
# classificacoes e metricas (label derivada do MAC do atacante).
#
# Uso:
#   ./scripts/ids_ecu2_validation.sh [dataset] [scale]
#     default: ANEpc-a1 0.10
#     exemplos: ./scripts/ids_ecu2_validation.sh ANEpc-a1 0.10
#               ./scripts/ids_ecu2_validation.sh ARR-Res-a1 0.10
#
# Modo "deixar a correr" (para atacar manualmente):
#   NO_ATTACK=1 ./scripts/ids_ecu2_validation.sh ANEpc-a1 0.10
#     -> monta tudo e sai; o IDS continua a correr.
#   # noutro terminal:
#   SKIP_UP=1 NO_BUILD=1 ./scripts/gen_attack_dataset.sh ANEpc-a1 --scale 0.10
#   # parar e limpar:
#   DOWN=1 ./scripts/ids_ecu2_validation.sh
#
# Saidas:
#   results/ids_live_ecu2/<dataset>/host/          (referencia host)
#   results/ids_live_ecu2/<dataset>/sidecar/       (IDS dentro do ecu2)
#   results/ids_live_ecu2/<dataset>/mirror_host.pcap
#   results/ids_live_ecu2/<dataset>/compare_<dataset>.json
#   results/ids_live_ecu2/<dataset>/metadata.json
#
# Nao faz build: usa as imagens existentes (automotive-ids/vsomeip:latest e
# automotive-ids/attacker:latest). Nao altera a imagem nem a config do ecu2.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DATASET="${1:-ANEpc-a1}"
SCALE="${2:-0.10}"
IMG="automotive-ids/attacker:latest"
BPF='udp and (port 30490 or port 30509 or port 30510 or port 30511)'
OUT_ROOT="$ROOT/results/ids_live_ecu2"
RUN_DIR="$OUT_ROOT/$DATASET"
HOST_OUT="$RUN_DIR/host"
SIDE_OUT="$RUN_DIR/sidecar"
HOST_REF="ids-host-ref-$$"
PCAP_REF="ids-mirror-pcap-$$"
STATE_FILE="$OUT_ROOT/.live_state"

COMPOSE_BASE=(docker compose -f docker-compose.yml -f docker-compose.datasets.yml \
              -f docker-compose.attacker.yml)
COMPOSE_IDS=("${COMPOSE_BASE[@]}" -f docker-compose.ids.yml)

warn() { echo "[ids-ecu2-val] $*"; }
die()  { echo "[ids-ecu2-val][ERRO] $*" >&2; exit 1; }

# --- helpers de rede ---------------------------------------------------------
hostsh() { # comando no host via contentor privilegiado (sem sudo)
    docker run --rm --net=host --privileged --pid=host --entrypoint sh "$IMG" -c "$1"
}

net1_iface() { # $1=contentor $2=ip sem mascara
    docker exec "$1" sh -c \
        "ip -o -4 addr show | awk 'index(\$4,\"$2/\")==1 {print \$2; exit}'"
}

veth_of() { # $1=contentor $2=iface
    local link
    link=$(docker exec "$1" cat "/sys/class/net/$2/iflink") || return 1
    ip -o link | awk -F': ' -v i="$link" \
        '$1==i {split($2,a,"@"); print a[1]; exit}'
}

V1="" V2="" V6=""
MIRROR_UP=0
STOPPED=0
LEAVE_RUNNING=0

write_state() {
    {
        printf 'DATASET=%q\n' "$DATASET"
        printf 'SCALE=%q\n' "$SCALE"
        printf 'V1=%q\n' "$V1"
        printf 'V2=%q\n' "$V2"
        printf 'V6=%q\n' "$V6"
        printf 'HOST_REF=%q\n' "$HOST_REF"
        printf 'PCAP_REF=%q\n' "$PCAP_REF"
    } > "$STATE_FILE"
}

cleanup_mirror() {
    [ "$MIRROR_UP" = "1" ] || return 0
    warn "a remover mirror (tc ingress + veth mirrorh/mirror0)..."
    hostsh "
      for V in $V1 $V2 $V6; do
        tc qdisc del dev \$V handle ffff: ingress 2>/dev/null || true
      done
      ip link del mirrorh 2>/dev/null || true
    " || true
    MIRROR_UP=0
}

stop_ids() {
    [ "$STOPPED" = "1" ] && return 0
    if [ "$LEAVE_RUNNING" = "1" ]; then
        warn "sessao deixada a correr (NO_ATTACK=1); limpar com DOWN=1"
        return 0
    fi
    STOPPED=1
    set +e
    # SIGINT (stop_signal do compose) -> ids_live.py faz finish()/flush.
    if docker inspect -f '{{.State.Running}}' ids-ecu2 2>/dev/null | grep -qx true; then
        warn "a parar ids-ecu2 (SIGINT -> flush do retro)..."
        "${COMPOSE_IDS[@]}" stop ids-ecu2 >/dev/null 2>&1
    fi
    if docker inspect -f '{{.State.Running}}' "$HOST_REF" 2>/dev/null | grep -qx true; then
        warn "a parar referencia host (SIGINT)..."
        docker kill -s INT "$HOST_REF" >/dev/null 2>&1
        for _ in $(seq 1 30); do
            docker inspect -f '{{.State.Running}}' "$HOST_REF" 2>/dev/null \
                | grep -qx true || break
            sleep 1
        done
        docker kill "$HOST_REF" >/dev/null 2>&1
    fi
    # pcap de referencia: parar depois do IDS para nao perder o flush final.
    if docker inspect -f '{{.State.Running}}' "$PCAP_REF" 2>/dev/null | grep -qx true; then
        warn "a parar tcpdump de referencia (SIGINT)..."
        docker kill -s INT "$PCAP_REF" >/dev/null 2>&1
        for _ in $(seq 1 20); do
            docker inspect -f '{{.State.Running}}' "$PCAP_REF" 2>/dev/null \
                | grep -qx true || break
            sleep 0.5
        done
        docker kill "$PCAP_REF" >/dev/null 2>&1
    fi
    # Logs (antes de remover os contentores auxiliares).
    if [ -d "$SIDE_OUT" ]; then
        docker logs ids-ecu2 > "$SIDE_OUT/ids_live.log" 2>&1 || true
    fi
    if [ -d "$HOST_OUT" ]; then
        docker logs "$HOST_REF" > "$HOST_OUT/ids_live.log" 2>&1 || true
    fi
    if [ -d "$RUN_DIR" ]; then
        docker logs "$PCAP_REF" > "$RUN_DIR/mirror_tcpdump.log" 2>&1 || true
    fi
    docker rm -f "$HOST_REF" "$PCAP_REF" >/dev/null 2>&1
    cleanup_mirror
}
trap 'rc=$?; stop_ids; exit $rc' EXIT

# --- modo DOWN: derruba uma sessao deixada a correr com NO_ATTACK=1 ----------
if [ "${DOWN:-0}" = "1" ]; then
    [ -f "$STATE_FILE" ] || die "sem sessao viva registada em $STATE_FILE"
    # shellcheck disable=SC1090
    . "$STATE_FILE"
    RUN_DIR="$OUT_ROOT/$DATASET"
    HOST_OUT="$RUN_DIR/host"
    SIDE_OUT="$RUN_DIR/sidecar"
    MIRROR_UP=1
    warn "a derrubar a sessao viva de $DATASET ..."
    stop_ids
    rm -f "$STATE_FILE"
    warn "sessao terminada."
    exit 0
fi

# --- pre-condicoes -----------------------------------------------------------
docker image inspect automotive-ids/vsomeip:latest >/dev/null 2>&1 \
    || die "imagem automotive-ids/vsomeip:latest nao existe (nao vou buildar)"
docker image inspect "$IMG" >/dev/null 2>&1 \
    || die "imagem $IMG nao existe (nao vou buildar)"
[ -f "config/datasets/attack/${DATASET}.yaml" ] \
    || die "config do dataset nao encontrada: config/datasets/attack/${DATASET}.yaml"
docker run --rm --entrypoint sh "$IMG" -c 'command -v tc >/dev/null' \
    || die "imagem $IMG sem 'tc' (necessario para o mirror)"

# Diretorio de saida criado pelo utilizador (os ficheiros dentro ficam root,
# mas o directorio pertence ao utilizador -> pode ser limpo nas runs seguintes).
mkdir -p "$OUT_ROOT"
if ! rm -rf "$RUN_DIR" 2>/dev/null; then
    die "nao consegui limpar $RUN_DIR (root-owned de uma run anterior?)"
fi
mkdir -p "$HOST_OUT" "$SIDE_OUT"
warn "dataset=$DATASET scale=$SCALE saida=$RUN_DIR"

# --- 1. laboratorio base (sem build, sem sidecar ainda) ----------------------
warn "a subir laboratorio base (--no-build)..."
"${COMPOSE_BASE[@]}" up -d --no-build 2>&1 | tail -3

for c in ecu1 ecu2 ecu3 ecu4 ecu5 ecu6; do
    ok=0
    for _ in $(seq 1 30); do
        if docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -qx true; then
            ok=1; break
        fi
        sleep 1
    done
    [ "$ok" = "1" ] || die "contentor $c nao esta' a correr"
done
sleep 12

# --- 2. resolver as pernas net1 no host --------------------------------------
IF1=$(net1_iface ecu1 192.168.1.2) || true
IF2=$(net1_iface ecu2 192.168.1.1) || true
[ -n "$IF1" ] || die "nao encontrei a interface net1 (192.168.1.2) no ecu1"
[ -n "$IF2" ] || die "nao encontrei a interface net1 (192.168.1.1) no ecu2"
V1=$(veth_of ecu1 "$IF1") || die "veth peer do ecu1/$IF1 nao encontrado"
V2=$(veth_of ecu2 "$IF2") || die "veth peer do ecu2/$IF2 nao encontrado"
V6=$(veth_of ecu6 eth0)    || die "veth peer do ecu6/eth0 nao encontrado"
for V in "$V1" "$V2" "$V6"; do
    ip link show "$V" >/dev/null 2>&1 || die "veth '$V' nao existe no host"
done
ECU2_PID=$(docker inspect -f '{{.State.Pid}}' ecu2)
[ -n "$ECU2_PID" ] && [ "$ECU2_PID" != "0" ] \
    || die "PID do ecu2 indisponivel (nao consigo mover o mirror0)"
warn "veths net1: ecu1=$V1 ecu2=$V2 ecu6=$V6  ecu2_pid=$ECU2_PID"

# --- 3. mirror: tc ingress nos 3 veths -> mirrorh; mirror0 no netns do ecu2 --
warn "a montar o mirror (tc ingress -> mirrorh <-> mirror0)..."
docker exec ecu2 sh -c 'ip link del mirror0 2>/dev/null || true'
hostsh "
  ip link del mirrorh 2>/dev/null || true
  ip link add mirrorh type veth peer name mirrorp
  ip link set mirrorp netns $ECU2_PID
  ip link set mirrorh up
  for V in $V1 $V2 $V6; do
    tc qdisc del dev \$V handle ffff: ingress 2>/dev/null || true
    tc qdisc add dev \$V handle ffff: ingress
    tc filter add dev \$V parent ffff: protocol all u32 match u32 0 0 \
        action mirred egress mirror dev mirrorh
  done
" || die "falha a montar o mirror tc/veth"
docker exec ecu2 sh -c \
    'ip link set mirrorp name mirror0 && ip link set mirror0 up' \
    || die "falha a preparar mirror0 no netns do ecu2"
MIRROR_UP=1
docker exec ecu2 ip -br link show mirror0 >/dev/null \
    || die "mirror0 nao existe no ecu2"
warn "mirror activo: mirrorh (host) <-> mirror0 (ecu2)"

# --- 4. referencia host (ids + pcap) no par do mirror ------------------------
docker rm -f "$HOST_REF" "$PCAP_REF" >/dev/null 2>&1 || true

warn "a arrancar referencia host (ids_live) em mirrorh ..."
docker run -d --name "$HOST_REF" --net=host --cap-add NET_RAW \
    -v "$ROOT/tools:/work/tools:ro" \
    -v "$ROOT/features:/work/features:ro" \
    -v "$ROOT/results/baseline_v3:/work/results/baseline_v3:ro" \
    -v "$HOST_OUT:/work/results/ids_live_ecu2/$DATASET/host" \
    -w /work --entrypoint python3 "$IMG" \
    tools/ids_live.py \
        --interface mirrorh \
        --out-dir "results/ids_live_ecu2/$DATASET/host" \
        --name "$DATASET" \
        --session-max-age 60 \
        --bpf-filter "$BPF" >/dev/null

warn "a arrancar tcpdump de referencia em mirrorh ..."
docker run -d --name "$PCAP_REF" --net=host --cap-add NET_RAW \
    -v "$RUN_DIR:/out" --entrypoint tcpdump "$IMG" \
    -i mirrorh -nn -p -s 0 -U -w /out/mirror_host.pcap "$BPF" >/dev/null

# --- 5. sidecar dentro do ecu2 (escuta o par do mirror) ---------------------
export IDS_IFACE=mirror0
export IDS_RUN_DIR="$DATASET/sidecar"
export IDS_RUN_NAME="$DATASET"
export IDS_SESSION_MAX_AGE=60
warn "a arrancar ids-ecu2 (netns do ecu2, iface mirror0) ..."
"${COMPOSE_IDS[@]}" up -d --no-build --force-recreate --no-deps ids-ecu2 2>&1 | tail -3

# esperar os sniffers (ids_live.py imprime "a escutar em"; tcpdump "listening on").
wait_sniffer() { # $1=nome do contentor  $2=padrao
    for _ in $(seq 1 40); do
        if docker logs "$1" 2>&1 | grep -q "$2"; then
            return 0
        fi
        sleep 0.5
    done
    docker logs "$1" >&2 || true
    return 1
}
wait_sniffer "$HOST_REF" "a escutar em" || die "referencia host nao arrancou o sniffer"
wait_sniffer ids-ecu2  "a escutar em" || die "sidecar ids-ecu2 nao arrancou o sniffer"
wait_sniffer "$PCAP_REF" "listening on" || die "tcpdump de referencia nao arrancou"

# --- 5b. modo persistente: sair e deixar o IDS a correr ---------------------
if [ "${NO_ATTACK:-0}" = "1" ]; then
    LEAVE_RUNNING=1
    write_state
    warn "=============================================================="
    warn "IDS a correr: sidecar em mirror0, referencia host em mirrorh."
    warn "Noutro terminal, lancar o ataque:"
    warn "  SKIP_UP=1 NO_BUILD=1 ./scripts/gen_attack_dataset.sh $DATASET --scale $SCALE"
    warn "Ver o IDS ao vivo:  docker logs -f ids-ecu2"
    warn "Parar e limpar:     DOWN=1 ./scripts/ids_ecu2_validation.sh"
    warn "=============================================================="
    exit 0
fi
warn "sniffers activos; a gerar o ataque ..."

# --- 6. ataque (sem up: o laboratorio ja' esta' levantado) -------------------
# O gen_attack valida o dataset contra um alvo pensado para scale=1; em
# escalas pequenas a duracao minima de 5 s produz mais pacotes que o alvo e a
# validacao sai !=0. Isso NAO invalida a comparacao (o atacante correu e o MAC
# e' verificado no comparador), por isso continuamos e registamos o rc.
set +e
SKIP_UP=1 NO_BUILD=1 ./scripts/gen_attack_dataset.sh "$DATASET" --scale "$SCALE"
GEN_RC=$?
set -e
if [ "$GEN_RC" != "0" ]; then
    warn "gen_attack rc=$GEN_RC (validacao do dataset em escala pequena; continuo)"
fi

# --- 7. parar e comparar -----------------------------------------------------
MAC6=$(docker exec ecu6 cat /sys/class/net/eth0/address | tr -d '\r\n')
[ -n "$MAC6" ] || die "nao consegui ler o MAC do atacante (ecu6)"
warn "MAC do atacante=$MAC6"
stop_ids

[ -s "$RUN_DIR/mirror_host.pcap" ] \
    || warn "AVISO: pcap de referencia vazio/ausente ($RUN_DIR/mirror_host.pcap)"

warn "a comparar host vs sidecar ..."
RC=0
python3 tools/compare_ids_location.py \
    --host-dir "$HOST_OUT" \
    --sidecar-dir "$SIDE_OUT" \
    --name "$DATASET" \
    --attacker-mac "$MAC6" \
    --reference-pcap "$RUN_DIR/mirror_host.pcap" \
    --out-json "$RUN_DIR/compare_${DATASET}.json" || RC=$?

python3 - "$RUN_DIR/metadata.json" "$DATASET" "$SCALE" \
    "$IF1" "$IF2" "$V1" "$V2" "$V6" "$MAC6" "$BPF" <<'PY'
import json, subprocess, sys, datetime
(out, dataset, scale, if1, if2, v1, v2, v6, mac6, bpf) = sys.argv[1:11]
def sh(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except Exception:
        return None
data = {
    "phase": "6-extension-ids-in-ecu2",
    "dataset": dataset,
    "scale": float(scale),
    "ecu1_net1_iface": if1,
    "ecu2_net1_iface": if2,
    "host_veths": {"ecu1": v1, "ecu2": v2, "ecu6": v6},
    "mirror": {"host_end": "mirrorh", "ecu2_end": "mirror0",
               "method": "tc ingress mirred em cada veth net1"},
    "reference_pcap": "mirror_host.pcap",
    "attacker_mac": mac6,
    "bpf_filter": bpf,
    "git_commit": sh("git rev-parse --short HEAD"),
    "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "images": {
        "ecu": sh("docker image inspect automotive-ids/vsomeip:latest --format '{{.Id}}'"),
        "sidecar": sh("docker image inspect automotive-ids/attacker:latest --format '{{.Id}}'"),
    },
}
with open(out, "w") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")
print(f"[ids-ecu2-val] metadata -> {out}")
PY

warn "feito (rc=$RC). Ver $RUN_DIR/compare_${DATASET}.json"
exit "$RC"
