#!/bin/sh
# =============================================================================
# scripts/ids_ecu2.sh -- entrypoint do sidecar `ids-ecu2` (Fase 6, extensao)
#
# Corre DENTRO do network namespace do ecu2 (network_mode: service:ecu2).
# Resolve a interface pelo IP (os nomes eth0/eth1 NAO sao estaveis no Docker)
# e arranca o IDS online, que ja' vem montado em /work/tools/ids_live.py.
#
# Variaveis:
#   IDS_IFACE=net1|net2|auto|<iface>  (default: net1)
#   IDS_OUT_DIR=/work/results/...     (default: /work/results/ids_live_ecu2/sidecar)
#   IDS_NAME=<prefixo>                (default: sidecar)
#   IDS_SESSION_MAX_AGE=<s>           (default: 60)
#   IDS_BPF_FILTER=<filtro>           (default: udp)
#
# Nao precisa de NET_ADMIN: o sniffing usa AF_PACKET com a capability NET_RAW,
# que o Docker da' por omissao. O script nao altera rotas nem iptables.
# =============================================================================
set -eu

log() { echo "[ids-ecu2] $*"; }

IFACE_SPEC="${IDS_IFACE:-net1}"
IF=""
case "$IFACE_SPEC" in
    net1)
        IP="192.168.1.1"
        IF=$(ip -o -4 addr show | awk -v ip="$IP" 'index($4, ip "/") == 1 {print $2; exit}')
        ;;
    net2)
        IP="192.168.2.1"
        IF=$(ip -o -4 addr show | awk -v ip="$IP" 'index($4, ip "/") == 1 {print $2; exit}')
        ;;
    auto)
        # Preferir net1 (lado do ecu1/atacante); cair para net2 se nao existir.
        IF=$(ip -o -4 addr show | awk 'index($4, "192.168.1.1/") == 1 {print $2; exit}')
        if [ -z "$IF" ]; then
            IF=$(ip -o -4 addr show | awk 'index($4, "192.168.2.1/") == 1 {print $2; exit}')
        fi
        IP="auto"
        ;;
    *)
        # Nome de interface explicito (ex.: eth0); validar que existe.
        IP="$IFACE_SPEC"
        IF="$IFACE_SPEC"
        if ! ip link show "$IF" >/dev/null 2>&1; then
            log "ERRO: interface explicita '$IF' nao existe neste namespace"
            ip -o -4 addr show >&2 || true
            exit 1
        fi
        ;;
esac

if [ -z "$IF" ]; then
    log "ERRO: nao encontrei a interface para IDS_IFACE='$IFACE_SPEC'"
    ip -o -4 addr show >&2 || true
    exit 1
fi

# Sanidade: o Python/scapy vem da imagem attacker (nao se constroi nada aqui).
if ! python3 -c 'import scapy' >/dev/null 2>&1; then
    log "ERRO: python3/scapy indisponivel na imagem do sidecar"
    exit 1
fi

OUT="${IDS_OUT_DIR:-/work/results/ids_live_ecu2/sidecar}"
NAME="${IDS_NAME:-sidecar}"
MAX_AGE="${IDS_SESSION_MAX_AGE:-60}"
BPF="${IDS_BPF_FILTER:-udp}"

mkdir -p "$OUT"

log "iface=$IF (IDS_IFACE=$IFACE_SPEC) out=$OUT name=$NAME"
log "enderecos visiveis neste namespace:"
ip -o -4 addr show | sed 's/^/[ids-ecu2]   /'

exec python3 /work/tools/ids_live.py \
    --interface "$IF" \
    --out-dir "$OUT" \
    --name "$NAME" \
    --session-max-age "$MAX_AGE" \
    --bpf-filter "$BPF"
