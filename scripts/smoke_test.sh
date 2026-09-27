#!/usr/bin/env bash
# =============================================================================
# smoke_test.sh -- sobe o ambiente someip-ids, gera trafego SOME/IP e valida
#                   que os pacotes SOME/IP e SOME/IP-SD trafegaram (pcap + scapy).
#
#   ./scripts/smoke_test.sh            # sobe, testa, deixa o ambiente de pé
#   ./scripts/smoke_test.sh --down     # idem, mas termina o ambiente no fim
#                                       (remove tambem as excecoes do host)
#   ./scripts/smoke_test.sh --host-raw up|down
#                                       aplica/remove so as excecoes do
#                                       raw PREROUTING do host (limpeza manual
#                                       se o script for interrompido)
#
# Saida: linhas [PASS]/[FAIL] legiveis; exit code 0 = sucesso, 1 = falha.
# Artefactos:
#   pcaps/*.pcap      capturas tcpdump (uma por ECU)
#   logs/*.log        logs do cliente, do servidor, do tcpdump e do verificador
#   .state/*.json     regras aplicadas ao raw PREROUTING do host
#
# NOTA (Docker >= 26, anti-spoofing): o Docker insere no raw PREROUTING do host
#   -A PREROUTING -d <IP>/32 ! -i <bridge_da_rede_do_IP> -j DROP
# de modo a so aceitar cada IP se o frame entrar pela bridge da propria rede.
# Neste lab o trafego entre sub-redes e roteado nos ecu2/ecu3, pelo que chega
# a <IP> pela bridge da OUTRA rede e e descartado. A funcao
# `host_raw_exceptions` espelha essas regras como ACCEPT antes delas.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE=${COMPOSE:-"docker compose"}
CAPTURE_FILTER='udp and (port 30490 or port 30509 or port 30510)'
CAPTURES=("ecu1:eth0" "ecu2:any" "ecu3:eth0" "ecu4:eth0" "ecu5:eth0")
CLIENT_TIMEOUT_S=120      # guarda-chuva do "timeout" no host
CLIENT_WAIT_S=60          # tempo que o ids_client espera pelos dados
SERVER_WARMUP_S=4

if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_OFF=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_OFF=""
fi

step() { printf '\n%s==> %s%s\n' "$C_YEL" "$*" "$C_OFF"; }
info() { printf '    %s\n' "$*"; }
pass() { printf '    %s[PASS]%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
fail() { printf '    %s[FAIL]%s %s\n' "$C_RED" "$C_OFF" "$*"; }
warn() { printf '    %s[AVISO]%s %s\n' "$C_YEL" "$C_OFF" "$*"; }
die()  { fail "$*"; exit 1; }

# -----------------------------------------------------------------------------
# Excecoes no raw PREROUTING do host (Docker >= 26: anti-spoofing por rede)
#
# O Docker Engine insere, por IP de container, no raw PREROUTING do host:
#     -A PREROUTING -d <IP>/32 ! -i <bridge_da_rede_do_IP> -j DROP
# i.e. so aceita o IP se o frame entrar pela bridge da rede onde o IP vive.
# Com duas bridges distintas (net1/net2) o trafego roteado entre sub-redes
# cai nessas regras: chega a <IP> pela bridge "errada" e e descartado.
#
# Correcao: espelhar EXATAMENTE a expressao do Docker (mesmo -d e mesmo
# `! -i <bridge>`, calculado a partir da rede onde o IP vive) mas como ACCEPT,
# posicionada ANTES da regra DROP. Se a expressao nao for identica, a regra
# nunca casa com os pacotes que precisamos de deixar passar.
# -----------------------------------------------------------------------------
STATE_DIR=".state"
STATE_FILE="$STATE_DIR/host_raw_exceptions.json"
IMAGE="${IMAGE:-automotive-ids/vsomeip:latest}"

# (IP de destino, container que vive na rede onde o IP esta -- usado para
#  descobrir o nome da bridge dessa rede).
# Estes sao os dois destinos deste lab que sao alcancados por uma bridge
# diferente da propria rede:
#   192.168.2.4 (ecu5) <- frame entra na bridge de net1  (ecu1 -> ecu2 -> ecu5)
#   192.168.1.2 (ecu1) <- frame entra na bridge de net2  (ecu5 -> ecu3 -> ecu2)
RAW_EXCEPTIONS=(
    "192.168.2.4 ecu5"
    "192.168.1.2 ecu1"
)

# Executa um comando no netns do host (o iptables do host nao e alcancavel a
# partir de um container normal) usando a propria imagem do lab.
host_ipt() {
    docker run --rm --net=host --privileged --entrypoint sh "$IMAGE" -c "$1" 2>/dev/null
}

# br-<12 primeiros chars do id> da rede do container indicado
bridge_of_container() {
    local container="$1" net id
    net=$(docker inspect "$container" \
        -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null) || return 1
    id=$(docker network inspect "$net" -f '{{.Id}}' 2>/dev/null) || return 1
    printf 'br-%.12s' "$id"
}

# Remove TODAS as regras ACCEPT do raw PREROUTING com -d <ip>/32, seja qual
# for o nome da bridge (`-i`). E necessario porque o nome da bridge vem do ID
# da rede: se a rede for recriada, a regra antiga ja nem referencia uma
# interface existente e o `down` (que apaga o estado) deixa-a orfa.
# Devolve o numero de regras removidas.
host_raw_flush_ip() {
    local ip="$1" rule n=0
    while IFS= read -r rule; do
        [ -n "$rule" ] || continue
        rule="${rule/-A PREROUTING/-D PREROUTING}"
        if host_ipt "iptables -t raw $rule" >/dev/null; then
            n=$((n + 1))
        fi
    done < <(host_ipt "iptables -t raw -S PREROUTING" \
                 | grep -F -- "-d $ip/32" | grep -F -- "-j ACCEPT" || true)
    printf '%s' "$n"
}

# host_raw_exceptions up   -> aplica as regras e grava o estado (overwrite)
# host_raw_exceptions down -> remove as regras do estado e apaga o estado
host_raw_exceptions() {
    local mode="${1:-}" entry ip probe br ts line n_res n_res_total
    local n_ok=0 n_dup=0 n_err=0 n_del=0 n_warn=0
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    case "$mode" in
        up)
            mkdir -p "$STATE_DIR"
            local json="" n_res_total=0
            for entry in "${RAW_EXCEPTIONS[@]}"; do
                ip=${entry%% *}
                probe=${entry##* }
                br=$(bridge_of_container "$probe") || {
                    fail "nao foi possivel determinar a bridge da rede do $probe (IP $ip)"
                    return 1
                }
                # Limpa residuos destes mesmos IPs (bridge antiga, regra duplicada,
                # nome de interface que ja nem existe) antes de inserir a actual.
                n_res=$(host_raw_flush_ip "$ip")
                n_res_total=$((n_res_total + n_res))
                if host_ipt "iptables -t raw -C PREROUTING -d $ip/32 ! -i $br -j ACCEPT" >/dev/null; then
                    n_dup=$((n_dup + 1))
                elif host_ipt "iptables -t raw -I PREROUTING 1 -d $ip/32 ! -i $br -j ACCEPT" >/dev/null; then
                    n_ok=$((n_ok + 1))
                else
                    n_err=$((n_err + 1))
                    fail "falhou a inserir '-d $ip/32 ! -i $br -j ACCEPT'"
                fi
                json="${json}${json:+, }{\"ip\":\"$ip\",\"bridge\":\"$br\",\"timestamp\":\"$ts\"}"
            done
            printf '[%s]\n' "$json" > "$STATE_FILE"
            info "raw PREROUTING do host: $n_res_total residua(is) removida(s), $n_ok inserida(s), $n_dup ja existia(m), $n_err erro(s)"
            info "estado em $STATE_FILE"
            [ "$n_err" -eq 0 ]
            ;;
        down)
            n_res_total=0
            if [ -f "$STATE_FILE" ]; then
                while IFS= read -r line; do
                    ip=$(printf '%s' "$line" | sed -n 's/.*"ip":[[:space:]]*"\([^"]*\)".*/\1/p')
                    br=$(printf '%s' "$line" | sed -n 's/.*"bridge":[[:space:]]*"\([^"]*\)".*/\1/p')
                    [ -n "$ip" ] && [ -n "$br" ] || continue
                    if host_ipt "iptables -t raw -D PREROUTING -d $ip/32 ! -i $br -j ACCEPT" >/dev/null; then
                        n_del=$((n_del + 1))
                    else
                        warn "remocao de '-d $ip/32 ! -i $br -j ACCEPT' falhou (regra inexistente ou rede recriada)"
                        n_warn=$((n_warn + 1))
                    fi
                done < <(grep -o '{[^}]*}' "$STATE_FILE" || true)
                rm -f "$STATE_FILE"
                info "raw PREROUTING do host: $n_del removida(s), $n_warn aviso(s)"
            else
                info "sem estado em $STATE_FILE"
            fi
            # Residuos: regras dos mesmos IPs que o estado ja nao conhece -- rede
            # recriada com outro ID de bridge, estado perdido, execucao anterior
            # interrompida. Sem isto ficam orfas para sempre no host.
            n_res_total=0
            for entry in "${RAW_EXCEPTIONS[@]}"; do
                ip=${entry%% *}
                n_res=$(host_raw_flush_ip "$ip")
                n_res_total=$((n_res_total + n_res))
            done
            if [ "$n_res_total" -gt 0 ]; then
                info "raw PREROUTING do host: $n_res_total residua(is) removida(s)"
            fi
            return 0
            ;;
        *)
            fail "modo desconhecido em host_raw_exceptions: '${mode:-}' (use: up | down)"
            return 1
            ;;
    esac
}

stop_captures() {
    for spec in "${CAPTURES[@]}"; do
        c="${spec%%:*}"
        docker exec "$c" sh -c 'pkill -INT tcpdump' >/dev/null 2>&1 || true
    done
}
kill_apps() {
    docker exec ecu1 sh -c 'pkill -TERM -f ids_client'  >/dev/null 2>&1 || true
    docker exec ecu5 sh -c 'pkill -TERM -f ids_server'  >/dev/null 2>&1 || true
}

cleanup() {
    local rc=$?
    stop_captures
    kill_apps
    if [ "$TEARDOWN" = "1" ]; then
        # --down: o ambiente e desfeito, portanto as regras do host tambem.
        # Vale tambem se o script morrer a meio (die/trap) -- nunca ficam orfas.
        # Regras ANTES de derrubar as redes (mesma ordem do passo 2).
        host_raw_exceptions down || true
        $COMPOSE down --remove-orphans >/dev/null 2>&1 || true
    elif [ "$rc" -ne 0 ] && [ -f "$STATE_FILE" ]; then
        # Ambiente ficou de pé (e as regras sao necessarias enquanto ele existir).
        warn "o ambiente ficou de pé com as excecoes do host em $STATE_FILE"
        warn "terminar tudo com ./scripts/smoke_test.sh --down"
        warn "(ou so as regras com ./scripts/smoke_test.sh --host-raw down)"
    fi
}

TEARDOWN=0
case "${1:-}" in
    --down)     TEARDOWN=1 ;;
    --host-raw) host_raw_exceptions "${2:-}"; exit $? ;;
    "")         ;;
    *)          fail "argumento desconhecido: $1 (uso: [--down] [--host-raw up|down])"; exit 1 ;;
esac

trap cleanup EXIT

# -----------------------------------------------------------------------------
step "1/8  Preparar pastas"
mkdir -p pcaps logs .build
rm -f pcaps/*.pcap logs/*.log
info "pcaps/ = capturas tcpdump    logs/ = aplicacoes + verificacao"

# -----------------------------------------------------------------------------
step "2/8  Levantar o ambiente (build da imagem + 5 ECUs)"
# ANTES de derrubar as redes: as regras do raw referem o nome da bridge actual.
# `docker compose down` apaga as redes (e as DROP do Docker) mas NAO as nossas
# ACCEPT; se o `up` seguinte recriar a rede com outro ID de bridge, o state e
# reescrito e as regras antigas ficam orfas para sempre.
host_raw_exceptions down || true
$COMPOSE down --remove-orphans >/dev/null 2>&1 || true
if ! $COMPOSE up -d --build; then
    die "docker compose up falhou"
fi
info "rede net1 192.168.1.0/24 (ecu1, ecu2) | rede net2 192.168.2.0/24 (ecu2, ecu3, ecu4, ecu5)"

# Sem estas excecoes o trafego roteado entre as duas sub-redes e descartado no
# host pelas regras anti-spoofing do Docker (ver cabecalho deste script).
if ! host_raw_exceptions up; then
    die "nao foi possivel preparar o raw PREROUTING do host"
fi

# -----------------------------------------------------------------------------
step "3/8  Aguardar os daemons SOME/IP (routingmanagerd em ecu1/ecu5)"
for c in ecu1 ecu5; do
    ready=0
    for _ in $(seq 1 45); do
        if docker exec "$c" sh -c 'pgrep -x routingmanagerd >/dev/null' 2>/dev/null; then
            ready=1; break
        fi
        sleep 1
    done
    [ "$ready" = "1" ] || die "routingmanagerd nao arrancou em $c (ver: docker compose logs $c)"
    info "$c: routingmanagerd ativo"
done
sleep 2

# -----------------------------------------------------------------------------
step "4/8  Iniciar capturas tcpdump (uma por ECU)"
for spec in "${CAPTURES[@]}"; do
    c="${spec%%:*}"
    i="${spec##*:}"
    docker exec -d "$c" sh -c \
        "exec tcpdump -i '$i' -s 0 -U -w '/pcaps/$c.pcap' '$CAPTURE_FILTER' > '/logs/$c.tcpdump.log' 2>&1"
done
sleep 1
for spec in "${CAPTURES[@]}"; do
    c="${spec%%:*}"
    docker exec "$c" sh -c "pgrep -x tcpdump >/dev/null" 2>/dev/null \
        || die "tcpdump nao arrancou em $c (ver logs/$c.tcpdump.log)"
done
info "filtro: $CAPTURE_FILTER"

# -----------------------------------------------------------------------------
step "5/8  Iniciar o servidor SOME/IP em ecu5 (0x1234 + 0x1235)"
docker exec -d ecu5 sh -c \
    'exec ids_server --cycle 500 > /logs/ecu5.ids_server.log 2>&1'
sleep "$SERVER_WARMUP_S"
if [ ! -s logs/ecu5.ids_server.log ]; then
    die "o servidor nao escreveu nada em logs/ecu5.ids_server.log"
fi
sed 's/^/    | /' logs/ecu5.ids_server.log | head -6

# -----------------------------------------------------------------------------
step "6/8  Executar o cliente em ecu1 (Request/Response + subscripcao de eventos)"
timeout "$CLIENT_TIMEOUT_S" docker exec ecu1 ids_client \
    --cycle 500 --timeout "$CLIENT_WAIT_S" 2>&1 | tee logs/ecu1.ids_client.log
client_rc=${PIPESTATUS[0]}
kill_apps
if [ "$client_rc" -eq 0 ]; then
    pass "ids_client terminou com exit code 0 (respostas + notificacoes recebidas)"
else
    fail "ids_client terminou com exit code $client_rc"
    info "ultimas linhas do log do servidor:"
    sed 's/^/    | /' logs/ecu5.ids_server.log | tail -8 || true
fi

# -----------------------------------------------------------------------------
step "7/8  Parar capturas e recolher logs"
sleep 1
stop_captures
sleep 2
for c in ecu1 ecu2 ecu5; do
    $COMPOSE logs --no-color "$c" > "logs/$c.routingmanagerd.log" 2>&1 || true
done
$COMPOSE logs --no-color ecu3 > "logs/ecu3.entrypoint.log" 2>&1 || true
$COMPOSE logs --no-color ecu4 > "logs/ecu4.entrypoint.log" 2>&1 || true
$COMPOSE logs --no-color ecu2 > "logs/ecu2.entrypoint.log" 2>&1 || true

info "pcaps gerados:"
ls -l pcaps/*.pcap 2>/dev/null | sed 's/^/    /' || fail "nenhum pcap gerado"

# -----------------------------------------------------------------------------
step "8/8  Validar os pcaps com scapy"
if ! python3 -c 'import scapy' >/dev/null 2>&1; then
    fail "scapy nao esta instalado no host:  python3 -m pip install --user scapy"
    verify_rc=2
else
    python3 tools/verify_pcap.py 'pcaps/*.pcap' 2>&1 | tee logs/verify_pcap.log
    verify_rc=${PIPESTATUS[0]}
fi

# -----------------------------------------------------------------------------
printf '\n'
overall=0
if [ "$client_rc" -eq 0 ]; then
    pass "cliente SOME/IP (ecu1 -> ecu5)"
else
    fail "cliente SOME/IP (ecu1 -> ecu5) -- exit code $client_rc"; overall=1
fi
if [ "$verify_rc" -eq 0 ]; then
    pass "verificacao dos pcaps (scapy)"
else
    fail "verificacao dos pcaps (scapy) -- exit code $verify_rc"; overall=1
fi

if [ "$overall" -eq 0 ]; then
    printf '\n%sSMOKE TEST: SUCESSO%s\n' "$C_GRN" "$C_OFF"
else
    printf '\n%sSMOKE TEST: FALHA%s  (logs em ./logs, pcaps em ./pcaps)\n' "$C_RED" "$C_OFF"
fi

if [ "$TEARDOWN" = "1" ]; then
    info "a terminar o ambiente (--down)"
    trap - EXIT
    stop_captures; kill_apps
    host_raw_exceptions down
    $COMPOSE down --remove-orphans
else
    info "ambiente de pé: ver logs com  docker compose logs -f ecu1"
    info "terminar com:    ./scripts/smoke_test.sh --down"
    info "as excecoes do raw PREROUTING do host so saem no --down; se o ambiente"
    info "for terminado a mao, correr: ./scripts/smoke_test.sh --host-raw down"
fi

exit "$overall"
