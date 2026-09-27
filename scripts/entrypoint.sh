#!/usr/bin/env bash
# =============================================================================
# entrypoint.sh -- arranque de cada ECU do laboratorio someip-ids
#
# Faz, nesta ordem:
#   1. tuning de rede (ip_forward + rp_filter desligado para o ambiente de lab);
#   2. rotas estaticas que constroem o caminho ecu1 <-> ecu5 atraves dos
#      roteadores ecu2 (ida) e ecu3 (volta);
#   3. no ecu2 (roteador entre 192.168.1.0/24 e 192.168.2.0/24):
#        - reescreve o TTL dos pacotes SOME/IP-SD multicast (que saem com
#          TTL=1, valor por omissao de multicast no Linux) para que o proprio
#          ec2 possa encaminha-los sem descarta-los;
#        - inicia o smcroute, que encaminha o grupo 224.224.224.245 entre as
#          duas interfaces (roteamento de multicast SOME/IP-SD);
#   4. inicia o daemon vsomeip (routingmanagerd) quando START_VSOMEIPD=1
#      (ecu1 e ecu5);
#   5. mantem o container vivo.
#
# Variaveis de ambiente definidas no docker-compose.yml:
#   ECU               ecu1..ecu5
#   START_VSOMEIPD    "1" nas ECUs que correm o stack SOME/IP
# =============================================================================
set -uo pipefail

ECU="${ECU:-unknown}"
SD_GROUP="${SD_GROUP:-224.224.224.245}"

log() { echo "[entrypoint:${ECU}] $*"; }

# -----------------------------------------------------------------------------
# 1. sysctls
# -----------------------------------------------------------------------------
sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || log "aviso: nao foi possivel definir ip_forward"
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    [ -w "$f" ] && printf '0\n' > "$f" 2>/dev/null
done
log "ip_forward=$(cat /proc/sys/net/ipv4.ip_forward 2>/dev/null || echo '?')"

# -----------------------------------------------------------------------------
# 2. rotas estaticas (caminho ecu1 <-> ecu5)
#
#    ecu1 --net1-- ecu2 --net2-- ecu3 --net2-- ecu4/ecu5
#
#    ida  (ecu1 -> ecu5): via ecu2 (unico vizinho de ecu1 em 192.168.1.0/24)
#    volta (ecu5 -> ecu1): via ecu3, que encaminha para ecu2 -- assim o ecu3
#                          exerce de facto a funcao de roteador descrita no
#                          artigo (topologia assimetrica; so UDP e usado, por
#                          isso a assimetria nao afeta a comunicacao).
# -----------------------------------------------------------------------------
case "$ECU" in
    ecu1)
        ip route replace 192.168.2.0/24 via 192.168.1.1 2>/dev/null \
            || log "aviso: falhou a rota 192.168.2.0/24 via 192.168.1.1"
        ;;
    ecu3)
        ip route replace 192.168.1.0/24 via 192.168.2.1 2>/dev/null \
            || log "aviso: falhou a rota 192.168.1.0/24 via 192.168.2.1"
        ;;
    ecu4|ecu5)
        ip route replace 192.168.1.0/24 via 192.168.2.2 2>/dev/null \
            || log "aviso: falhou a rota 192.168.1.0/24 via 192.168.2.2"
        ;;
esac

children=()

# -----------------------------------------------------------------------------
# 3. ecu2 -- roteador entre as duas sub-redes
# -----------------------------------------------------------------------------
if [ "$ECU" = "ecu2" ]; then
    # 3a. TTL do SOME/IP-SD. O vsomeip envia SD multicast com TTL=1 (default do
    #     Linux para multicast) e o encaminhamento decrementa o TTL para 0,
    #     descartando o pacote. Reescrevemos para 4 na PREROUTING, antes da
    #     decrementacao -> o pacote segue com TTL=3 (1 salto ate ao destino).
    if iptables-legacy -t mangle -C PREROUTING -d "$SD_GROUP" -j TTL --ttl-set 4 >/dev/null 2>&1; then
        log "regra TTL ja presente"
    elif iptables-legacy -t mangle -A PREROUTING -d "$SD_GROUP" -j TTL --ttl-set 4 >/dev/null 2>&1; then
        log "regra TTL SOME/IP-SD aplicada (mangle/PREROUTING -> 4)"
    else
        log "ERRO: nao foi possivel aplicar a regra TTL para $SD_GROUP"
    fi

    # 3b. Nomes de interface nao sao previsiveis (o docker nao garante a ordem
    #     de ligacao das redes), por isso sao detetados pelo endereco IP.
    IF_1=$(ip -o -4 addr show | awk '$4 ~ /^192\.168\.1\.1\// {print $2; exit}')
    IF_2=$(ip -o -4 addr show | awk '$4 ~ /^192\.168\.2\.1\// {print $2; exit}')

    if [ -z "${IF_1:-}" ] || [ -z "${IF_2:-}" ]; then
        log "ERRO: nao foi possivel identificar as interfaces (1='$IF_1' 2='$IF_2')"
    else
        log "interface 192.168.1.1=${IF_1}  192.168.2.1=${IF_2}"
        {
            echo "# Gerado por entrypoint.sh -- NAO EDITAR (roda no ecu2)"
            echo "phyint ${IF_1} enable"
            echo "phyint ${IF_2} enable"
            # SOME/IP-SD de todos os ECUs possiveis, nas duas direcoes.
            for host in 192.168.1.1 192.168.1.2; do
                echo "mroute from ${IF_1} group ${SD_GROUP} source ${host} to ${IF_2}"
            done
            for host in 192.168.2.1 192.168.2.2 192.168.2.3 192.168.2.4; do
                echo "mroute from ${IF_2} group ${SD_GROUP} source ${host} to ${IF_1}"
            done
        } > /run/smcroute.conf
        sed "s/^/[entrypoint:ecu2]   /" /run/smcroute.conf

        # valida a sintaxe antes de arrancar (fica registado no log)
        if smcrouted -F /run/smcroute.conf -l info >/proc/1/fd/1 2>&1; then
            log "configuracao smcroute valida"
        else
            log "ERRO: configuracao smcroute invalida"
        fi

        # -n = primeiro plano; o PID fica em background dentro deste shell
        smcrouted -n -l info -f /run/smcroute.conf &
        children+=($!)
        log "smcrouted iniciado (pid $!)"
    fi
fi

# -----------------------------------------------------------------------------
# 3c. ECUs que correm o vsomeip: rota explicita para o grupo SOME/IP-SD
#
#     O connector netlink do vsomeip so põe o encaminhamento externo de SD
#     "ready" (is_external_routing_ready -> sd_route_set_) quando encontra, na
#     tabela principal de rotas, uma rota para o grupo multicast multicast com
#     saida pela interface que detem o endereco unicast da ECU. A tabela de um
#     container nao tem nenhuma (ha apenas a rota default e a do proprio
#     prefixo, e a rota default nao traz o atributo RTA_DST), pelo que o SD
#     ficaria eternamente "not ready" e nunca enviaria trafego algum. A rota
#     /32 explicita resolve isto e e validada logo de seguida.
# -----------------------------------------------------------------------------
if [ "${START_VSOMEIPD:-0}" = "1" ]; then
    SD_IF=$(ip -o route get "$SD_GROUP" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
    if [ -n "${SD_IF:-}" ] && ip route replace "${SD_GROUP}/32" dev "$SD_IF" 2>/dev/null; then
        log "rota SOME/IP-SD ${SD_GROUP}/32 dev ${SD_IF} instalada"
    else
        log "ERRO: nao foi possivel instalar a rota ${SD_GROUP}/32"
    fi
fi

# -----------------------------------------------------------------------------
# 4. daemon SOME/IP (vsomeipd / routingmanagerd)
# -----------------------------------------------------------------------------
if [ "${START_VSOMEIPD:-0}" = "1" ]; then
    log "a iniciar routingmanagerd com ${VSOMEIP_CONFIGURATION:-<config default>}"
    routingmanagerd &
    children+=($!)
fi

# -----------------------------------------------------------------------------
# 5. mantem o container vivo; termina se algum daemon morrer.
# -----------------------------------------------------------------------------
trap 'log "a encerrar"; [ ${#children[@]} -gt 0 ] && kill "${children[@]}" 2>/dev/null; exit 0' TERM INT

log "rotas:"
ip route show | sed 's/^/[entrypoint:'"$ECU"']   /'

while :; do
    # rouba os filhos terminados (evita zombies)
    for pid in ${children[@]+"${children[@]}"}; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null
            log "AVISO: o processo $pid terminou"
        fi
    done
    sleep 5 &
    wait $! 2>/dev/null
done
