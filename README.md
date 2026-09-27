# someip-ids

Reprodução local, com Docker/compose, do ambiente descrito em
*"SOME/IP Intrusion Detection System Using Real-Time and Retroactive Anomaly
Detection"* (Koyama et al., IEEE VTC2022-Spring): 5 ECUs Linux com
[vsomeip 3.7.6](https://github.com/COVESA/vsomeip) compilado a partir do
repositório oficial, duas sub-redes com roteadores, captura de tráfego com
`tcpdump`, configurações vsomeip em JSON e um smoke test que valida os pcaps
com `scapy`.

## Topologia

```
   ecu1 (192.168.1.2)  cliente SOME/IP
     |
   net1 192.168.1.0/24  (bridge br-<id da rede>)
     |
   ecu2 (192.168.1.1 + 192.168.2.1)  roteador + relay SOME/IP-SD
     |
   net2 192.168.2.0/24  (bridge br-<id da rede>)
     |-- ecu3 (192.168.2.2)  roteador (caminho de volta)
     |-- ecu4 (192.168.2.3)
     +-- ecu5 (192.168.2.4)  servidor SOME/IP
```

As duas redes são duas bridges Docker distintas (dois domínios broadcast), pelo
que o encaminhamento L3 entre elas faz-se, de facto, nos `ecu2`/`ecu3`:

* ida: `ecu1 → ecu2 → ecu5`
* volta: `ecu5 → ecu3 → ecu2 → ecu1` (caminho assimétrico, só UDP)

Sem `smcroute` no `ecu2` o multicast SOME/IP-SD não atravessa as duas redes.

## Uso rápido

```bash
python3 -m pip install --user scapy     # só para a verificação dos pcaps

./scripts/smoke_test.sh                 # sobe, testa, deixa o ambiente de pé
./scripts/smoke_test.sh --down          # termina o ambiente e limpa o host
```

O smoke test:

1. cria `pcaps/`, `logs/`, `.state/`;
2. `docker compose down --remove-orphans` + `up -d --build`;
3. aplica as exceções do `raw` PREROUTING do host (ver secção seguinte);
4. espera pelo `routingmanagerd` em `ecu1` e `ecu5`;
5. arranca `tcpdump` em cada ECU (filtro: `udp and (port 30490 or 30509 or 30510)`);
6. corre `ids_server` em `ecu5` e `ids_client` em `ecu1`;
7. recolhe os logs;
8. valida os pcaps com `tools/verify_pcap.py` (scapy).

Critérios de sucesso: `C1..C5` todos `[PASS]` e `ids_client` com exit code 0.

Saída esperada:

```
  [PASS] C1 existe trafego SOME/IP-SD   (90 pacotes SD)
  [PASS] C2 ecu1 recebeu SOME/IP-SD vindo de 192.168.2.4 (SD roteado via ecu2)
  [PASS] C3 SOME/IP REQUEST  192.168.1.2 -> 192.168.2.4
  [PASS] C4 SOME/IP RESPONSE 192.168.2.4 -> 192.168.1.2
  [PASS] C5 SOME/IP NOTIFICATION do evento 0x8001 do servico 0x1235

SMOKE TEST: SUCESSO
```

## Exceções no `raw` PREROUTING do host (Docker >= 26)

**Isto é uma mudança de comportamento do Docker Engine, não um bug deste
ambiente.** Desde o Docker Engine 26.x (aqui confirmado com **29.6.1**) o
daemon insere, por IP de container, uma regra anti-spoofing no `raw`
`PREROUTING` **do host**:

```
-A PREROUTING -d <IP_DO_CONTAINER>/32 ! -i <BRIDGE_DA_REDE_DESTE_IP> -j DROP
```

Ou seja: só aceita um IP se o frame entrar pela bridge da rede onde esse IP
vive. Neste lab o tráfego entre sub-redes é roteado nos `ecu2`/`ecu3`, pelo que
chega ao IP de destino pela bridge da **outra** rede:

```
ecu1 --[br da net1]--> ecu2 --[br da net2]--> ecu5 (192.168.2.4)
                    ^ o frame ainda está na bridge errada para o Docker
```

A regra `-d 192.168.2.4 ! -i br-da-net2 -j DROP` casa (a bridge de entrada é a
da net1) e o pacote é descartado **antes** do conntrack — por isso não havia
`nf_conntrack` para esses fluxos e o `ping` entre ECUs dava 100% de perda.

### Correção aplicada

`scripts/smoke_test.sh` espelha essas regras como `ACCEPT`, posicionadas
**antes** das regras `DROP`, usando exatamente a mesma expressão (o `-d` e o
`! -i <bridge>` têm de ser idênticos, senão a regra nunca casa):

```bash
iptables -t raw -C PREROUTING -d <IP>/32 ! -i <BRIDGE> -j ACCEPT 2>/dev/null || \
iptables -t raw -I PREROUTING 1 -d <IP>/32 ! -i <BRIDGE> -j ACCEPT
```

`<BRIDGE>` é calculado a partir da **rede onde o IP vive**:

```bash
br-$(docker network inspect <rede> -f '{{.Id}}' | cut -c1-12)
```

Os pares exatos desta topologia (os únicos destinos cruzados entre sub-redes):

| IP destino | rede do IP   | container | bridge           | tráfego              |
|------------|--------------|-----------|------------------|----------------------|
| 192.168.2.4 | `someip-ids_net2` | `ecu5` | `br-<12 chars>` | `ecu1 → ecu2 → ecu5` |
| 192.168.1.2 | `someip-ids_net1` | `ecu1` | `br-<12 chars>` | `ecu5 → ecu3 → ecu2` |

### Ciclo de vida

* As regras vivem no **netns do WSL** (o `dockerd` corre dentro da distro —
  nada é alterado no Windows) enquanto o ambiente existir.
* São aplicadas automaticamente no `up` e **removidas automaticamente no
  `--down`**.
* O estado (IP, bridge, timestamp) fica em `.state/host_raw_exceptions.json`
  e é reescrito de cada vez que o `up` corre.
* Se o script for interrompido de forma anormal, o ambiente fica de pé (e com
  ele as regras — sem elas o lab não funciona). Para as remover à mão:

  ```bash
  ./scripts/smoke_test.sh --host-raw down     # só remove as regras
  ./scripts/smoke_test.sh --host-raw up       # volta a aplicá-las (idempotente)
  ```

  Isto é também o que se deve fazer se o ambiente for terminado com
  `docker compose down` à mão, para não deixar regras órfãs no host.

### Alternativa descartada: `net.bridge.bridge-nf-call-iptables=0`

Desligar o `bridge-nf-call-iptables` no host faria os frames encaminhados
entre portas da bridge ignorarem por completo o netfilter do host, contornando
as regras anti-spoofing. Foi descartado porque:

* é um sysctl **global do host**, não específico deste lab;
* desliga o netfilter para **todo** o tráfego inter-container (todas as regras
  Docker de isolamento, publicação de portas via bridge, etc.), em vez de
  apenas permitir o roteamento entre as duas sub-redes deste teste;
* as duas regras `ACCEPT` por IP são cirúrgicas, reversíveis e ficam
  registadas em `.state/`.

## Estrutura

```
docker-compose.yml          5 ECUs, duas redes, IPs fixos
Dockerfile                  build do vsomeip 3.7.6 + apps C++
config/<ecu>/ids.json       configuração vsomeip de cada ECU
scripts/entrypoint.sh       sysctls, rotas, rota multicast SD, TTL, smcroute
scripts/smoke_test.sh       orquestração + verificação
src/                        ids_client / ids_server (SOME/IP)
tools/verify_pcap.py        validação C1..C5 dos pcaps (scapy, no host)
```

Ver `config/README.md` para os IDs, portas e decisões das configurações
vsomeip.

## Artefactos

| caminho             | conteúdo                                        |
|---------------------|-------------------------------------------------|
| `pcaps/*.pcap`      | captura `tcpdump` por ECU                        |
| `logs/*.log`        | cliente, servidor, `routingmanagerd`, verificação |
| `.state/*.json`     | regras aplicadas ao `raw` PREROUTING do host     |

Todos ignorados pelo git (`.gitignore`).
