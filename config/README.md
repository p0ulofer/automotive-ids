# config/ — configurações vsomeip

Ficheiros `ids.json` (vsomeip 3.7.6) por ECU:

* `config/ecu1/ids.json` — cliente (`ids-client`, `0x1001`)
* `config/ecu5/ids.json` — servidor (`ids-server`, `0x1002`)

As ECUs de rede (`ecu2`, `ecu3`, `ecu4`) não têm ficheiro: correm apenas o
`entrypoint.sh` (roteamento + `smcroute`) e nunca arrancam `routingmanagerd`.

## IDs e portas (fixos/fictícios)

| item                        | valor       | onde                     |
|-----------------------------|-------------|--------------------------|
| aplicação routing           | `0x1000`    | todas as ECUs            |
| aplicação cliente           | `0x1001`    | `ecu1`                   |
| aplicação servidor          | `0x1002`    | `ecu5`                   |
| serviço A (Request/Response)| `0x1234`    | `ecu5`                   |
| instância                   | `0x0001`    | `ecu5`                   |
| método                      | `0x0001`    | `ecu5` (porta **30509**) |
| serviço B (Notification)    | `0x1235`    | `ecu5`                   |
| evento                      | `0x8001`    | `ecu5` (porta **30510**) |
| eventgroup                  | `0x0001`    | `ecu5` (`is_field: false`) |
| SOME/IP-SD                  | porta **30490**, UDP, multicast `224.224.224.245` | todas |

`ecu1` não tem secção `services`: o cliente descobre o serviço por SD
(`OFFER` → `SUBSCRIBE/STOP`), que é precisamente o que o artigo observa.

## Decisões

### `"netmask": "255.255.0.0"` em `ecu1` e `ecu5`

Não é a máscara real das redes (as duas são `/24`). O `netmask` da configuração
vsomeip **só** é usado em `udp_server_endpoint_impl::on_multicast_received()`
(`is_same_subnet_unlocked()`) e em `service_discovery_impl::check_ipv4_address()`
— um filtro de "mesma sub-rede" contra o endereço *de origem* do pacote SD.

Com `255.255.255.0`, um `OFFER` multicast de `192.168.2.4` recebido em `ecu1`
(`192.168.1.2`) era descartado silenciosamente nos dois lados. Com `/16` o
filtro passa e o SD estabelece-se; o encaminhamento não é afetado.

> Isto é uma decisão de configuração, não uma tentativa de "esconder" o facto
> de as ECUs estarem em sub-redes diferentes — a rota é que faz o trabalho.

### Rota `224.224.224.245/32 dev <eth>` (secção 3c do entrypoint)

O vsomeip só arranca o SD externo se `is_external_routing_ready()` devolver
`true`, o que exige `if_state_running_ && sd_route_set_`. `sd_route_set_` só
fica `true` quando o `netlink_connector` encontra na tabela principal uma rota
para o grupo multicast com `RTA_DST` **e** `RTA_OIF` = interface do unicast.
Uma rota `default` não traz `RTA_DST`, por isso nunca casava e o log ficava
em `netlink: from 2 to 3, ..., mc=0`.

A entrada `ip route replace 224.224.224.245/32 dev <eth>` resolve isso
(`mc=1` + `"SOME/IP routing ready."`).

### TTL do SD reescrito para 4 (regra `mangle/PREROUTING` no `ecu2`)

O vsomeip não seta `IP_MULTICAST_TTL` (fica a 1 por omissão), pelo que o
multicast SD não sai da sub-rede. A regra
`iptables -t mangle -PREROUTING -d 224.224.224.245 -j TTL --ttl-set 4`
(`iptables-legacy`, corre dentro do container) garante que sobra TTL após o
salto de relay. Nota: `nft meta ttl` não existe — é preciso a regra `TTL` do
`iptables-legacy`.

### Relay multicast: `smcrouted`

O binário chama-se **`smcrouted`** (em Ubuntu 24.04 `smcroute` é só um wrapper
de compatibilidade). Corre em `ecu2` com configuração dinâmica gerada pelo
`entrypoint.sh`, validada antes de arrancar (`smcrouted -F <conf>`).

### Fallback se o SD falhar

```json
"service-discovery": { "enable": "false" }
```

mais entradas `unicast` remoto nas secções `services` do cliente (endpoints
estáticos), apontando a `192.168.2.4`. Serve só como rede de segurança para
depanhar; dispensa a parte do artigo que é sobre SD.

## Exceções no `raw` PREROUTING do host

Ver a secção homónima em [`../README.md`](../README.md). Resumo: o Docker
Engine (>= 26, confirmado com 29.6.1) bloqueia no host pacotes que chegam a um
IP de container pela bridge da rede errada — o que mata exatamente o tráfego
roteado entre estas duas sub-redes. O `scripts/smoke_test.sh` aplica/remove as
regras `ACCEPT` correspondentes (`host_raw_exceptions up|down`), guarda o
estado em `.state/host_raw_exceptions.json` e limpa tudo no `--down`.

**Não** é um bug deste ambiente: é comportamento anti-spoofing do Engine. A
alternativa `net.bridge.bridge-nf-call-iptables=0` foi descartada por desligar
o netfilter do host para todo o tráfego inter-container, em vez de apenas para
estas duas sub-redes.
