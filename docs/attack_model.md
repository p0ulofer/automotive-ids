# Modelo de ataque — Fase 3 (datasets de anomalia)

> Documento complementar a [`attack_datasets.md`](attack_datasets.md) (tabela aprovada dos 25 sets).
> Este ficheiro descreve **como** os datasets de ataque são materializados: regra de etiquetagem,
> arquitetura do atacante, premissas do pipeline e bugs corrigidos durante a calibração.

---

## 1. Arquitetura do atacante

```
        net1 (192.168.1.0/24)                net2 (192.168.2.0/24)
ecu1 (client) ─── ecu2 (router/relay) ─── ecu3 ─── ecu5 (server)
     192.168.1.2   192.168.1.1 / 2.1          192.168.2.2   192.168.2.4
                 \
                  \── ecu6 (atacante, MITM) 192.168.1.50   [só net1]
```

- **ecu6**: container dedicado (`docker-compose.attacker.yml`, imagem com scapy), toolkit em
  `tools/attacker/attacker.py`, config `config/attacker/ids_attacker.json`.
- **MITM**: ARP spoofing dos pares `ecu1↔ecu2` na net1 (`--poison 192.168.1.2:192.168.1.1
  --poison 192.168.1.1:192.168.1.2`); o atacante encaminha, termina, injeta ou altera
  payloads conforme a variante (`--terminate-requests`, `--inject-requests`,
  `--tamper-notify`, `--fab-style`, …).
- **Observadores**: captura simultânea em 6 pontos — `ecu1_eth0`, `ecu2_eth0`, `ecu2_eth1`,
  `ecu3_eth0`, `ecu4_eth0`, `ecu5_eth0` — depois merge/`dedup` em `datasets/attack/<id>.pcap`.
- ecu4 permanece **observador** (não é reutilizado como atacante).

## 2. Regra de etiquetagem (label)

**`label = 1` ⟺ o frame foi emitido pelo próprio atacante (`Ether.src == MAC do atacante`).**

- Implementação: `pcap_to_csv.py --attacker-mac <MAC>` atribui `label=1` por src MAC e escreve
  a coluna `src_mac`; `label=0` para todo o resto.
- **Relay transparente**: o ecu2 reencaminha mantendo o `src MAC` original → `label=0`.
  Um ataque que só reescreve ARP mas reencaminha o payload original **não** conta como anomalia.
- **Enquadramento por variante** (o que produz frames com src MAC do atacante):
  - *ARR-Req-a1* (MITM request): pedidos **terminados** (só re-emitidos pelo atacante) +
    pedidos **injetados** + responses **fabricadas**.
  - *ARR-Res (a)*: responses fabricadas pelo atacante.
  - *ANEpc/ANEc (a)*: notificações **tamperadas** re-emitidas pelo atacante (as originais
    não são reencaminhadas para o cliente — o cliente vê só a cópia alterada).
  - Variantes (b)/(c): todos os frames do endpoint falso são do atacante (fora de escopo nesta etapa).
- Exclusão: as cópias *originais* (label=0) de eventos que chegaram ao cliente apenas na versão
  tamperada são removidas do dataset (§4.3) — o cliente nunca as viu.

## 3. Premissas do pipeline (verificadas a cada run)

1. **FDB estático na net1** — o `gen_attack_dataset.sh` instala entradas estáticas
   (MAC ecu1/ecu2 ↔ portos) e desliga *learning* no bridge da net1. Sem isto, o tráfego do
   atacante seria aprendido/floodado em portos errados e a captura no ecu1 poluiria-se com
   frames endereçados ao atacante. Verificação pós-setup incluída no script (`die` se falhar).
2. **`learning off` no porto do atacante** — os frames T (src=MAC atacante) chegariam ao porto
   do ecu1 e o bridge aprenderia `atacante → porta do ecu1`, roubando a entrega dos originais.
3. **Primagem ARP determinística** — `ip neigh replace <ip> lladdr <MAC6> dev <iface> nud
   permanent` em ecu1 (`192.168.1.1→MAC6`) e ecu2 (`192.168.1.2→MAC6`), com *wait-loop* de
   verificação (timeout 5s, `die` se falhar). O ARP *unsolicited* não cria entradas
   (`arp_accept=0`) e há corrida real-vs-atacante — a primagem elimina as duas.
4. **Dedup lógica no merge** (`merge_captures.py --attacker-mac`) — ver §4.3.
5. **Regra raw `2 7`** — com ecu6 up, o PREROUTING tem a regra anti-spoof extra (5 DROP em vez
   de 4). `expected_raw()` no script devolve `2 7` (ecu6 up) ou `2 6` (down) para a regressão.
6. **Teardown explícito**: `ip neigh del` (o `ip neigh flush all` **não** remove entradas
   `permanent`), remoção dos FDB estáticos, *learning on* — sem isto o run seguinte arranca com
   blackhole/FDB errado.
7. `datasets/normal/*` nunca são tocados; o PDF do artigo fica fora do git.

## 4. Bugs encontrados e corrigidos nesta sessão

### 4.1 Envenenamento ARP / timing
- `scapy.srp(timeout=2)` atrasava a entrada em MITM ~4s → o primeiro segundo de tráfego escapava
  (sem ataque → anomalias abaixo do alvo). **Fix**: timeout 0.5s + primagem `permanent` (§3.3).
- `ip neigh flush all` não limpa `permanent` → estado do run seguinte ficava com blackhole.
  **Fix**: `ip neigh del` direto no teardown.

### 4.2 Atribuição de interfaces instável
- A ordem `eth0/eth1 ↔ net1/net2` no ecu2 **alterna a cada recriação do container** — qualquer
  lógica "eth0 = net1" quebra em silêncio. **Fix**: identificar a iface da net1 pelo IP
  (`ip -o addr | grep 'inet 192.168.1.1/'`); FDB/verificações usam o lado da net1.

### 4.3 Dupla-contagem origem ↔ cópia (merge)
- Um mesmo evento SOME/IP é capturado em até 5 pontos; a cópia re-emitida pelo atacante tem
  **IP-ID/payload diferentes** da original → a chave exata `(5-tuple, ip-id, hash)` não as liga
  → contagens infladas (+305 no NEpc, +754 no NEc) e razões erradas.
  **Fix**: chave lógica SOME/IP `(5-tuple, svc, mtd, client, session, mtype)` — o label0 cuja
  chave lógica já existe em label1 é descartado (é a original que o cliente nunca viu).
  SD (`svc=0xFFFF`) fica fora da dedup lógica (todas as mensagens SD colidiriam).

### 4.4 **Race label0/label1 (subestimava anomalias do ARR)**
- O mesmo pacote do atacante aparece em **dois estados**: na net1 com `src MAC = atacante`
  (label=1) e, **depois de roteado pelo ecu2**, com `src MAC` reescrito para o do ecu2
  (label=0). A chave exata de ambos é idêntica (roteamento não altera IP-ID/payload).
- Qual dos dois é *primeiro* nos ficheiros de captura depende da ordem `ecu2_eth0/eth1`, que
  depende da atribuição instável do §4.2 — **não há garantia de ordem**.
- **Efeito medido** (ARR-Req-a1): as 46 injecções foram gravadas como label0 → anomalia 46
  em vez de 92 (−40%), razão 14.1% vs alvo 23.5% → FALHA no gate de ±10%.
- **Fix**: em conflito de chave exata, a vista **label1 substitui a label0** guardada
  (`merge_captures.py`, contagem `observacoes label0 substituidas pela copia label1`),
  independentemente da ordem dos ficheiros. Verificado: após o fix, anomalia 76 vs alvo 77.

### 4.5 Calibração vs. paper
- Taxas reais ≠ estimativas (198 pkt/s medidos vs 240/s estimados no NEc) → calibrar por um
  run curto e medir, não por conta teórica.
- Seed fixo não dá determinismo total: o RNG do atacante é partilhado e o número de draws
  depende da ordem de chegada de pacotes (`terminate=46` vs μ=38, +1.6σ) → ajuste de `t`
  (0.30→0.25) em vez de assumir re-run idêntico.
- `--stats-file` tem de ser path **do container** (`/logs/...`), não path de host.

### 4.6 Pendente (documentado, não corrigido)
- Wrap de Session-ID (`0xFFFF`→`0x0001`) gera `missing=1` fantasma no validador
  (`docs/relatorio_fase2.md` §8.2). Na Fase 3 as métricas de validação de ataque separam por
  label, pelo que o fantasma não contamina os gates de ±10%.

## 5. Validação (modo ataque)

`validate_dataset.py --attack --attacker-mac <MAC> --dataset <id> --scale <s> --update-manifest`:

- **Gates por set (±10% relativo)**: razão anomalia/total, contagem de anomalia, total de
  pacotes face aos alvos da Tabela III (interpretação (A)).
- **Integridade**: `truncated=0`, `duplicate=0` obrigatórios; continuidade de Session-ID
  informativa.
- Saída: `datasets/attack/MANIFEST.json` com campos `attack`, `attacker_mac`,
  `anomaly_packets`, `normal_packets`, `anomaly_ratio`, `target_*`, `diff_pct`,
  `in_tolerance_10pct`.
- O `gen_attack_dataset.sh` executa a validação no fim de cada geração e falha o run se um
  gate falhar (calibração iterada até os 3 critérios passarem).
