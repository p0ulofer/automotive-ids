# Comandos úteis — referência operacional

Este documento reúne **todos os comandos usados no projeto**, agrupados por
fase/ferramenta, com a explicação de cada campo e da finalidade de cada
comando. Serve como *cheat sheet*; a fundamentação metodológica está nos
relatórios indicados em [Referências](#referências).

> **Convenções**
> - Todos os comandos assumem que estás na **raiz do repositório**
>   (`automotive-ids/`), salvo indicação contrária.
> - `$` não faz parte do comando.
> - Os caminhos `datasets/`, `features/` e `results/` são relativos à raiz.
> - `docker compose` usa sempre a mesma pilha de ficheiros; quando a lista
>   importa, ela aparece completa.
> - `--scale < 1` **nunca** toca nos datasets canónicos nem nos `MANIFEST.json`;
>   `--scale 1.0` **sobrescreve** os artefactos completos. Ver
>   [Aviso sobre escalas](#aviso-sobre-escalas).

---

## Índice

1. [Ciclo de vida do laboratório](#1-ciclo-de-vida-do-laboratório)
2. [Datasets normais](#2-datasets-normais)
3. [Datasets de ataque](#3-datasets-de-ataque)
4. [Features de transição](#4-features-de-transição)
5. [IDS offline (Fase 5)](#5-ids-offline-fase-5)
6. [IDS online / live (Fase 6)](#6-ids-online--live-fase-6)
7. [IDS embarcado no ecu2 (sidecar)](#7-ids-embarcado-no-ecu2-sidecar)
8. [Comparadores e controlo de qualidade](#8-comparadores-e-controlo-de-qualidade)
9. [Debug de Docker e rede](#9-debug-de-docker-e-rede)
10. [Troubleshooting](#10-troubleshooting)
11. [Variáveis de ambiente, estado e caminhos](#11-variáveis-de-ambiente-estado-e-caminhos)
12. [Referências](#referências)

---

## Aviso sobre escalas

`gen_dataset.sh` e `gen_attack_dataset.sh` comportam-se de forma diferente
consoante `--scale`:

| `--scale` | nome do artefacto | `MANIFEST.json` | uso |
|---|---|---|---|
| `1` / `1.0` (default) | `datasets/{normal,attack}/<id>.pcap` e `.csv` | **atualizado** (`--update-manifest`) | geração canónica, Fases 4/5 |
| `< 1` (ex.: `0.05`, `0.10`) | `datasets/{normal,attack}/<id>_scale<N>.pcap` e `.csv` | **não é tocado** | iterações rápidas, demos, validação do IDS |

> **Atenção:** `tools/extract_features.py` faz *glob* de
> `datasets/{normal,attack}/*.csv`, pelo que **também apanha** os ficheiros
> `*_scale*`. Antes de correr a Fase 4 usa `--only` ou remove esses ficheiros:
>
> ```bash
> find datasets -maxdepth 2 -name '*_scale*' -print -delete
> ```
>
> Os datasets completos são protegidos por `datasets/CHECKSUMS.sha256`; usa
> `tools/check_checksums.sh` para confirmar que não foram alterados.

---

## 1. Ciclo de vida do laboratório

### 1.1 Smoke test (Fase 1)

```bash
./scripts/smoke_test.sh
```

Sobe o laboratório (build incluído), gera tráfego SOME/IP/SD e valida as
condições **C1–C5** lendo os pcaps com scapy. Deixa o ambiente **de pé**.

```bash
./scripts/smoke_test.sh --down
```

**Só derruba** o ambiente: para capturas e aplicações, remove as exceções do
`raw PREROUTING` do host e corre `docker compose down --remove-orphans`.
Não faz build, não sobe nada, não testa. É idempotente (exit 0 mesmo já em
baixo).

```bash
./scripts/smoke_test.sh --host-raw up
./scripts/smoke_test.sh --host-raw down
```

Aplica/remove **apenas** as regras `ACCEPT` no `raw PREROUTING` do host
(Docker ≥ 26 anti-spoofing). `up` deve ser corrido depois de subir as ECUs;
`down` **antes** de `docker compose down`, porque as regras referenciam os
nomes das bridges.

| campo | para que serve |
|---|---|
| `--down` | teardown completo e limpeza do host |
| `--host-raw up\|down` | gere só as exceções de iptables do host |
| `COMPOSE` (env) | comando compose alternativo (default `docker compose`) |
| `IMAGE` (env) | imagem usada nos contentores privilegiados de host (default `automotive-ids/vsomeip:latest`) |

### 1.2 Subir/derrubar manualmente a pilha

```bash
# subir tudo (lab + datasets + atacante + sidecar do IDS)
docker compose \
  -f docker-compose.yml \
  -f docker-compose.datasets.yml \
  -f docker-compose.attacker.yml \
  -f docker-compose.ids.yml \
  up -d --no-build

# só parar (mantém contentores e redes)
docker compose \
  -f docker-compose.yml -f docker-compose.datasets.yml \
  -f docker-compose.attacker.yml -f docker-compose.ids.yml \
  stop

# parar e remover contentores + redes
docker compose \
  -f docker-compose.yml -f docker-compose.datasets.yml \
  -f docker-compose.attacker.yml -f docker-compose.ids.yml \
  down --remove-orphans
```

| ficheiro compose | o que acrescenta |
|---|---|
| `docker-compose.yml` | topologia base: `ecu1`–`ecu5`, redes `net1`/`net2` |
| `docker-compose.datasets.yml` | troca a config vsomeip de `ecu1`/`ecu5` para os 3 serviços de dataset (`0x1234/0x1235/0x1236`) |
| `docker-compose.attacker.yml` | `ecu6` atacante (`192.168.1.50`, `NET_ADMIN`, imagem `automotive-ids/attacker:latest`) |
| `docker-compose.ids.yml` | sidecar `ids-ecu2` (`network_mode: service:ecu2`) |

> Não uses `down -v` nem `--rmi`: apagaria volumes e imagens necessárias.

### 1.3 Ordem correta de teardown

```bash
# 1) se deixaste o IDS a correr com NO_ATTACK=1
DOWN=1 ./scripts/ids_ecu2_validation.sh

# 2) teardown canónico (remove também ecu6 e ids-ecu2)
./scripts/smoke_test.sh --down
```

O passo 1 pode ser omitido se nunca usaste `NO_ATTACK=1` (as execuções normais
limpam o *mirror* no fim).

---

## 2. Datasets normais

```bash
./scripts/gen_dataset.sh normal_rr
./scripts/gen_dataset.sh normal_nepc
./scripts/gen_dataset.sh normal_nec

# iteração rápida (5 % do volume; não toca nos canónicos)
./scripts/gen_dataset.sh normal_rr --scale 0.05
```

O script orquestra: regressão das regras `raw` → `compose up` (com build) →
capturas `tcpdump` **por interface** → apps `ids_dataset_server` (ecu5) e
`ids_dataset_client` (ecu1) → paragem → merge + dedup → validação → `MANIFEST`.

| campo | para que serve |
|---|---|
| `normal_rr` | Request/Response do serviço `0x1234` (~6 455 pacotes full) |
| `normal_nepc` | notificações periódicas/on-change do serviço `0x1235` (~255 128) |
| `normal_nec` | notificações on-change do serviço `0x1236` (~1 722 011) |
| `--scale F` | fração da duração total (`0.05` = 5 %); grava `<id>_scaleF.{pcap,csv}` e não atualiza o manifest |

### 2.1 Campos dos YAML normais

Ficheiros: `config/datasets/normal_{rr,nepc,nec}.yaml`.

| campo | significado |
|---|---|
| `dataset` | nome lógico (tem de coincidir com o argumento do script) |
| `service_id` | Service ID SOME/IP do dataset (`0x1234`/`0x1235`/`0x1236`) |
| `instance_id` | Instance ID |
| `request_method` / `response_method` | Method IDs usados nos pedidos/respostas |
| `event_id` / `eventgroup_id` | evento e eventgroup subscritos via SD |
| `request_cycle_ms` | período dos requests (ms) |
| `notify_cycle_ms` | período das notificações (ms), quando aplicável |
| `observe_period_ms` | período de observação on-change (`normal_nec`) |
| `setmode_every_cycles` | a cada N ciclos o servidor muda de modo A/B/C/D |
| `p_ng` | probabilidade de resposta NG (return code de erro) |
| `timeout_s` | timeout das apps cliente/servidor |
| `num_events` | número de eventos/iterações configurado na app |
| `duration_s` | duração **full** do run; `--scale` multiplica este valor |
| `client_ecu` / `server_ecu` | contentores que correm cliente e servidor |
| `sd_port` | porta UDP do SOME/IP-SD (30490) |
| `service_a_port` / `service_b_port` | portas dos serviços (30509/30510) |
| `multicast_group` | grupo multicast do SD |
| `concurrent_sessions` | nº de sessões concorrentes |
| `seed` | seed RNG (runs reprodutíveis) |
| `target_packets` | alvo de volume da Tabela III (usado pela validação) |

---

## 3. Datasets de ataque

```bash
# um dataset
./scripts/gen_attack_dataset.sh ANEpc-a1

# iteração rápida / demo (5 %)
./scripts/gen_attack_dataset.sh ANEpc-a1 --scale 0.05
```

Os 11 datasets implementados:

| id | base | duração full | ataque |
|---|---|---|---|
| `ARR-Req-a1` | `normal_rr` | 135 s | MITM de request: termina + injeta + fabrica resposta |
| `ARR-Res-a1` | `normal_rr` | 154 s | MITM de response |
| `ANEpc-a1` | `normal_nepc` | 21 s | tamper de notificações, `violating`, sinais mistos |
| `ANEpc-a2` | `normal_nepc` | 21 s | idem, só `speed` |
| `ANEpc-a3` | `normal_nepc` | 21 s | idem, só `steering` |
| `ANEpc-a4` | `normal_nepc` | 21 s | idem, só `gear` |
| `ANEpc-a5` | `normal_nepc` | 21 s | `plausible`, sinais mistos |
| `ANEpc-a6` | `normal_nepc` | 21 s | `plausible`, só `speed` |
| `ANEpc-a7` | `normal_nepc` | 21 s | `plausible`, só `steering` |
| `ANEpc-a8` | `normal_nepc` | 21 s | `mixed` (plausible + violating) |
| `ANEc-a1` | `normal_nec` | 23 s | tamper de notificações on-change |

```bash
# gerar os 11 (sequencial; ≈ 15–20 min)
for id in ARR-Req-a1 ARR-Res-a1 \
          ANEpc-a1 ANEpc-a2 ANEpc-a3 ANEpc-a4 ANEpc-a5 ANEpc-a6 ANEpc-a7 ANEpc-a8 \
          ANEc-a1; do
  ./scripts/gen_attack_dataset.sh "$id"
done
```

O gerador: regressão `raw` → `compose up` (datasets + attacker) → setup da
bridge (FDB estático, learning OFF na porta do `ecu6`) → capturas por
interface → atacante no `ecu6` (ARP poison + relay + args do YAML) → apps →
teardown da bridge → merge/dedup → `pcap_to_csv --attacker-mac` → validação
`--attack` → `datasets/attack/MANIFEST.json`.

| campo / env | para que serve |
|---|---|
| `<id>` | um dos 11 identificadores da tabela |
| `--scale F` | fração da duração; `<id>_scaleF.*`, sem tocar no manifest |
| `IDS_ECU2=1` | inclui o sidecar `ids-ecu2` no `compose up` |
| `NO_BUILD=1` | usa `--no-build` (preserva a imagem actual do `ecu2`) |
| `SKIP_UP=1` | não faz `compose up` (laboratório já levantado) |

### 3.1 Campos dos YAML de ataque

Ficheiros: `config/datasets/attack/*.yaml`.

| campo | significado |
|---|---|
| `dataset` | id do ataque |
| `base` | dataset normal de onde herdam os campos em falta (`normal_rr`, `normal_nepc`, `normal_nec`) |
| `variant` | descrição legível do padrão de ataque |
| `seed` | seed RNG do atacante e das apps |
| `duration_s` | duração full do run |
| `attacker_args` | argumentos passados a `tools/attacker/attacker.py` |

### 3.2 Flags de `tools/attacker/attacker.py`

Corre **dentro do `ecu6`** (normalmente invocado pelo gerador, não à mão).

| flag | significado |
|---|---|
| `--iface` | interface do atacante (default `eth0`) |
| `--poison VICTIM:CLAIMED` | envenena a ARP de `VICTIM`, dizendo que `CLAIMED` está no MAC do atacante; repetível |
| `--terminate-requests F` | fração `F` dos ECHO requests interceptados |
| `--terminate-responses F` | fração `F` das responses RR interceptadas |
| `--inject-requests` | o atacante envia um request próprio (client id `0x1002`) e fabrica a resposta ao cliente |
| `--req-style knows\|ignores` | o servidor real “conhece” ou “ignora” o request injectado |
| `--fab-style knows\|ignores` | a resposta fabricada segue o estilo `knows`/`ignores` |
| `--tamper-notify F` | fração `F` das notificações alteradas |
| `--tamper-svc LIST` | Service IDs alvo do tamper (default `0x1235,0x1236`) |
| `--tamper-signal speed\|steering\|gear\|mixed` | sinal(ais) do payload a alterar |
| `--tamper-kind violating\|plausible\|mixed` | valores fora da faixa / plausíveis / mistos |
| `--drop-sd-subscribe SVC` | descarta Subscribes SD do serviço `SVC`; repetível |
| `--duration S` | duração do ataque (s); `0` = até ser parado |
| `--stats-file PATH` | JSON com contadores do atacante |
| `--seed N` | seed RNG |

---

## 4. Features de transição

```bash
python3 tools/extract_features.py
python3 tools/validate_features.py
```

`extract_features.py` lê os CSVs das Fases 2/3 e grava
`features/<nome>.csv` (colunas originais + 13 features + `label`),
`features/thresholds.json` e `features/MANIFEST.json`.

| flag | significado |
|---|---|
| `--normal-dir DIR` | diretório dos normais (default `datasets/normal`) |
| `--attack-dir DIR` | diretório dos ataques (default `datasets/attack`) |
| `--out-dir DIR` | saída (default `features`) |
| `--only NOME` | processa só este dataset (stem do CSV); repetível — **usa para excluir `*_scale*`** |
| `--thresholds PATH` | reutiliza limiares existentes e salta o aprendizado |
| `--learn-holdout FRAC` | aprende os limiares só nos primeiros `(1-FRAC)` de cada normal (ex.: `0.3`) |
| `--learn-only` | só aprende e grava `thresholds.json`, não extrai |

```bash
# exemplo: reextrair só os canónicos, ignorando ficheiros *_scale*
python3 tools/extract_features.py \
  --only normal_rr --only normal_nepc --only normal_nec \
  --only ARR-Req-a1 --only ARR-Res-a1 \
  --only ANEpc-a1 --only ANEpc-a2 --only ANEpc-a3 --only ANEpc-a4 \
  --only ANEpc-a5 --only ANEpc-a6 --only ANEpc-a7 --only ANEpc-a8 \
  --only ANEc-a1
```

`validate_features.py` faz o *sanity check* das features (sem IDS): KS entre
`label=0` e `label=1` e diferença de pontos percentuais nas categorias.

| flag | significado |
|---|---|
| `--features-dir DIR` | diretório das features (default `features`) |
| `--ks F` | limiar de KS (default `0.10`) |
| `--pp F` | limiar de diferença categórica em p.p. (default `5.0`) |
| `--only NOME` | valida só este dataset; repetível |

---

## 5. IDS offline (Fase 5)

### 5.1 `tools/ids_realtime.py` — Algoritmo 1

Três subcomandos: `train` (treina o modelo), `detect` (aplica a um CSV de
features) e `run` (treina se necessário e aplica a vários datasets).

```bash
# treinar
python3 tools/ids_realtime.py train \
  --features-dir features \
  --model results/baseline_v3/ip/realtime_model_use_ip_h30.json \
  --identity ip --avg-cold-start use \
  --thresholds features/thresholds.json --manifest features/MANIFEST.json

# detetar num CSV
python3 tools/ids_realtime.py detect \
  --input features/ANEpc-a1.csv \
  --model results/baseline_v3/ip/realtime_model_use_ip_h30.json \
  --out results/baseline_v3/ip/realtime_use_ip_h30_ANEpc-a1.csv

# treinar (se preciso) + detetar vários
python3 tools/ids_realtime.py run \
  --dataset ANEpc-a1 --dataset ANEc-a1 --force-train \
  --identity ip --model results/baseline_v3/ip/realtime_model_use_ip_h30.json
```

| flag (comuns) | significado |
|---|---|
| `--features-dir DIR` | diretório das features |
| `--thresholds PATH` | `thresholds.json` (discretização) |
| `--manifest PATH` | `MANIFEST.json` (exclusões) |
| `--model PATH` | modelo de saída/entrada |
| `--avg-cold-start use\|na` | usa ou ignora a média no arranque (“cold start”) |
| `--identity mac\|ip\|ip_client` | identidade usada na tupla de estado (o MAC é oráculo) |
| `--payload-state` | acrescenta o estado por sinal do payload à tupla (E3) |
| `--payload-exclude SINAL` | retira um sinal do estado (ex.: `seq`) |
| `--session-source timeout\|sd` | delimita sessões por inatividade ou por eventos SD (E4) |
| `--normal NOME` | (`train`) normais a usar; repetível |
| `--input CSV` | (`detect`) CSV de features de entrada |
| `--out PATH` | saída (`train`: modelo; `detect`: CSV de veredictos) |
| `--dataset NOME` | (`run`) dataset a detetar; repetível |
| `--force-train` | (`run`) força treino mesmo que o modelo exista |

### 5.2 `tools/ids_retroactive.py apply` — Algoritmo 2

```bash
python3 tools/ids_retroactive.py apply \
  --detect results/baseline_v3/ip/realtime_use_ip_h30_ANEpc-a1.csv \
  --model results/baseline_v3/ip/realtime_model_use_ip_h30.json \
  --retro-window 3 \
  --out results/baseline_v3/ip/retro_use_ip_h30_ANEpc-a1.csv
```

| flag | significado |
|---|---|
| `--detect CSV` | saída do Algoritmo 1 para o mesmo dataset |
| `--model PATH` | modelo usado pelo Algoritmo 1 |
| `--out CSV` | CSV final (por omissão `results/retro_<nome>.csv`) |
| `--session-timeout S` | inatividade que fecha uma sessão (default 10 s) |
| `--session-source timeout\|sd` | delimitação por timeout ou por SD |
| `--retro-window T` | janela de retroação em segundos em torno do *hit*; **omitido** = literal (toda a sessão, `baseline_v2`) |

### 5.3 `tools/evaluate_ids.py` — avaliação completa

```bash
for ident in ip ip_client; do
  python3 tools/evaluate_ids.py \
    --features-dir features --identity "$ident" --holdout 0.3 \
    --retro-window 3 \
    --results-dir "results/baseline_v3/$ident" \
    --out "results/baseline_v3/$ident/report.json"
done
```

| flag | significado |
|---|---|
| `--features-dir DIR` | features de entrada |
| `--thresholds PATH` | `thresholds.json` |
| `--manifest PATH` | `MANIFEST.json` |
| `--results-dir DIR` | onde gravar CSVs e modelos |
| `--variant use\|na\|both` | variante `avg-cold-start` |
| `--identity mac\|ip\|ip_client` | identidade |
| `--holdout FRAC` | fração final de cada normal reservada para medir FPR (protocolo E1) |
| `--session-source timeout\|sd` | delimitação de sessões |
| `--retro-window T` | janela retroativa (`T=3` é o valor do baseline v3) |
| `--payload-state` | liga o estado de payload (E3) |
| `--payload-exclude SINAL` | exclui um sinal do estado (repetível) |
| `--out JSON` | relatório final |
| `--no-train` | reutiliza modelos existentes |
| `--compare-baseline DIR` | compara o relatório com outro (`evaluation_report.json`) |

### 5.4 Ferramentas de análise (só leitura)

```bash
python3 tools/consolidate_fase5.py
```

Lê os CSVs congelados do `baseline_v1/v2/v3` e das experiências e imprime a
tabela consolidada (TPR/FPR por pacote, TPR direta vs contágio, por sessão,
% tempo-real vs retroativo). Grava `results/fase5_consolidado.json`. **Não
treina nem corre detetores.**

```bash
python3 tools/diagnose_ids.py \
  --results-dir results/baseline_v3/ip \
  --results-dir-alt results/baseline_v3/ip_client \
  --model-100 results/baseline_v1/realtime_model_use.json \
  --out results/baseline_v3/diagnose.json
```

Diagnósticos D1/M1: classifica falsos positivos do Algoritmo 1, verifica SD
com MAC do atacante e separa deteção direta de contágio.

| flag | significado |
|---|---|
| `--results-dir DIR` | resultados principais |
| `--results-dir-alt DIR` | resultados alternativos (comparação) |
| `--model-100 PATH` | modelo treinado a 100 % (para o diagnóstico D1) |
| `--out JSON` | saída |

```bash
python3 tools/experiment_e1b_report.py
python3 tools/experiment_e3_report.py
python3 tools/experiment_e3b_report.py
python3 tools/experiment_r1.py
python3 tools/experiment_r2.py
python3 tools/smoke_s1_sd_injection.py
```

Experiências E1b (limiares), E3/E3b (estado de payload), R1/R2 (retroativo) e
o *smoke* S1 de injeção SD. Cada uma tem `--help` com os campos específicos;
nenhuma altera os artefactos congelados.

---

## 6. IDS online / live (Fase 6)

`tools/ids_live.py` corre os dois algoritmos **sem treino**, com o modelo
congelado `results/baseline_v3/ip/realtime_model_use_ip_h30.json`.

### 6.1 Replay determinístico de um pcap

```bash
python3 tools/ids_live.py \
  --pcap datasets/attack/ANEpc-a1.pcap \
  --labels-csv datasets/attack/ANEpc-a1.csv \
  --out-dir results/ids_live/ANEpc-a1 \
  --name ANEpc-a1 \
  --session-max-age 60
```

Reproduz o *offline* pacote a pacote (timestamps do pcap). Usa `--labels-csv`
só para atribuir `label`; **nunca** é entrada do detetor.

### 6.2 Captura ao vivo

A imagem base das ECUs não monta o repositório, por isso corre o IDS num
contentor auxiliar que partilha o *network namespace* do `ecu2` e monta o
repositório:

```bash
# descobrir a interface (nomes eth0/eth1 não são estáveis no Docker)
docker exec ecu2 ip -o -4 addr show

# IDS no netns do ecu2 (ex.: interface com 192.168.1.1)
docker run --rm -it --network container:ecu2 --cap-add NET_RAW \
  -v "$PWD:/work" -w /work \
  --entrypoint python3 automotive-ids/attacker:latest \
  tools/ids_live.py --interface <iface> \
    --out-dir results/ids_live/ecu2 --name ecu2-live --session-max-age 60
```

> Isto só vê o tráfego endereçado ao próprio `ecu2`. Para ver o unicast
> `ecu1↔ecu6` é necessário o *mirror* descrito em §7.2.

### 6.3 Flags de `ids_live.py`

| flag | significado |
|---|---|
| `--pcap PATH` | replay determinístico (exclusivo com `--interface`) |
| `--interface IF` | captura ao vivo (ex.: `eth0`, `mirror0`) |
| `--model PATH` | modelo congelado (default `baseline_v3/ip/...h30.json`) |
| `--thresholds PATH` | `thresholds.json` (default: o do modelo ou `features/thresholds.json`) |
| `--labels-csv CSV` | só replay: CSV com `label`, para relatório (não é feature) |
| `--out-dir DIR` | diretório de saída (default `results/ids_live`) |
| `--name NOME` | prefixo dos ficheiros (`realtime_<nome>.csv`, `retro_<nome>.csv`) |
| `--retro-window T` | janela retroativa em segundos (default `3.0`) |
| `--session-timeout S` | inatividade que fecha a sessão (default `10.0`) |
| `--session-hold-timeout S` | teto de segurança para sessões fechadas mas pendentes de CS (default `300`; `0` = sem teto) |
| `--session-max-age S` | idade máxima da sessão; corta como EOF e limita memória (`0` = sem corte) |
| `--emit-from-index N` | só emite vereditos a partir deste índice global; antes só aquece estado (holdout) |
| `--bpf-filter EXPR` | filtro BPF na captura ao vivo (default `udp`) |
| `--max-packets N` | limite de pacotes (debug) |
| `--dump-features PATH` | grava linhas + features calculadas (debug/validação) |
| `--quiet-alerts` | não imprime `[ALERT]` no stderr |

Saídas: `results/<out-dir>/realtime_<nome>.csv` (uma linha por pacote,
`alert_transition` imediato) e `retro_<nome>.csv` (veredicto final, escrito
quando a sessão fecha). Os `[ALERT]` vão para stderr/`docker logs`.

### 6.4 Validar o modo online contra o baseline congelado

```bash
python3 tools/validate_ids_live.py --max-age 60
```

| flag | significado |
|---|---|
| `--attack NOME` | ataque a validar (repetível; default: `ANEpc-a1`, `ARR-Res-a1`, `ANEc-a1` — `ARR-Req-a1` não serve, ver `nota_divergencia_arrreqa1.md`) |
| `--normal NOME` | normal a validar (repetível; default `normal_rr`) |
| `--max-age S` | valor de `--session-max-age` a testar (default `60`; `0` = não validar) |
| `--skip-max-age` | corre só a variante sem corte (semântica offline) |
| `--identity ID` | `ip` (default) ou `ip_client` |
| `--baseline DIR` | diretório do baseline congelado (default `results/baseline_v3/ip`) |
| `--out JSON` | relatório (default `results/ids_live_validation/report.json`) |

### 6.5 Estágio B — replay pela rede real

```bash
./scripts/stage_b_live_replay.sh ANEpc-a1
```

Cria uma rede Docker própria (`someip_stageb`, `172.31.0.0/16`), liga dois
contentores por um veth **direto** (evita duplicação por forwarding do host),
o emissor reenvia o pcap com o temporismo original e o recetor corre
`ids_live.py --interface eth9`. Mede o desvio introduzido pelo jitter.

| campo / env | significado |
|---|---|
| `DATASET` (arg) | dataset a reenviar (default `ANEpc-a1`) |
| `NET` | nome da rede Docker (default `someip_stageb`) |
| `SUBNET` | sub-rede da rede (default `172.31.0.0/16`) |
| `IMG` | imagem dos contentores (default `automotive-ids/attacker:latest`) |

Saída: `results/ids_live_stageB/<dataset>/` (CSVs, log e `features.csv`).

`tools/replay_pcap_live.py` é o emissor usado pelo estágio B:

| flag | significado |
|---|---|
| `--pcap PATH` | pcap a reenviar |
| `--interface IF` | interface de saída |
| `--dst-mac MAC` | MAC de destino (opcional) |
| `--src-mac MAC` | MAC de origem (opcional) |
| `--speed F` | fator de velocidade (`1.0` = temporismo original) |
| `--limit N` | nº máximo de pacotes |
| `--out-json PATH` | relatório de envio |

### 6.6 Comparar live vs replay offline

```bash
python3 tools/compare_live_replay.py \
  --live-dir results/ids_live_stageB/ANEpc-a1 \
  --dataset ANEpc-a1
```

| flag | significado |
|---|---|
| `--live-dir DIR` | resultados do modo online |
| `--dataset NOME` | dataset comparado |
| `--baseline-dir DIR` | baseline de referência (default `results/baseline_v3/ip`) |
| `--features PATH` | CSV de features congelado (`features/<ds>.csv`) para comparar com as features ao vivo; opcional |
| `--live-features PATH` | CSV de features gravado pelo `--dump-features`; opcional |
| `--out-json PATH` | relatório JSON |

Quantifica o desvio (não exige 0/0 bit-a-bit; ver critério de jitter em
[`docs/ids_live.md`](ids_live.md)).

---

## 7. IDS embarcado no ecu2 (sidecar)

### 7.1 Sidecar isolado

```bash
# arrancar só o sidecar (ecu2 já tem de estar up)
docker compose -f docker-compose.yml -f docker-compose.ids.yml \
  up -d --no-build ids-ecu2

# ver decisões ao vivo
docker logs -f ids-ecu2

# parar com SIGINT (flush das sessões retroativas)
docker compose -f docker-compose.yml -f docker-compose.ids.yml stop ids-ecu2
```

| env | significado |
|---|---|
| `IDS_IFACE=net1\|net2\|auto\|<iface>` | interface escutada (default `net1`) |
| `IDS_OUT_DIR` | diretório de saída dentro de `/work` |
| `IDS_NAME` | prefixo dos CSV (default `sidecar`) |
| `IDS_SESSION_MAX_AGE` | `--session-max-age` (default `60`) |
| `IDS_BPF_FILTER` | filtro BPF (default do compose: portas 30490/30509/30510/30511) |

> **Limitação importante:** um veth só vê o tráfego endereçado ao próprio
> contentor. A interface `net1` do `ecu2` **não vê** o unicast `ecu1↔ecu6`
> (atacante). Para observar ataques é preciso o *mirror* montado pelo script
> de validação (ver §7.2). O sidecar **não** tem `NET_ADMIN`.

### 7.2 Validação host vs sidecar (com mirror)

```bash
# execução completa (gera o ataque e compara no fim)
./scripts/ids_ecu2_validation.sh ANEpc-a1 0.10
./scripts/ids_ecu2_validation.sh ARR-Res-a1 0.10
```

O script:
1. sobe o lab (`--no-build`);
2. monta `tc ingress` nos veths de `ecu1`/`ecu2`/`ecu6` → `mirrorh` (host) ↔
   `mirror0` (netns do `ecu2`), uma cópia por trama;
3. arranca a **referência host** (`ids_live.py` em contentor `--net=host` em
   `mirrorh`), o **tcpdump de referência** e o **sidecar** (`mirror0`);
4. corre `gen_attack_dataset.sh` com `SKIP_UP=1`;
5. faz SIGINT, flush, e compara com `tools/compare_ids_location.py`.

### 7.3 Deixar o IDS a correr e atacar manualmente

```bash
# terminal 1 — monta lab + mirror + sidecar e SAI, deixando tudo a correr
NO_ATTACK=1 ./scripts/ids_ecu2_validation.sh ANEpc-a1 0.10

# terminal 2 — ataque (pode ser repetido; o IDS acumula estado)
SKIP_UP=1 NO_BUILD=1 ./scripts/gen_attack_dataset.sh ANEpc-a1 --scale 0.10

# observar
docker logs -f ids-ecu2

# parar e limpar (SIGINT -> flush, para testemunhas, remove mirror/veth)
DOWN=1 ./scripts/ids_ecu2_validation.sh
```

| campo / env | significado |
|---|---|
| `<dataset>` (arg 1) | dataset de ataque (default `ANEpc-a1`) |
| `<scale>` (arg 2) | escala do ataque (default `0.10`); usa sempre `< 1` |
| `NO_ATTACK=1` | monta tudo, grava `.live_state` e sai sem atacar |
| `DOWN=1` | lê `.live_state`, faz SIGINT ao sidecar, para testemunhas e remove o mirror |

O estado da sessão persistente fica em
`results/ids_live_ecu2/.live_state` (nomes dos contentores auxiliares e veths)
e é removido pelo `DOWN=1`.

### 7.4 Comparar host vs sidecar depois de parar

```bash
MAC=$(docker exec ecu6 cat /sys/class/net/eth0/address)
python3 tools/compare_ids_location.py \
  --host-dir results/ids_live_ecu2/ANEpc-a1/host \
  --sidecar-dir results/ids_live_ecu2/ANEpc-a1/sidecar \
  --name ANEpc-a1 \
  --attacker-mac "$MAC" \
  --reference-pcap results/ids_live_ecu2/ANEpc-a1/mirror_host.pcap \
  --out-json results/ids_live_ecu2/ANEpc-a1/compare_manual.json
```

| flag | significado |
|---|---|
| `--host-dir DIR` | resultados da referência host |
| `--sidecar-dir DIR` | resultados do sidecar |
| `--name NOME` | prefixo dos CSV (ex.: `ANEpc-a1`) |
| `--attacker-mac MAC` | MAC do atacante; a `label` é derivada de `src_mac` |
| `--reference-pcap PCAP` | pcap do mesmo stream (prova que ambos viram as mesmas mensagens) |
| `--out-json PATH` | relatório de equivalência |
| `--time-margin S` | margem em volta da janela de ataque (default `1.0`) |
| `--align-tol-ms MS` | tolerância de emparelhamento (default `5`) |

Critério documentado: **mesmas classificações dentro do envelope de jitter**
(não 0/0 bit-a-bit). O relatório traz
`verdict.equivalent_within_jitter`.

---

## 8. Comparadores e controlo de qualidade

### 8.1 `tools/pcap_to_csv.py`

```bash
python3 tools/pcap_to_csv.py datasets/attack/ANEpc-a1.pcap \
  --out datasets/attack/ANEpc-a1.csv \
  --attacker-mac "$(docker exec ecu6 cat /sys/class/net/eth0/address)"
```

| flag | significado |
|---|---|
| `pcap` (posicional) | pcap de entrada |
| `--out CSV` | CSV de saída (default `<pcap>.csv`) |
| `--label N` | label por omissão (`0`) |
| `--attacker-mac MAC` | `label=1` quando `src_mac == MAC` (regra da Fase 3); ignora `--label` |

### 8.2 `tools/merge_captures.py`

```bash
python3 tools/merge_captures.py datasets/attack/ANEpc-a1.pcap \
  pcaps/ecu1.pcap pcaps/ecu2.pcap pcaps/ecu3.pcap \
  --report --attacker-mac "$MAC"
```

| flag | significado |
|---|---|
| `output` (posicional) | pcap de saída |
| `inputs...` (posicional) | pcaps de entrada (ordem fixa) |
| `--report` | imprime contagens por ficheiro |
| `--attacker-mac MAC` | modo ataque: dedup lógica entre a cópia original (`label=0`) e a reemitida (`label=1`) |

### 8.3 `tools/validate_dataset.py`

```bash
# normal
python3 tools/validate_dataset.py datasets/normal/normal_rr.pcap \
  --dataset normal_rr --scale 0.05

# ataque
python3 tools/validate_dataset.py datasets/attack/ANEpc-a1.pcap \
  --attack --attacker-mac "$MAC" --scale 0.05
```

| flag | significado |
|---|---|
| `pcap` (posicional) | pcap a validar |
| `--dataset NOME` | nome lógico (normais) |
| `--scale F` | escala usada na geração (ajusta os alvos) |
| `--removed-dups N` | nº de duplicados removidos no merge (informativo) |
| `--update-manifest` | atualiza `MANIFEST.json` (só em runs completos) |
| `--attack` | valida no modo ataque |
| `--attacker-mac MAC` | MAC que define `label=1` no modo ataque |

Alvos completos: `normal_rr` 6 455, `normal_nepc` 255 128, `normal_nec`
1 722 011; ataques com `(anomalia, total)` por set (Tabela III).

### 8.4 `tools/verify_pcap.py`

```bash
python3 tools/verify_pcap.py pcaps/*.pcap
```

Valida C1–C5 do smoke test lendo os pcaps com scapy. Exit `0` = tudo passou.

### 8.5 `tools/check_checksums.sh`

```bash
tools/check_checksums.sh
```

Verifica `datasets/CHECKSUMS.sha256` (pcaps + CSVs congelados). Correr
**antes** das Fases 4/5. Exit `0` = intactos; `1` = alterado/em falta.

---

## 9. Debug de Docker e rede

```bash
# estado dos contentores
docker ps -a --format '{{.Names}}\t{{.Status}}'

# IPs e interfaces de cada ECU
for c in ecu1 ecu2 ecu3 ecu4 ecu5 ecu6; do
  echo "== $c"
  docker exec "$c" ip -o -4 addr show
done

# logs de uma ECU
docker logs --tail 100 -f ecu2

# shell dentro de uma ECU
docker exec -it ecu1 sh

# MAC do atacante (label da Fase 3)
docker exec ecu6 cat /sys/class/net/eth0/address

# regras do raw PREROUTING no host
./scripts/smoke_test.sh --host-raw up     # (re)aplica
docker run --rm --net=host --privileged --entrypoint sh \
  automotive-ids/vsomeip:latest -c 'iptables -t raw -S PREROUTING'

# interfaces veth do host
ip -o link show | grep -E 'veth|mirror'

# qdiscs (confirmar/limpar mirror)
tc qdisc show dev <veth>
```

Para testar o IDS ao vivo a partir do **host** (sem `sudo`), usa um contentor
com `--net=host`:

```bash
docker run --rm -it --net=host --cap-add NET_RAW \
  -v "$PWD:/work" -w /work \
  --entrypoint python3 automotive-ids/attacker:latest \
  tools/ids_live.py --interface <iface> --out-dir results/ids_live/host
```

Índices úteis: `iflink`/`ifindex` para descobrir o peer de um veth:

```bash
docker exec ecu1 cat /sys/class/net/eth0/iflink
ip -o link | awk -F': ' -v i="$(docker exec ecu1 cat /sys/class/net/eth0/iflink)" '$1==i {print $2}'
```

---

## 10. Troubleshooting

| sintoma | causa provável | resolução |
|---|---|---|
| `ids-ecu2` não vê o ataque | está em `net1`, que não vê o unicast `ecu1↔ecu6` | usa o *mirror* do `ids_ecu2_validation.sh` (`IDS_IFACE=mirror0`) |
| tráfego entre sub-redes desaparece | regras `DROP` anti-spoofing do Docker ≥ 26 | `./scripts/smoke_test.sh --host-raw up` |
| `compose down` falha ou deixa bridges | regras `raw` ainda referem bridges | `./scripts/smoke_test.sh --host-raw down` antes do `down` |
| `extract_features.py` apanha `*_scale*` | glob de `datasets/*/*.csv` | `--only` ou apagar os `*_scale*` |
| validação de dataset `FALHA` em escala pequena | alvos assumem `scale=1`; o run reduzido subestima taxas | é esperado; o ataque corre na mesma |
| `pool overlaps` no estágio B | sub-rede igual à do lab | usa `SUBNET=172.31.0.0/16` (default) |
| `ids-ecu2` não arranca | `ecu2` em baixo ou iface inexistente | sobe `ecu2`; usa `IDS_IFACE=auto` ou um nome válido |
| sem flush do retroativo ao parar | `SIGTERM` em vez de `SIGINT` | usa `docker compose stop` (o compose tem `stop_signal: SIGINT`) |
| ficheiros de resultados com owner `root` | escritos por contentores | normal; remove com `sudo`/`docker` se necessário |

---

## 11. Variáveis de ambiente, estado e caminhos

### 11.1 Variáveis

| variável | usada por | efeito |
|---|---|---|
| `NO_ATTACK=1` | `ids_ecu2_validation.sh` | deixa o IDS a correr e sai |
| `DOWN=1` | `ids_ecu2_validation.sh` | derruba a sessão persistente |
| `IDS_IFACE` | sidecar / validação | interface (`net1`, `net2`, `auto`, `mirror0`, …) |
| `IDS_RUN_DIR` / `IDS_RUN_NAME` | compose do sidecar | subdiretório e prefixo dos CSV |
| `IDS_SESSION_MAX_AGE` | sidecar | corte por idade da sessão |
| `IDS_ECU2=1` | `gen_attack_dataset.sh` | inclui o sidecar no `up` |
| `NO_BUILD=1` | `gen_attack_dataset.sh` | `--no-build` |
| `SKIP_UP=1` | `gen_attack_dataset.sh` | não faz `compose up` |
| `NET` / `SUBNET` / `IMG` | `stage_b_live_replay.sh` | rede, sub-rede e imagem do estágio B |
| `COMPOSE` / `IMAGE` | `smoke_test.sh` | comando compose e imagem dos helpers |

### 11.2 Estado

| caminho | conteúdo |
|---|---|
| `results/ids_live_ecu2/.live_state` | sessão persistente do sidecar (removido no `DOWN=1`) |
| `results/ids_live_ecu2/<dataset>/{host,sidecar}/` | CSVs e logs das duas testemunhas |
| `results/ids_live_ecu2/<dataset>/mirror_host.pcap` | pcap de referência do mirror |
| `results/baseline_v3/{ip,ip_client}/` | artefactos congelados da Fase 5 (não alterar) |
| `results/ids_live_stageB/<dataset>/` | resultados do estágio B |
| `.state/host_raw_exceptions.json` | regras `raw` aplicadas ao host |
| `datasets/{normal,attack}/MANIFEST.json` | validação dos datasets canónicos |
| `datasets/CHECKSUMS.sha256` | checksums dos datasets congelados |
| `features/{thresholds,MANIFEST}.json` | limiares e exclusões da Fase 4 |

### 11.3 Caminhos que não devem ser alterados

- `datasets/` canónicos e `datasets/CHECKSUMS.sha256`;
- `results/baseline_v3/`;
- `docs/relatorio_fase5.md`;
- `automotive-ids/vsomeip:latest` e a configuração do `ecu2`.

---

## Referências

| documento | conteúdo |
|---|---|
| [`README.md`](../README.md) | visão geral, fases e passo a passo |
| [`docs/documentacao.md`](documentacao.md) | relatório geral das Fases 1–6 |
| [`docs/relatorio_fase2.md`](relatorio_fase2.md) | datasets normais |
| [`docs/attack_datasets.md`](attack_datasets.md) | datasets de ataque |
| [`docs/attack_model.md`](attack_model.md) | modelo e premissas do atacante |
| [`docs/feature_model.md`](feature_model.md) | features e limiares |
| [`docs/ids_model.md`](ids_model.md) | algoritmos 1 e 2 |
| [`docs/relatorio_fase5.md`](relatorio_fase5.md) | avaliação offline |
| [`docs/ids_live.md`](ids_live.md) | modo online, latência, memória, validação e sidecar |
| [`docs/relatorio_fase6.md`](relatorio_fase6.md) | relatório consolidado da Fase 6 |
