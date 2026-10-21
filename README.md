# someip-ids

Reprodução local, com Docker/compose, do ambiente **e** do IDS descritos em
*"SOME/IP Intrusion Detection System Using Real-Time and Retroactive Anomaly
Detection"* (Koyama et al., IEEE VTC2022-Spring).

O projeto tem **cinco fases**, todas executáveis do zero:

| fase | o que faz | script / comando | doc |
|---|---|---|---|
| **1** | laboratório SOME/IP (5+1 ECUs vsomeip, 2 sub-redes) + smoke test | `./scripts/smoke_test.sh` | [`docs/documentacao.md`](docs/documentacao.md) Parte I |
| **2** | datasets **normais** (RR, NEpc, NEc) | `./scripts/gen_dataset.sh <nome>` | [`docs/relatorio_fase2.md`](docs/relatorio_fase2.md) |
| **3** | datasets de **ataque** (11 sets, variante (a) MITM) | `./scripts/gen_attack_dataset.sh <id>` | [`docs/attack_datasets.md`](docs/attack_datasets.md) |
| **4** | **features** de transição (Tabela IV) | `python3 tools/extract_features.py` | [`docs/feature_model.md`](docs/feature_model.md) |
| **5** | **IDS** real-time + retroativo + avaliação | `python3 tools/evaluate_ids.py` | [`docs/relatorio_fase5.md`](docs/relatorio_fase5.md) |
| **6** | **IDS online** (ao vivo, mesmo modelo congelado) | `python3 tools/ids_live.py --interface eth0` | [`docs/ids_live.md`](docs/ids_live.md) |

O **resultado final** (comparação com os alvos do artigo, limitações e o que
mudaria) está em [`docs/relatorio_fase5.md`](docs/relatorio_fase5.md).

---

## Requisitos

| requisito | nota |
|---|---|
| Linux ou WSL2 (Ubuntu) | testado em WSL2 / Ubuntu 24.04 |
| Docker Engine **≥ 26** + Compose v2 | aqui: Docker 29.6.1 / Compose 2.40.3 |
| Python **≥ 3.10** | aqui: 3.12.3 (stdlib apenas + `scapy`) |
| `scapy` | `python3 -m pip install --user scapy` (verificação dos pcaps) |
| acesso a `iptables` (root / `--privileged`) | exceções do `raw PREROUTING` do host |
| disco | ~2,3 GB (imagens Docker) + ~1 GB (datasets+features) + pcaps/logs |

> O ambiente cria 5 ECUs + 1 atacante. **Nada** é alterado fora do Docker/WSL
> excepto regras `iptables` do `raw PREROUTING`, aplicadas e removidas
> automaticamente (ver [Exceções no `raw` PREROUTING](#exceções-no-raw-prerouting)).

---

## Do zero ao resultado final (passo a passo)

### 0. Preparação

```bash
python3 -m pip install --user scapy
```

### 1. Fase 1 — laboratório + smoke test  *(≈ 2–3 min; o 1.º build é mais lento)*

```bash
./scripts/smoke_test.sh              # sobe, gera tráfego, valida C1..C5
```

Saída esperada: `[PASS] C1..C5` e `SMOKE TEST: SUCESSO`.

### 2. Fase 2 — datasets normais  *(≈ 2,5 h no total)*

```bash
./scripts/gen_dataset.sh normal_rr      # ~5 min
./scripts/gen_dataset.sh normal_nepc    # ~21 min
./scripts/gen_dataset.sh normal_nec     # ~2 h (dominante)
```

Para iterar depressa use `--scale 0.05` (5 % do volume). Com escala 1.0 os
volumes-alvo são: RR 6 455, NEpc 255 128, NEc 1 722 011 (gates ±10 %).

### 3. Fase 3 — datasets de ataque (11 sets)  *(≈ 15–20 min)*

```bash
for id in ARR-Req-a1 ARR-Res-a1 \
          ANEpc-a1 ANEpc-a2 ANEpc-a3 ANEpc-a4 ANEpc-a5 ANEpc-a6 ANEpc-a7 ANEpc-a8 \
          ANEc-a1; do
  ./scripts/gen_attack_dataset.sh "$id"
done
```

Cada run valida contra os alvos da Tabela III (gate ±10 %) e escreve
`datasets/attack/MANIFEST.json`.

### 4. Fase 4 — features de transição  *(≈ 1–2 min)*

```bash
python3 tools/extract_features.py       # aprende limiares nos normais + extrai
python3 tools/validate_features.py      # sanity check (KS, Δp.p.)
```

Saída: `features/<nome>.csv`, `features/thresholds.json`, `features/MANIFEST.json`.

### 5. Fase 5 — IDS (real-time + retroativo)  *(≈ 30 s por identidade)*

```bash
for ident in ip ip_client; do
  python3 tools/evaluate_ids.py \
      --features-dir features --identity "$ident" --holdout 0.3 \
      --retro-window 3 \
      --results-dir "results/baseline_v3/$ident" \
      --out "results/baseline_v3/$ident/report.json"
done
```

`--holdout 0.3` = protocolo **E1** (treina nos primeiros 70 % de cada normal e
mede a FPR nos 30 % retidos); `--retro-window 3` = **T = 3 s** (a priori).
Resultado por identidade: `results/baseline_v3/<ident>/report.json`.

### 6. Terminar e limpar

```bash
./scripts/smoke_test.sh --down       # para contentores e limpa o raw PREROUTING
```

> `--down` é **só teardown** (idempotente, exit 0): não faz build, não sobe
> nada e **não** corre o teste completo.

---

## Tempo e espaço estimados

| etapa | captura | wall-clock (aprox.) |
|---|---|---|
| Fase 1 (smoke) | ~90 s | 2–3 min (1.º build: vários min) |
| `normal_rr` | 310 s | ~5 min |
| `normal_nepc` | 1 280 s | ~21 min |
| `normal_nec` | 7 100 s | ~2 h |
| Fase 3 (11 ataques) | ~8 min de captura | ~15–20 min |
| Fase 4 (features) | — | ~1–2 min |
| Fase 5 (2 identidades) | — | ~1 min |
| **total (escala 1.0)** | | **≈ 3 h** |

Atalho para demo/CI: correr tudo com `--scale 0.05` (minutos) — **mas** os
números do IDS só fazem sentido com escala 1.0.

---

## Onde ficam os artefactos

| caminho | conteúdo | no git? |
|---|---|---|
| `datasets/normal/<nome>.pcap/.csv` | datasets normais | **não** (`.gitignore`) |
| `datasets/attack/<id>.pcap/.csv` | datasets de ataque | **não** |
| `datasets/*/MANIFEST.json` | metadados/validação (versionado) | **sim** |
| `features/<nome>.csv` | features de transição | **não** |
| `features/thresholds.json` | limiares de discretização | **sim** |
| `features/MANIFEST.json` | contagens + exclusões | **sim** |
| `features_e1b/` | limiares/features do experimento **E1b** | **não** |
| `results/baseline_v1..v3/` | baselines congeladas (CSVs + `report.json` + modelo) | **não** |
| `results/exp_*/` | experimentos (E1b, E3, E3b, R1, R2, S1…) | **não** |
| `pcaps/*.pcap`, `logs/*.log`, `.state/*.json` | capturas/logs brutos | **não** |

> `results/` **não** é versionado (nem ignorado — simplesmente untracked). As
> baselines congeladas (`baseline_v1/v2/v3`) são regeneráveis a partir de
> `datasets/` + `features/`, mas **não** estão no git.

### O que está fora do git e como regenerar

| artefacto | regenerar com |
|---|---|
| `datasets/*/*.{pcap,csv}` | Fases 2 e 3 (`gen_dataset.sh` / `gen_attack_dataset.sh`) |
| `features/*.csv` | `python3 tools/extract_features.py` |
| `features_e1b/` | `python3 tools/extract_features.py --out-dir features_e1b --learn-holdout 0.3` |
| `results/baseline_v2/`, `results/baseline_v3/` | `tools/evaluate_ids.py` (ver §5 acima) |
| `results/exp_E1b/` | Control: `--features-dir features`; E1b: `--features-dir features_e1b` (ambos `--holdout 0.3 --retro-window 3`) |
| `pcaps/`, `logs/`, `.state/` | criados por cada run dos scripts |

O PDF do artigo também fica **fora** do git (untracked, `.gitignore`).

---

## Deteção numa captura já extraída (à mão)

```bash
# Algoritmo 1 (real-time) com o modelo congelado do baseline_v3
python3 tools/ids_realtime.py detect --identity ip \
    --input features/ARR-Req-a1.csv \
    --model results/baseline_v3/ip/realtime_model_use_ip_h30.json \
    --out /tmp/arr_rt.csv

# Algoritmo 2 (retroativo, T = 3 s) sobre a saída anterior
python3 tools/ids_retroactive.py apply \
    --detect /tmp/arr_rt.csv \
    --model results/baseline_v3/ip/realtime_model_use_ip_h30.json \
    --retro-window 3 --out /tmp/arr_retro.csv
```

Colunas chave da saída: `alert_transition` (hit direto do Algoritmo 1),
`final_anomaly` (após o retroativo), `label` (0/1).

---

## Topologia (Fase 1)

```
   ecu1 (192.168.1.2)  cliente SOME/IP
     |
   net1 192.168.1.0/24
     |
   ecu2 (192.168.1.1 + 192.168.2.1)  roteador + relay SOME/IP-SD
     |
   net2 192.168.2.0/24
     |-- ecu3 (192.168.2.2)  roteador (caminho de volta)
     |-- ecu4 (192.168.2.3)
     +-- ecu5 (192.168.2.4)  servidor SOME/IP
```

As duas sub-redes são bridges Docker distintas (dois domínios broadcast); o
roteamento L3 faz-se nos `ecu2`/`ecu3` (ida `ecu1→ecu2→ecu5`, volta
`ecu5→ecu3→ecu2→ecu1`). A Fase 3 acrescenta **ecu6** como atacante. IDs,
portas e detalhes das configurações vsomeip: [`config/README.md`](config/README.md).

---

## Exceções no `raw` PREROUTING

A partir do Docker Engine 26, o daemon insere por IP de contentor uma regra
anti-spoofing no `raw PREROUTING` **do host**: só aceita o IP se o frame entrar
pela bridge da rede onde esse IP vive. Como aqui o tráfego entre sub-redes é
**roteado** nos `ecu2`/`ecu3`, chega ao destino pela bridge da *outra* rede e
seria descartado. Os scripts espelham essas regras como `ACCEPT`, **antes** das
`DROP`, usando exatamente a mesma expressão (`-d <IP> ! -i <bridge>`).

- Aplicadas no `up`, removidas no `--down` (antes do `compose down`).
- Estado em `.state/host_raw_exceptions.json`; proteção contra regras órfãs.
- Remediação manual: `./scripts/smoke_test.sh --host-raw down|up`.
- Resultado esperado no host: **2 `ACCEPT` + 6 `DROP`** (7 `DROP` com o ecu6).

Detalhe completo (incluindo a alternativa descartada
`bridge-nf-call-iptables=0`): `docs/documentacao.md` Parte I.

---

## Documentação

| documento | conteúdo |
|---|---|
| [`docs/documentacao.md`](docs/documentacao.md) | relatório geral das Fases 1–6 (mapa, checklist, git) |
| [`docs/relatorio_fase2.md`](docs/relatorio_fase2.md) | Fase 2 (datasets normais), evidências |
| [`docs/attack_datasets.md`](docs/attack_datasets.md) · [`docs/attack_model.md`](docs/attack_model.md) | Fase 3 (tabela aprovada · modelo/premissas/bugs) |
| [`docs/feature_model.md`](docs/feature_model.md) | Fase 4 (features, limiares) |
| [`docs/ids_model.md`](docs/ids_model.md) · [`docs/relatorio_fase5.md`](docs/relatorio_fase5.md) | Fase 5 (algoritmos, protocolos · relatório final) |
| [`docs/ids_live.md`](docs/ids_live.md) | Fase 6 (modo online: arquitetura, latência, memória, validação) |
| [`docs/attacker_sd_plan.md`](docs/attacker_sd_plan.md) | R3 (atacante sem SD) — **plano, não implementado** |

---

## Notas metodológicas

- **O MAC nunca é entrada do detetor.** A identidade honesta é `ip` ou
  `ip_client`; `mac` só existe como cenário-oráculo/histórico (`baseline_v1`).
- **Protocolo E1:** treino nos primeiros 70 % de cada normal, medição no
  holdout temporal de 30 % (evita *leakage*).
- **`T = 3 s`** (janela retroativa) é escolhido *a priori* (= TTL do SD medido),
  não por tuning; 1/5/30 s são só sensibilidade.
- **`baseline_v1`/`v2`/`v3` são congeladas** — não sobrescrever. `v3` é a
  configuração principal (E1 + sem MAC + `T = 3 s`).
- O **R3** (atacante com SD próprio) e os **14 sets (b)/(c)** em falta são
  decisões de escopo pendentes, não bugs.
