# Nota de divergência — ARR-Req-a1

*Criado em: 2026-10-18. Leitura obrigatória antes de qualquer re-geração do ARR-Req-a1.*

---

## 1. Situação documentada

O dataset `ARR-Req-a1` em disco **não é bit-a-bit idêntico** ao que foi usado nos
resultados congelados (`baseline_v3`). Há duas diferenças:

| item | execução congelada | em disco (regenerada) |
|---|---|---|
| `total_packets` (datagramas) | **3 272** | **3 276** (+4) |
| linhas de dados no CSV | 3 272 | 3 277 |
| `anomaly_packets` | 738 | 738 (igual) |
| transições detectadas (Algoritmo 1, `ip`) | **498** | **447** |
| TPR final micro (`ip`) | **0,9477** | **0,9431** (−0,46 p.p.) |
| TPR final micro (`ip_client`) | **0,4866** | **0,4828** (−0,38 p.p.) |

**O MANIFEST versionado** (`datasets/attack/MANIFEST.json`, commit `f917551`)
documenta a execução congelada (3 272). Esse MANIFEST **não foi e não deve ser
atualizado** — serve de referência histórica da execução que gerou os
`baseline_v1/v2/v3`. O `datasets/CHECKSUMS.sha256` (não versionado) fixa o hash
dos arquivos atualmente em disco (ARR-Req-a1 = 3 276).

A variação de ~0,5 p.p. no TPR final e de 51 transições no Algoritmo 1 é a
**única estimativa de variabilidade run-a-run** disponível (n = 2, sem repetição
controlada). Deve ser lida como indicação da ordem de grandeza, **não** como
intervalo de confiança.

---

## 2. Investigação forense — quando e como aconteceu

### 2.1 Cronologia reconstruída

| momento | evento |
|---|---|
| **2026-10-04 19:39** | Commit `f917551` — MANIFEST gerado com 3 272 datagramas (execução congelada PASS). |
| **2026-10-17 23:13** | Commit `bc80bc6` — `.gitignore` do PDF do artigo. O ARR-Req-a1 em disco ainda era o de 3 272. |
| **2026-10-17 23:??** | Execução do comando `./scripts/gen_attack_dataset.sh ARR-Req-a1 --scale 0.10` (ver §2.2). O script na versão anterior **não** separava o path de saída por escala: escrevia diretamente em `datasets/attack/ARR-Req-a1.pcap`, sobrescrevendo o dataset completo. |
| **2026-10-17 23:42** | Timestamp atual dos arquivos `ARR-Req-a1.pcap` e `ARR-Req-a1.csv` em disco. *Nota: o timestamp não é da run de 10% — é da re-geração a escala 1.0 feita pelo agente anterior para desfazer o dano (ver §2.3).* |

### 2.2 Comando que causou a sobrescrita

O histórico de shell (`~/.bash_history`, entrada 1979) registra:

```
./scripts/gen_attack_dataset.sh ARR-Req-a1 --scale 0.10
```

Na versão do script em vigor naquele momento (antes do commit `01d5c6f`), o
caminho de saída era **fixo**:

```bash
OUT_PCAP="$ROOT/datasets/attack/${DATASET}.pcap"  # sem sufixo de escala
```

e o `validate_dataset.py` sempre era chamado com `--update-manifest`. Portanto,
`--scale 0.10` gerava 329 pacotes (10 % do alvo) e os gravava em
`datasets/attack/ARR-Req-a1.pcap`, **apagando silenciosamente** o dataset
completo de 3 272 pacotes. O MANIFEST em disco também seria atualizado para 329
— mas como o MANIFEST está sob controlo do git, o git não o rastreou como
modificado (`.gitignore` não o inclui, mas estava untracked/unmodified na pasta
de ataque? — na prática a versão em disco do MANIFEST ficou com 3 272 porque o
agente anterior restaurou de seguida).

### 2.3 O que o agente anterior fez para recuperar

O agente anterior detectou a substituição durante a preparação do experimento
E1b. Ele re-gerou o ARR-Req-a1 a escala 1.0 (correndo novamente o
`gen_attack_dataset.sh ARR-Req-a1`), obtendo 3 276 datagramas (e 3 277 linhas
de CSV). **A run regenerada não é idêntica à congelada** porque a captura
`tcpdump` sobre tráfego Docker em tempo real tem marcas temporais variáveis. O
arquivo em disco com timestamp `2026-10-17 23:42` é a run regenerada (escala
1.0), não o run de 10%.

O MANIFEST em disco permanece com `total_packets: 3272` porque o agente
**não** chamou `--update-manifest` na re-geração (decisão correta — preservar
o registro da execução congelada).

### 2.4 O original (3 272) está perdido?

Sim. Os pcaps e CSVs **não estão no git** (`.gitignore` exclui
`datasets/**/*.pcap` e `*.csv`). A execução de `--scale 0.10` sobrescreveu o
arquivo sem backup. O conteúdo original só poderia ser recuperado se existisse
uma cópia externa (não confirmada).

---

## 3. Impacto nos resultados

- Os resultados congelados em `results/baseline_v3/` usaram o ARR-Req-a1 de
  **3 272** datagramas. Esses resultados estão corretos para aquele dataset.
- O dataset atual em disco tem **3 276** datagramas. A diferença de +4 é
  variabilidade run-a-run normal (o MANIFEST versionado documenta essa
  discrepância como observação, não como erro).
- Os 13 outros datasets (ARR-Res-a1, ANEpc-a1..a8, ANEc-a1) são **idênticos**
  entre a execução congelada e a situação atual em disco (confirmado pelo
  Control do E1b: 13 de 14 datasets produzem resultado bit-a-bit igual ao
  `baseline_v3`).
- **Nenhum resultado publicado precisa ser corrigido.** A variação de ~0,5 p.p.
  no TPR é uma observação de sensibilidade, não uma correção.

---

## 4. Proteção implementada (commit `01d5c6f`)

O commit `01d5c6f` adicionou ao `gen_attack_dataset.sh` e ao `gen_dataset.sh`
um bloco de proteção que **separa o caminho de saída** para runs com
`--scale != 1`:

```bash
if [[ "$SCALE" != "1" && "$SCALE" != "1.0" ]]; then
    DATASET_ID="${DATASET}_scale${SCALE}"   # ex.: ARR-Req-a1_scale0.10.pcap
    MANIFEST_ARGS=()                        # não toca no MANIFEST canônico
    warn "scale=$SCALE != 1 -> dataset reduzido '${DATASET_ID}' (NAO sobrescreve '${DATASET}')"
else
    DATASET_ID="$DATASET"
    MANIFEST_ARGS=(--update-manifest)
fi
```

Com esta proteção, `./scripts/gen_attack_dataset.sh ARR-Req-a1 --scale 0.10`
grava em `datasets/attack/ARR-Req-a1_scale0.10.pcap` e **não toca**
em `ARR-Req-a1.pcap` nem em `MANIFEST.json`.

Adicionalmente, `datasets/CHECKSUMS.sha256` (verificado por
`tools/check_checksums.sh`) fixa os hashes SHA-256 dos datasets atualmente em
disco. Deve ser executado antes das Fases 4 e 5:

```bash
tools/check_checksums.sh    # sai 0 se OK, 1 se algum arquivo mudou
```

---

## 5. O que fazer se o ARR-Req-a1 precisar ser regenerado

Se, por qualquer motivo, for necessário regenerar o ARR-Req-a1 a escala 1.0:

1. Correr `./scripts/gen_attack_dataset.sh ARR-Req-a1` (sem `--scale`).
2. O resultado **não será idêntico** ao de 3 272 nem ao de 3 276 — é uma nova
   execução independente.
3. Atualizar `datasets/CHECKSUMS.sha256` com `sha256sum datasets/attack/ARR-Req-a1.{pcap,csv} >> datasets/CHECKSUMS.sha256` (e remover as linhas antigas).
4. Re-correr as Fases 4 e 5 e comparar com `baseline_v3` antes de qualquer
   decisão sobre re-congelar resultados.
5. **Não** sobrescrever `results/baseline_v3/` sem pedido explícito.
