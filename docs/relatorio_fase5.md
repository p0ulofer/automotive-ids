# Fase 5 — relatório final consolidado

Reprodução do IDS SOME/IP de Koyama et al. (VTC2022-Spring, Sec. V-B e V-C).
Este relatório fecha a Fase 5: consolida as configurações **congeladas**, mede-as
de forma uniforme a partir dos CSVs por-pacote já produzidos (nenhum detector é
re-corrido e nenhum limiar é re-ajustado) e confronta o resultado com o artigo.

> **Regra de leitura.** Todos os números abaixo são medidos **só** a partir dos
> artefactos congelados em `results/`. Nada foi afinado para melhorar métricas.
> A ferramenta que os recomputa é `tools/consolidate_fase5.py`
> (saída: `results/fase5_consolidado.json`).

## Protocolo de medição

- **E1** — split temporal honesto: treino = primeiros 70 % de cada run normal,
  teste = últimos 30 % retidos (ver `ids_model.md` §7.1). **Limitação conhecida:**
  os limiares de discretização continuam a ser os da Fase 4, aprendidos com
  **100 %** dos normais — só as transições e a contagem de remetentes são
  reaprendidas no treino.
- **Sem MAC** — a identidade do remetente é `ip` (só o endereço) ou `ip_client`
  (endereço + `client_id`). O MAC existe apenas nos ataques, pelo que serve de
  **rótulo-verdade/oráculo** e nunca entra no detetor.
- **11 de 25 datasets** do artigo implementados:
  `ARR-Req-a1`, `ARR-Res-a1`, `ANEpc-a1..a8`, `ANEc-a1`.
- **Sessão** = `(Service ID, identidade do remetente)`, truncada por 10 s de
  inatividade. Uma sessão é **marcada** se ≥ 1 dos seus pacotes tem
  `final_anomaly` (o gatilho V-C 2 do artigo propaga a anomalia à sessão).

Definições das colunas da tabela principal:

- *TPR pacote* = TP / pacotes de ataque (micro, 11 datasets).
- *FPR pacote (3 normais)* = FP / pacotes normais retidos nos 3 datasets limpos.
- *FPR pacote (normais nos ataques)* = FP / pacotes legítimos **dentro** dos 11
  datasets de ataque.
- *TPR sessão* = sessões contendo ≥ 1 pacote do atacante que ficaram marcadas.
- *FPR sessão (…)* = idem para sessões **só** com tráfego legítimo.
- *TP direta* = pacotes de ataque com hit do Algoritmo 1 (`alert_transition`);
  *TP contágio* = TP marcados só porque a sessão foi marcada (relativos ao TP
  final).
- *% tempo-real / retroativo* = fração das deteções **nos datasets de ataque**
  que são tempo-real (o resto retroativo).

---

## 1. Configurações congeladas

| configuração | TPR pacote | FPR pkt (3 normais) | FPR pkt (normais nos ataques) | TPR sessão | FPR sess (3 normais) | FPR sess (normais nos ataques) | TP direta | TP contágio | % tempo-real | % retroativo |
|---|---|---|---|---|---|---|---|---|---|---|
| `baseline_v1` (mac, **oráculo**, histórico) | 0,664 | 0,000 ¹ | 0,364 | 0,692 | 0,000 ¹ | 0,328 | 4,3 % | 95,7 % | 3,3 | 96,7 |
| `baseline_v2` / `ip` | 1,000 | 0,894 | 0,376 | 1,000 | 0,500 | 0,308 | 2,9 % | 97,1 % | 2,7 | 97,3 |
| `baseline_v2` / `ip_client` | 0,706 | 0,894 | 0,346 | 0,769 | 0,154 | 0,451 | 4,1 % | 95,9 % | 3,4 | 96,6 |
| **`baseline_v3` / `ip`** ² | **0,948** | **0,055** | **0,222** | **1,000** | **0,500** | **0,308** | **3,1 %** | **96,9 %** | **3,3** | **96,7** |
| **`baseline_v3` / `ip_client`** ² | **0,487** | **0,003** | **0,145** | **0,769** | **0,154** | **0,451** | **5,9 %** | **94,1 %** | **5,9** | **94,1** |
| `E3b` / `ip` | 0,960 | 0,655 | 0,227 | 1,000 | 0,722 | 0,308 | 62,1 % | 37,9 % | 50,0 | 50,0 |
| `E3b` / `ip_client` | 0,954 | 0,626 | 0,220 | 1,000 | 0,856 | 0,451 | 62,5 % | 37,5 % | 50,6 | 49,4 |

Constantes da medição: 17 598 pacotes de ataque; 575 318 pacotes normais retidos
(30 %); 13 sessões de ataque.

¹ `baseline_v1` dá **FPR = 0** nos 3 normais por **fuga de treino**: treina e
testa nos *mesmos* pacotes (usa os 1 917 719 pacotes dos normais completos, não os
30 % retidos). É o valor histórico do oráculo, listado só para memória — **não é
comparável** com as linhas com holdout.

² **A configuração principal é `baseline_v3`**, reportada nas duas identidades
(`ip` e `ip_client`). Razões:

1. é a medição **honesta** (E1 + sem MAC): a de `baseline_v1` tem fuga de treino
   e a de `baseline_v2` herda-a parcialmente na retroação literal;
2. usa a janela **T = 3 s** fixada *a priori* (é o TTL do SD medido nas capturas,
   `config/*/ids_*.json`), não escolhida para melhorar números (ver D2,
   `ids_model.md` §10.1);
3. o **Algoritmo 1 de `baseline_v3` é bit-idêntico ao de `baseline_v2`**
   (hashes em `results/baseline_v3/MANIFEST.json`); a única diferença é o
   Algoritmo 2 (janela de retroação);
4. `E3b` é uma **extensão exploratória** (estado de payload por sinal) — a sua
   TPR final sobe, mas a FPR final (~0,65) é inutilizável, pelo que fica como
   diagnóstico e não como configuração a adoptar.

**Como ler a configuração principal.**

- `ip`: TPR final **0,948**, mas a TPR **direta** é só **3,1 %** — 96,9 % do TPR
  vem de **contágio** (a sessão é marcada e arrasta os seus pacotes). O número de
  deteção "real" do Algoritmo 1 é próximo de zero.
- `ip_client`: TPR **0,487** com FPR **0,003** nos 3 normais; é a medição mais
  próxima de um detetor sem MAC — mas paga o TPR com metade dos datasets ANEpc
  com TPR 0 (ver §3).
- A FPR tem **duas leituras** que diferem ~4×: **0,055** nos 3 normais retidos e
  **0,222** nos normais dentro dos ataques. Ambas são honestas; medem tráfego
  diferente.

### Por padrão (configuração principal `baseline_v3 / ip`)

| dataset | TPR dir (Alg. 1) | TPR final | FPR final |
|---|---|---|---|
| ARR-Req-a1 | 0,557 | 0,926 | 0,301 |
| ARR-Res-a1 | 0,000 | 0,136 | 0,052 |
| ANEpc-a1 | 0,005 | 1,000 | 0,123 |
| ANEpc-a2 | 0,000 | 1,000 | 0,228 |
| ANEpc-a3 | 0,036 | 1,000 | 0,267 |
| ANEpc-a4 | 0,000 | 0,976 | 0,118 |
| ANEpc-a5 | 0,001 | 1,000 | 0,141 |
| ANEpc-a6 | 0,000 | 0,962 | 0,188 |
| ANEpc-a7 | 0,007 | 1,000 | 0,131 |
| ANEpc-a8 | 0,002 | 1,000 | 0,127 |
| ANEc-a1 | 0,003 | 0,951 | 0,665 |

Nenhum dos 11 padrões tem TPR = 1 **e** FPR = 0 simultaneamente.

---

## 2. Comparação com o artigo

Alvos do artigo (Sec. VI): **TPR ≈ 0,91**, **FPR ≈ 0,052**, **18 % tempo-real /
82 % retroativo**, **5 de 9 padrões com TPR = 1 e FPR = 0**.

| métrica | artigo | `baseline_v3 / ip` | `baseline_v3 / ip_client` |
|---|---|---|---|
| TPR | 0,91 | 0,948 | 0,487 |
| FPR | 0,052 | 0,055 ³ | 0,003 ³ |
| % tempo-real / retroativo | 18 / 82 | 3,3 / 96,7 | 5,9 / 94,1 |
| padrões TPR = 1 ∧ FPR = 0 | 5 de 9 | **0 de 11** | **0 de 11** |

³ Ambíguo: a nossa FPR tem duas unidades de terreno (0,055 nos 3 normais retidos
vs 0,222 nos normais dentro dos ataques). O artigo não fixa qual; a coincidência
de 0,055 com 0,052 é **fortuna de medição**, não paridade.

**Ressalvas explícitas (a comparação é PARCIAL):**

1. **11 de 25 datasets.** Implementámos 11 (`…-a1`/`ANEpc-a1..a8`); faltam 14
   variantes `(b)`/`(c)` (outro posicionamento do atacante). O conjunto de teste é
   menor e diferente; os totais de TPR/FPR não são o mesmo parâmetro do artigo.
2. **Atacante sem SD.** Nas capturas implementadas o atacante **não** emite SD
   próprio (ver §3), pelo que o gatilho V-C 1 do artigo nunca arma. O item V-C
   1+3 do artigo está, na prática, **não testado** por este conjunto.
3. **Protocolo de medição diferente.** Medimos com hold-out temporal 70/30 e
   **sem MAC**; o artigo não descreve um split temporal nem esconde o MAC do
   detetor. Usar o MAC como identidade mudaria os números (é o oráculo
   `baseline_v1`).
4. **Unidade de medida possivelmente diferente.** O artigo não deixa claro se
   TPR/FPR são por pacote ou por sessão. As nossas duas unidades divergem
   (ex.: `ip_client` FPR 0,003 por pacote vs 0,154 por sessão).
5. **% tempo-real muito abaixo do artigo (3 % vs 18 %).** No artigo 18 % das
   deteções são tempo-real; aqui quase tudo é retroativo (contágio). A razão é a
   TPR direta do Algoritmo 1 ser ~3 % (§1).

**Conclusão da comparação.** A TPR do `ip` fica **acima** do artigo (0,948 vs
0,91) e a FPR(3 normais) praticamente igual (0,055 vs 0,052) — mas **por motivos
errados**: a TPR é quase toda contágio (96,9 %), não deteção direta, e a FPR é
alta em qualquer leitura. As proporções tempo-real/retroativo (3 % vs 18 %) e os
padrões perfeitos (0 de 11 vs 5 de 9) **não** reproduzem o artigo. Não se
reivindica paridade.

---

## 3. Limitações

Cada limitação é acompanhada do **dado** que a sustenta.

### 3.1 Amplificação do gatilho V-C 2 (o problema dominante)

O Algoritmo 1 tem uma FPR muito baixa; a retroação do V-C 2 transforma cada FP em
**sessões inteiras marcadas**.

- `baseline_v2 / ip`: **87 FPs** do Algoritmo 1 nos 3 normais → FPR final por
  pacote **0,894** (amplificação ×700–×9000; `ids_model.md` §9.1).
- Curva de T (`results/exp_R2`), `ip`: literal 1,000/0,894 → T=1 s 0,778/0,020 →
  **T=3 s 0,948/0,055** → T=5 s 0,967/0,069 → T=30 s 1,000/0,225.
- Com T = 3 s a FPR ainda é 0,055 (≈ alvo do artigo) mas o TPR cai de 1,000 para
  0,948: a janela corta o contágio dos dois lados.

Interpretação: a deteção do protocolo é essencialmente **contágio**; o TPR e a
FPR são dois lados do mesmo mecanismo, e não há, neste desenho, um limiar que dê
TPR alto **e** FPR baixa.

### 3.2 ARR-Res-a1 — response payload-idêntico

O ataque repete respostas legítimas (mesmo payload). O estado de payload não o
distingue.

- `baseline_v3 / ip`: TPR direta **0,000**, TPR final 0,136.
- `E3` e `E3b` (per-signal payload state): TPR direta continua **0,000** e final
  0,136 — **sem melhoria nenhuma** (`ids_model.md` §10.2/10.3).

### 3.3 Atacante sem SD → o gatilho de CS (V-C 1) não arma

O número de remetentes por serviço (`CS`) só cresce se o atacante se apresentar
como um remetente **novo**. Nos ataques implementados o atacante reutiliza o IP
(e o `client_id`) do servidor e **não** emite SD próprio.

- `ids_model.md` §8.3: com `ip`, só `ARR-Req-a1` arma CS (`0x1234` 3 vs 2); nos
  outros 10 datasets o CS **não** arma. Com `ip_client`, o CS **nunca** arma.
- Consequência: o gate do artigo (V-C 1 → V-C 3) fica **inerte** (§3.4).

### 3.4 V-C 3 sem contribuição marginal

A condição do V-C 3 (CS excedido **e** intervalo médio da sessão a desviar-se) é
satisfeita **exactamente 1 vez** (em `ARR-Req-a1`), e essa sessão **já tinha sido
marcada pelo V-C 2**.

- Sessões marcadas por V-C 3 (novas) = **0** em `baseline_v2`, `baseline_v3`,
  `E3` e `E3b` (campo `sessoes marcadas por V-C3 (session-interval) = 0` em todos
  os `report.json`).
- O interval check usa `[min, max]` de `dt_prev_res` por tipo; como o `min` é
  ~0, o desvio é **unilateral** (só "demasiado lento"). Um atacante com renovação
  normal não desvia (ver §4, S1).

### 3.5 Cobertura de treino do estado por sinal (custo do E3/E3b)

Estender a tupla com o estado por sinal multiplica o espaço de estados; o split
70/30 deixa combinações sem cobertura.

- E3: 130 → 16 229 estados; FPs do Algoritmo 1 **87 → 14 567**, dos quais
  **13 015 (89,3 %) nunca vistos** e **um único grupo** com 87,5 % (o `seq` do
  ECHO, contador monótono quantizado em tercil global) — um defeito de modelagem.
- E3b (corrigido, `--payload-exclude seq`): 14 567 → **1 553** (×9,4) **sem custo
  de deteção**; classe (iii) **0**; mas **1 535 dos 1 553 (98,8 %) são classe
  (ii)** — estados que existem no modelo de 100 % e que os 70 % de treino não
  cobriram. Maior grupo isolado: **n=9 (0,6 %)**; a contribuição das faixas
  contínuas (`steer`+`speed` = 1 363 causas) é comparável à do timing base
  (1 332) e à das transições de enumerados (1 262).
- Efeito no resultado final: a FPR final quase não melhora (E3 0,677 → E3b 0,655
  no `ip`) — os 1 553 FPs residuais continuam a ser amplificados pelo V-C 2. O
  limite é a **amplificação** (§3.1), não a qualidade do estado.

### 3.6 Limiares aprendidos com 100 % dos normais

O protocolo E1 reaprende só as **transições** e a **contagem de remetentes** no
treino (70 %). Os **limiares de discretização** (bins de tempo e de `ΔP`), da
Fase 4, continuam a vir dos **100 %** dos normais.

- `ids_model.md` §7.1: a FPR honesta é a do E1, mas permanece parcialmente
  optimista/pessimista porque os bins "viram" parte do conjunto de teste.
- Efeito visível: as classes (i)/(ii) de D1a mostram que a FPR do Algoritmo 1 é
  dominada por **cobertura de treino**, não pelo estado ser impossível.

### 3.7 Métricas por sessão têm denominador pequeno

As métricas por sessão assentam em poucos casos (13 sessões de ataque; 18 sessões
normais retidas com `ip`, 104 com `ip_client`), pelo que são **grosseiras**; são
reportadas por completude, não como estimativa estável.

---

## 4. O que o R3 mudaria e o que não mudaria

O **R3** (plano em `attacker_sd_plan.md`, **não implementado**) faria o atacante
emitir o **seu próprio SD** (Offer/Subscribe) a partir de um remetente distinto.
O **S1** (`docs` §10.4; `results/exp_S1_smoke/`; só diagnóstico) testou o
mecanismo por injeção offline sintética de Offer/Subscribe do atacante
(`192.168.1.50`) em `ARR-Req-a1` a 10 %.

### Mudaria

- **Armaria o gatilho de CS (V-C 1).** O serviço `0xFFFF` passa de 2 para **3**
  remetentes (> máximo aprendido 2) e `cs_armed` liga — em `ip` **e** em
  `ip_client`. Dá ao ataque um sinal de CS que hoje **não** tem (§3.3); com
  `ip_client`, é o **único** sinal de CS que existe.
- Em renovação **anormalmente lenta** (testado: 8 s), o **V-C 3** dispara de
  facto (média 8 s > 2,66 s do anchor) e marca a sessão SD inteira — incluindo
  pacotes **fora** da janela T = 3 s.

### Não mudaria

- **A deteção continua a não vir do V-C 1+3.** No teste, o SD injetado do atacante
  **já é um hit do Algoritmo 1** no 2.º pacote (stream nova, médias frias:
  estado `NA|medium|NA|NA|NA|0|1` ∉ modelo), pelo que é o **V-C 2** que marca a
  sessão; `session-interval` (V-C 3) acrescenta **0 sessões novas**.
- **No ritmo realista (ttl/2 = 1,5 s) o V-C 3 não dispara:** 1,5 s cai **dentro**
  do anchor normal `[2,3·10⁻⁵, 2,66]`. Em `sd15`, com T = 3 s, só **8 dos 18**
  pacotes SD ficam marcados (a vizinhança do hit); os **10 da cauda** ficam por
  marcar apesar do CS armado.
- **Não resolve o ARR-Res** (payload-idêntico, §3.2) nem a **amplificação do
  V-C 2** (§3.1). O R3 actua no V-C 1; a patologia dominante é o V-C 2.
- **Não melhora a FPR.** Em todas as variantes do S1 a FPR se manteve nos 0,343
  por pacote (normais do dataset truncado); o R3 acrescenta SD do atacante, não
  remove falsos positivos nos normais.

### Balanço

O R3 torna o IDS **fiel ao artigo** (testa o V-C 1+3, hoje inerte: §3.4) e dá ao
ataque um gatilho de CS que falta (§3.3). Mas, no cenário realista, **não cria um
caminho de deteção novo** (o V-C 2 apanha a sessão SD antes) e **não melhora
TPR/FPR**. O seu valor é **diagnóstico** — verificar o comportamento do artigo —
não de desempenho. Com T = 3 s, o V-C 1+3 só acrescenta valor para renovações
anormalmente lentas ou para estender a marcação a pacotes fora da janela.

---

## 5. Reprodutibilidade

| componente | caminho |
|---|---|
| métricas consolidadas (esta tabela) | `tools/consolidate_fase5.py` → `results/fase5_consolidado.json` |
| `baseline_v1` (oráculo, histórico) | `results/baseline_v1/` |
| `baseline_v2` (E1 + sem MAC) | `results/baseline_v2/` (+ `MANIFEST.json`, `diagnose.json`) |
| `baseline_v3` (T = 3 s, principal) | `results/baseline_v3/` (+ `MANIFEST.json`) |
| `E3b` (payload sem contadores) | `results/exp_E3b/` (+ `diagnose.json`, `per_signal.json`) |
| S1 (smoke do R3) | `results/exp_S1_smoke/` + `tools/smoke_s1_sd_injection.py` |
| algoritmo e decisões | `docs/ids_model.md`, `docs/feature_model.md`, `docs/attacker_sd_plan.md` |

Os diretórios `baseline_v1`/`baseline_v2`/`baseline_v3` são **congelados** (não
sobrescrever). A decisão de implementar o R3 completo (variante β) e de correr as
14 variantes `(b)`/`(c)` em falta **fica pendente**.
