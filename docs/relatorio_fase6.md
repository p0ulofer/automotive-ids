# Fase 6 — Relatório consolidado (modo online do IDS)

Fecho da Fase 6: o que a passagem do IDS de **batch** para **online** provou, que
defeitos encontrou pelo caminho, e o que ficou por decidir. O detalhe técnico
está em [`ids_live.md`](ids_live.md); este relatório é legível por si só.

**Âmbito da fase.** Implementar um **modo de operação em tempo real** do IDS
existente — captura de tráfego ao vivo (scapy), classificação de cada pacote
SOME/IP com os mesmos dois algoritmos do modo offline (Algoritmo 1, Algoritmo 2
com janela retroactiva T = 3 s), com o modelo e os limiares **congelados** do
`baseline_v3` (identidade `ip`, sem payload-state/E3). O modo offline continua
intacto e a ser a referência; nada em `results/baseline_v3/`, `datasets/`,
`features/` ou `docs/relatorio_fase5.md` foi alterado. O objectivo não era
"mais uma interface", era **provar que o detector que valém em batch é o mesmo
que decide ao vivo** — e medir, com honestidade, onde os dois divergem.

---

## 1. O que a Fase 6 provou

### 1.1 Equivalência exacta entre o modo batch e o modo online

O modo online foi confrontado com o `baseline_v3` congelado, **pacote a pacote e
coluna a coluna**, em 6 datasets que cobrem as três famílias de tráfego
(RR, NEpc, NEc) e as duas classes (ataque / normal):

| dataset | família | linhas comparadas | diffs de classificação | métricas |
|---|---|---|---|---|
| `ANEpc-a1` | ataque | 4 135 | **0** | iguais |
| `ARR-Res-a1` | ataque (lado *Response*) | 3 310 | **0** | iguais |
| `ANEc-a1` | ataque | 5 368 | **0** | iguais |
| `normal_rr` | normal (holdout 30 %) | 1 998 | **0** | iguais |
| `normal_nepc` | normal (holdout 30 %) | 76 750 | **0** | iguais |
| `normal_nec` | normal (holdout 30 %) | 496 570 | **0** | iguais |

**Zero diferenças de classificação** em 588 131 linhas. A única divergência em
todo o conjunto é a coluna de metadados `src_mac` — 575 318 células: os CSVs
normais da Fase 2 não têm coluna MAC, e o MAC não entra na identidade `ip`
nem na tupla de estado. É contada à parte, sem afectar nenhum veredito.

Um dataset ficou de fora **por uma razão documentada**: `ARR-Req-a1`, cujo pcap
em disco já não é o da execução congelada (foi substituído por um `--scale 0.10`
e re-gerado; ver `nota_divergencia_arrreqa1.md`). A divergência não foi
escondida: foi corrida e quantificada à parte (19 050 / 21 907 células
divergentes no prefixo comum, com **todas** as timestamps diferentes), e o
relatório marca esse caso como "não comparável" em vez de "0/0".

### 1.2 O bug silencioso que a própria validação apanhou

O primeiro modo online já não batia com o offline — e a causa foi um erro de
**tipo**, não de lógica: a descodificação partilhada devolvia o campo `is_sd`
como `int` (1), enquanto o pipeline offline lê `csv.DictReader`, ou seja
**string** ("1"). A comparação `row["is_sd"] == "1"` falhava, os pacotes SD
passavam a ser tipados como `NOTIFICATION` e as `stream_key` divergiam.

Medido em `ANEpc-a1`, com o bug presente: **4 132 de 4 135 linhas (99,9 %)**
tinham pelo menos uma feature errada, 8 362 células divergentes — e o pior não
era o `stream_key` (47 linhas) nem o `n_cs` (43): eram os **bins**
(`dt_prev_res_bin` errado em 4 126 linhas, `dt_prev_req_bin` em 4 008). Ou
seja, a *tupla de estado discretizada* — o input do Algoritmo 1 — estava errada
em praticamente todas as linhas, e **nenhum teste de sanidade unitário teria
dado por isso**: o IDS continuava a "correr" e a devolver métricas.

A lição é a que justifica a arquitectura da fase: o modo online **não
reimplementa** a lógica de features. A descodificação e o cálculo das features
passaram a ser módulos partilhados (`tools/feature_logic.py`,
`tools/pcap_to_csv.py`), e a equivalência pacote-a-pacote é a rede de segurança
que apanha exactamente este tipo de divergência. Sem ela, a Fase 6 teria
publicado um detector diferente do validado.

---

## 2. O limite de memória/tempo encontrado e a correcção arquitectural

### 2.1 O problema

O motor online retinha os vereditos finais numa **fila global por `idx`**, para
poder escrever o `retro_*.csv` pela mesma ordem do offline. A consequência foi
dupla:

- uma sessão que **nunca fecha** (uma stream periódica mais rápida que o
  timeout de 10 s) ficava a bloquear tudo o que viesse atrás dela
  (*head-of-line blocking*): o veredito das outras streams esperava;
- a fila crescia sem limite — medido ≈ **25 MB/min** (≈ 1,5 GB/h) com o
  `normal_nepc`, porque nenhuma das suas streams chega a ter 10 s de silêncio.

Era, em operação longa, um vazamento de memória — e um atraso de decisão que
não vinha do algoritmo.

### 2.2 A descoberta: a ordem global era um artefacto do comparador

A pergunta certa não era "como ordenar mais depressa", mas "**a ordem global é
mesmo necessária?**". A resposta está no código do offline
(`tools/ids_retroactive.py`): o `retro_*.csv` é escrito numa **passagem final**
sobre o ficheiro de detecção (uma linha retro por linha de entrada, pela mesma
ordem) e a marcação retroactiva é **por sessão** — os hits são os da própria
sessão (`hits[skey]`) e o gatilho V-C 1+3 é um estado por sessão
(`interval_poisoned`). O veredito de uma linha depende **só da sua sessão**, nunca
da ordem global das linhas.

Logo, a ordenação estrita por `idx` era uma **conveniência do comparador de
validação** (que faz diff linha-a-linha contra o baseline congelado), não um
requisito de operação. Um `retro_*.csv` em operação é um **registo de decisões**:
cada linha traz `idx` e `timestamp`, e quem precisar de ordem global reordena.

### 2.3 A solução (e o que deixou de ser necessário)

| | antes | agora |
|---|---|---|
| caminho ao vivo | fila global por `idx` | **emissão por sessão**: cada sessão escreve as suas linhas assim que o seu veredito é definitivo; as linhas de uma sessão ficam contíguas; **sem ordem global** |
| harness de validação | comparava posicionalmente | **ordena por `idx`** as duas tabelas antes de comparar — é o harness que reintroduz a ordem |
| conteúdo de cada linha | — | **inalterado** (a marca é por sessão): os mesmos números, célula a célula |

A eliminação do *head-of-line blocking* resolve o atraso entre streams. Para o
crescimento da memória, a peça que faltava é **`--session-max-age`**: uma
sessão mais antiga que N segundos é **cortada como o EOF faria** (o offline
fecha todas as sessões no fim da captura), o que limita o estado retido ao
tráfego dos últimos N segundos. Com `--session-max-age 60`, o `normal_nepc`
passa de 152 MB para **90 MB** e **71 996 das 76 750 linhas** passam a ser
escritas em fluxo (antes: 0, todas no fim).

**O buffer em disco que estava previsto não foi necessário** — com a emissão por
sessão e o corte por idade, o conjunto pendente fica limitado e nada precisa de
ir para disco.

Complemento: `--session-hold-timeout` (300 s) dá um **tecto rígido** às
sessões que ficam *em espera* (fechadas, mas cujo serviço nunca excedeu os CSs,
pelo que o gatilho V-C 1+3 nunca pode disparar) — sem ele, ficariam retidas
para sempre. O caminho é exercitado por um **auto-teste incluído no relatório
de validação** (10/10 passos), porque nos datasets avaliados raramente dispara.

---

## 3. O efeito real do `--session-max-age`, quando formalizado

A variante de operação de longa duração foi **formalizada com o mesmo padrão
de evidência** dos restantes casos (o validador corre o motor com o corte
activo e regista o resultado no relatório). E a formalização **corrigiu uma
afirmação nossa**: o corte não mexe "só em metadata".

| dataset | realtime | retro: colunas do A1 | retro: colunas do A2 | métricas (TPR / FPR) |
|---|---|---|---|---|
| `ANEpc-a1` (21 s) | 0 | 0 | 0 | inalteradas |
| `ARR-Res-a1` (154 s) | 0 | **0** | **488** (51 linhas) | 0,136→0,101 · 0,052→0,042 |
| `ANEc-a1` (23 s) | 0 | 0 | 0 | inalteradas |
| `normal_rr` (93 s) | 0 | 0 | 0 | inalteradas |
| `normal_nepc` (384 s) | 0 | 0 | 0 | inalteradas |
| `normal_nec` (2 135 s) | 0 | **0** | **1 926** (642 linhas) | FPR 0,063→0,061 |

**Mecanismo (verificado linha a linha):** cortar uma sessão **parte a janela
retroactiva V-C 2**. Em `ARR-Res-a1` os hits do atacante chegam a cada ~60 s e o
corte cai ~0,45 s depois de um hit: as 51 linhas seguintes do atacante (cada
100 ms) estavam marcadas `realtime-window` no baseline — o hit estava na mesma
sessão — e deixam de estar, porque o hit ficou do outro lado da fronteira. O
efeito é **localizado na fronteira** (linhas a menos de T = 3 s do corte) e
**direccionado**: só se perdem marcas, nunca se ganham (tp −26, fp −25).

Isto **não invalida a equivalência por omissão** (`--session-max-age 0`, que
continua exacto, 0/0). É um **trade-off explícito para operação longa** —
documentado, medido e com o critério formal no relatório — e não um defeito.
Paga-se uma alteração marginal das métricas (em `ARR-Res-a1`, TPR −3,5 pp e FPR
−1,0 pp; em `normal_nec`, FPR −0,13 pp; nos dois casos por *perder* marcações) em
troca de memória limitada e de vereditos que saem em fluxo. Quem precisar de memória limitada **e** de
equivalência exacta tem de escolher conscientemente; o default é a
equivalência.

---

## 4. Jitter real de rede (Estágio B) e o efeito no FPR

O Estágio A prova a **lógica**; o Estágio B mede o que acontece quando o mesmo
tráfego passa por uma **stack de rede real** — os timestamps são os de
*captura*, e o jitter de agendamento entra nas features discretizadas.

**Montagem.** Dois contentores ligados por um **par veth directo**; o emissor
reenvia o pcap por socket raw com o **temporismo original** (dorme até ao
instante previsto de cada pacote, com um último passo em busy-wait para
precisão de sub-milissegundo) e mede o seu próprio jitter; o receptor corre o
IDS em modo online (`--interface`) e a comparação com o baseline é feita depois.

Duas armadilhas do teste ficaram documentadas porque mascaram o resultado:

1. **O host reencaminha as tramas.** Com `net.ipv4.ip_forward=1`, as tramas cujo
   IP de destino está na sub-rede da bridge voltam a entrar no contentor — o
   receptor via **cada trama duas vezes** (3 060 mensagens extra). Daí o link
   veth directo: a stack IP do host fica fora do caminho.
2. **Os timestamps do pcap estão no passado** (o dataset é de Outubro): o replay
   tem de rebasear a linha temporal, senão envia tudo de seguida, sem cadência.

**Resultado** (mesma montagem, 2 datasets):

| | `ANEpc-a1` (4 135 msgs) | `ARR-Res-a1` (3 310 msgs) |
|---|---|---|
| jitter de captura (mediana / p95 / máx) | 0,082 / 0,527 / 18,0 ms | 0,114 / 0,375 / 28,9 ms |
| `dt_prev_res` diferente do congelado | 4 109 / 4 126 linhas (mediana 0,096 ms) | 3 286 / 3 303 (0,067 ms) |
| `state` (tupla discretizada) divergente | **10** (0,24 %) | **2** (0,06 %) |
| alertas do Algoritmo 1 | 26 → **29** | 7 → **9** |
| linhas reclassificadas pelo Algoritmo 2 | **314** (7,6 %) | **40** (1,2 %) |
| TPR | 1,000 → **1,000** | 0,1356 → **0,1356** |
| FPR | 0,123 → **0,254** | 0,052 → **0,067** |

**Mecanismo:** o jitter de ~0,1 ms medido no receptor altera o `dt_prev_res`; em
0,06–0,24 % das linhas esse valor cruza um limiar de discretização e o `state`
muda; em 2–3 dessas linhas a transição deixa de existir no modelo e nasce um
**alerta extra**. O Algoritmo 2 **amplifica**: cada hit novo contamina a janela
de T = 3 s da sua sessão, e é isso que produz 1–8 % de linhas reclassificadas.

Duas conclusões:

- o caminho ao vivo **não** é bit-idêntico ao offline, e **não deve ser** — a
  única forma de o ser seria um relógio virtual, que é precisamente o que se
  queria evitar medir. A divergência é pequena, reproduzível e explicada;
- a **margem operacional do modelo é da ordem de 0,1 ms** (as features
  discretizadas são sensíveis a essa escala) e o **factor de risco real é a
  amplificação do V-C 2**, muito maior do que o jitter em si. A TPR não se
  alterou em nenhum dos datasets; a FPR sobe (0,123→0,254 no caso mais
  severo) porque os alertas extra caem em tráfego normal.

---

## 5. O que isto deixa para o texto final

**O que a Fase 6 acrescenta ao resultado do artigo:** o IDS deixa de ser um
artefacto de batch e passa a ter uma implementação online **verificada
equivalente** ao modelo validado, com o comportamento em operação longa
**medido** (limites de tempo e memória com tetos rígidos e auto-teste) e o
**comportamento em rede real quantificado** (jitter → 0,06–0,24 % de linhas com
estado discretizado diferente → 1–8 % de linhas reclassificadas pela
retroacção).

**Limitações que subsistem e devem ser ditas:** (i) a equivalência é exacta
apenas com o modo de captura determinístico — em rede real há divergência,
medida e caracterizada; (ii) o corte de sessão por idade (`--session-max-age`)
altera marginalmente as métricas, por corte da janela retroactiva — é um
trade-off explícito, não o comportamento por omissão; (iii) o
`ARR-Req-a1` disponível em disco não é o da execução congelada e por isso não
entra na validação de equivalência (a divergência está quantificada à parte).

**Reprodução.** `python3 tools/validate_ids_live.py --normal normal_rr
--normal normal_nepc --normal normal_nec` (equivalência + variante
`--session-max-age` + auto-teste) e `./scripts/stage_b_live_replay.sh
ANEpc-a1` (Estágio B). Detalhe de comandos, arquitectura e latências em
[`ids_live.md`](ids_live.md); o modelo e os protocolos em
[`ids_model.md`](ids_model.md).
