# Fase 5 — Modelo IDS (Algoritmo 1 + Algoritmo 2)

Documento dos dois algoritmos de deteção de Koyama et al., *"SOME/IP Intrusion
Detection System Using Real-Time and Retroactive Anomaly Detection"*
(VTC2022-Spring), Sec. V-B (deteção em tempo real) e Sec. V-C (deteção
retroativa), tal como implementados em `tools/ids_realtime.py`,
`tools/ids_retroactive.py` e `tools/evaluate_ids.py`.

Implementação e avaliação: Fase 5. Treino: **somente** os 3 datasets normais da
Fase 2 (`normal_rr`, `normal_nepc`, `normal_nec`). Os limiares de discretização
(`features/thresholds.json`) são os da Fase 4 — **não são reaprendidos aqui**.
Teste: os 11 datasets de ataque da Fase 3 + os 3 normais (para FPR sobre tráfego
limpo; a FPR sobre os 3 normais é otimista por fuga de treino — ver §5.3).

---

## 1. Algoritmo 1 — deteção em tempo real (Sec. V-B, Figs. 7 e 8)

### 1.1 Tupla de estado ("transição", Fig. 7)

Para cada pacote, a Fase 4 já calculou as features da Tabela IV **relativas ao
pacote anterior da mesma `stream_key`**. Formalizamos aqui a "transição" como a
tupla discretizada dessas features — não se recalcula nada:

```
estado = (dt_prev_req_bin, dt_prev_res_bin, dt_prev_req_avg_bin,
          dt_prev_res_avg_bin, dp_prev_req, dp_prev_res, os)
```

* `dt_prev_req_bin` / `dt_prev_res_bin` — bins `short`/`medium`/`long` da Fase 4.
* `dt_prev_req_avg_bin` / `dt_prev_res_avg_bin` — as médias móveis ficaram
  contínuas na Fase 4, mas a Tabela IV lista-as; discretizamo-las com os
  **mesmos** limiares da respetiva feature dT (por `service|tipo`).
* `dp_prev_req` / `dp_prev_res` — 0/1 (com/sem mudança nos campos contínuos).
* `os` — ordem do Session-ID (0/1); **`NA`** nas 2 `stream_keys` excluídas pela
  decisão pré-Fase 5 (ver §5.1).
* Componentes estruturalmente ausentes (ex.: `dt_prev_req` para SD, primeiro
  pacote de uma stream) ficam a `NA`, de forma estável entre treino e deteção.

### 1.2 Porque `n_cs` (Fase 4) não entra na tupla

O `n_cs` da Fase 4 conta `stream_key`s distintas por serviço. Incluí-lo na tupla
faria com que **todos** os pacotes posteriores a uma subida do contador
(ex.: `n_cs` 3→4 num ataque, que depois persiste) fossem marcados como
transição desconhecida — o que se mediu como falsos positivos em massa. Além
disso, o artigo trata o número de CSs **separadamente** (fluxo da Fig. 8). Por
isso `n_cs` é verificado no gatilho de CS (§2), não na tupla.

### 1.3 Tabela de transições permitidas

No treino, regista-se o conjunto de tuplas observadas por `(Service ID, tipo de
mensagem)`. Cada `tipo` é o da Fase 4 (`REQUEST`/`RESPONSE`/`NOTIFICATION` ou
`SD:Offer`/`SD:Find`/`SD:Subscribe`/`SD:SubAck`). Nº de transições únicas por
chave: 6–16 (`results/realtime_model_use.json`).

### 1.4 Observação/deteção

Para cada pacote (em ordem temporal):

* `dt_prev_res` vazio ⇒ **primeiro pacote da stream**: não há transição para
  comparar (Fig. 8: início de sessão); `checkable=False`, sem alerta.
* Caso contrário, se a tupla **não existe** na tabela do seu `service|tipo` ⇒
  alerta **`transition`** (anomalia de pacote; entra no TPR/FPR do Algoritmo 1).
* `cs_armed` — sinal de serviço (não de pacote), ver §2.

### 1.5 Variante de arranque da média móvel (`--avg-cold-start`)

A média móvel sobre menos de `W=10` amostras é pouco representativa. Duas
variantes, ambas disponíveis e reportadas:

* `use` (default) — usa o bin da média sempre que existe.
* `na` — trata os bins das médias como `NA` enquanto a janela não estiver
  completa (menos de `W` amostras), **no treino e na deteção**, com o contador
  de posição da stream reiniciado por captura.

---

## 2. Número de CSs — definição adotada (decisão de projeto)

O artigo define CS como *"the number of concurrent service subscription ECUs"*.
O `n_cs` da Fase 4 (nº de `stream_key`s) **não** serve para este gatilho, por
três razões medidas em `ARR-Req-a1`:

| regra | pacotes de ataque marcados | pacotes normais marcados |
|---|---|---|
| literal `n_cs > máximo` (por pacote) | 550 | **1 823** (inutilizável) |
| `stream_key` nova **E** `n_cs > máximo` | 0 | 1 |
| **adotada:** nº de remetentes distintos (IP+MAC) por serviço | limpo | 0 |

O problema do `n_cs` é de **ordenação**: em `ARR-Req-a1` a stream do atacante
abre quando `n_cs` vai 2→3 (não excede o máximo 3); o contador só chega a 4
quando abre a 4.ª chave — que aqui é a stream **NOTIFICATION normal** do
servidor. A contagem de remetentes (IP+MAC) é a do artigo (nº de ECUs); no
treino dá 2 por serviço (`max_senders`), e em `ARR-Req-a1` dá 3 para 0x1234.

**`cs_armed`** = verdadeiro a partir do momento em que o nº de remetentes do
serviço excede o máximo aprendido. **Não marca nenhum pacote** — apenas arma a
avaliação retroativa (§3, gatilho V-C 1+3).

---

## 3. Algoritmo 2 — deteção retroativa (Sec. V-C)

### 3.1 Definição de "sessão"

O artigo não fixa a sessão numericamente. Adotamos:

> **sessão = (Service ID, IP de origem, MAC de origem)** — o "remetente"/ECU do
> artigo —, truncada por um **timeout de inatividade** `SESSION_TIMEOUT = 10 s`
> (default; parâmetro de `ids_retroactive.py`). A sessão termina no fim da
> captura ou após esse intervalo sem pacotes do mesmo remetente.

Nas 14 capturas atuais **não há cortes** (os maiores intervalos intra-sessão são
~5 s, nos clientes 0x1235/0x1236). Incluir o MAC na chave de sessão permite
separar o servidor legítimo do atacante que **impersona o IP do servidor** com
MAC diferente (padrão usado nos datasets ANEpc/ANEc e nas responses fabricadas
de `ARR-Req-a1`).

### 3.2 Gatilhos

| Gatilho do artigo | Chave no output | Implementação |
|---|---|---|
| V-C 2 — pacote marcado em tempo real | `realtime` | Um pacote com `alert_transition` marca **toda a sessão**: todos os anteriores e todos os seguintes (o artigo: *"all past packets … all future packets received from the same sender"*). |
| V-C 1+3 — nº anómalo de CSs + fim de sessão | `session-interval` | `cs_armed` do serviço **E** o intervalo médio da sessão desviar do modelo normal ⇒ marca a sessão inteira. |

O desvio de intervalo (V-C 3) é avaliado **por tipo de mensagem dentro da
sessão**: para cada tipo, compara-se a média de `dt_prev_res` da sessão com os
anchors `[min, max]` da Fase 4 dessa `service|tipo`. Isto evita colar o
intervalo bimodal de uma sessão servidor (responses a ~0,1 s + notifications a
~30 s), que de outro modo dispararia falsos positivos. A decisão do utilizador
foi explícita: **o gatilho de CS não marca sozinho** — só a combinação CS
excedido **E** intervalo desviante marca (V-C 3).

Pacotes cuja transição existe no modelo permanecem "normais temporários" até a
avaliação de fim de sessão (Fig. 8).

---

## 4. Separação treino/teste e métricas

* **Treino:** `normal_rr`, `normal_nepc`, `normal_nec` (mesma divisão da Fase 4).
* **Teste:** os 11 ataques (`ARR-Req-a1`, `ARR-Res-a1`, `ANEpc-a1..a8`,
  `ANEc-a1`) + os 3 normais. TPR/FPR são por pacote (label 1 = frame emitido
  pelo atacante, por MAC).
* Métricas por dataset, agregadas (micro e macro), por categoria
  (ARR-Req/ARR-Res/ANEpc/ANEc), proporção tempo-real/retroativo e comparação com
  os alvos do artigo (`results/evaluation_report.json`).

---

## 5. Limitações (herdadas da Fase 4 e de projeto)

### 5.1 Exclusão da feature `os` (Fase 4)
Decisão registada em `features/MANIFEST.json`: `os` é `NA` nas `stream_keys`
`0x1235|NOTIFICATION|192.168.2.4` e `0x1236|NOTIFICATION|192.168.2.4` (contador
de Session-ID partilhado entre serviços → baseline saturada). Afeta estas
avaliações: a ordem do Session-ID não contribui para essas chaves. Note-se que o
atacante que impersona o servidor reutiliza **a mesma string de `stream_key`**
(IP igual), pelo que a exclusão também se aplica às notificações atacantes.

### 5.2 ΔP categórico saturado (Fase 4)
`dp_prev_*` (com/sem mudança) está saturado a ~1 no tráfego normal destes
serviços (contadores/sinusoides mudam sempre). Consequência direta: ataques que
**só** alteram valores de payload (ANEpc/ANEc) e respostas fabricadas
`ARR-Res-a1` **não** são separáveis por ΔP — o TPR do Algoritmo 1 nesses casos é
~0. O sinal está nas magnitudes `dp_prev_*_l1`, que **não** entram na tupla (a
Tabela IV discretiza ΔP a dois valores).

### 5.3 Bins de dT grosseiros
`long` é ilimitado superiormente; o intervalo do cliente atacante (0,3 s) cai no
mesmo bin `long` que valores normais ocasionais (0,13–0,18 s), e `long` aparece
no treino. O sinal de temporização acaba por vir sobretudo dos **bins das
médias**, que também geram falsos positivos de arranque/quando o atacante
contamina a média de uma stream partilhada.

### 5.4 `n_cs` da Fase 4 conta streams, não ECUs
Ver §2: não é usado no gatilho de CS adotado.

### 5.5 Dependência de IP/MAC distintos (limitação da opção adotada)
O gatilho de CS (nº de remetentes por IP+MAC) e a separação de sessões por MAC
**dependem de o atacante ter IP e/ou MAC distintos dos legítimos**. O artigo
assume um atacante que **conhece** MACs/IPs válidos e pode transmitir por
impersonação; este laboratório **não cobre** esse caso (o atacante emite com o
seu próprio MAC, base da etiquetagem `label=1`). Um atacante que falsifique MAC
e IP não seria detetado por este gatilho.

### 5.6 FPR sobre os 3 normais é otimista
Os 3 normais servem de treino **e** teste; a FPR sobre eles é ~0 por construção
(fuga). A FPR reportada como primária é a dos **pacotes normais dentro dos
datasets de ataque**, que não sofre essa fuga.

### 5.7 Amplificação pelo gatilho V-C 2
O gatilho "marcar toda a sessão do mesmo remetente" transforma **qualquer** falso
positivo do Algoritmo 1 numa sessão inteira marcada. Como as sessões têm
centenas a milhares de pacotes, a FPR agregada sobe de ~0,8 % (Algoritmo 1) para
~36 % (com retroativo). Ver §6.5.

---

## 6. Resultados (resumo; ver `results/evaluation_report.json`)

11 ataques, 17 598 pacotes de ataque, 27 384 normais (dentro dos ataques).

| | Algoritmo 1 | Algoritmo 1+2 |
|---|---|---|
| TPR (micro) | 0,029 | 0,664 |
| FPR (micro, normais dentro dos ataques) | 0,008 | 0,364 |
| macro TPR/FPR | 0,055 / 0,008 | 0,636 / 0,353 |

Por categoria (Algoritmo 1+2): ARR-Req TPR 1,00 / FPR 0,39; ARR-Res 0,00 / 0,37;
ANEpc 0,62 / 0,29; ANEc 1,00 / 0,83.

Proporção tempo-real/retroativo: **3,3 % / 96,7 %** (alvo do artigo: 18 % / 82 %).

### 6.1 Comparação com o artigo (parcial)
O artigo reporta TPR ~0,91 e FPR ~0,052, 5 dos 9 padrões com TPR=1/FPR=0, e
18 %/82 %. Temos **11 dos 25 datasets** do artigo (conjunto menor e diferente) —
a comparação é qualitativa, não se procura paridade numérica. Nenhum dos nossos
11 datasets atinge TPR=1 & FPR=0.

### 6.2 TPR — o padrão do artigo repete-se
O artigo identifica impersonação MITM (RR) e ataques de NE(c) como difíceis.
Confirmamos: `ARR-Res-a1` (respostas fabricadas, payload/timing plausíveis) tem
TPR 0 no Algoritmo 1; `ARR-Req-a1` só é apanhado retroativamente (imunidade do
cliente atacante vem do CS/intervalo), e as respostas fabricadas só via V-C 2.

### 6.3 FPR e o gatilho V-C 2
Toda a FPR retroativa vem do gatilho V-C 2 (0 sessões marcadas por
`session-interval`). 30 sessões marcadas; 211 FP do Algoritmo 1 → 9 955 FP
finais (amplificação ~47×). A causa-raiz é a FPR não-nula do Algoritmo 1 sobre
streams partilhadas com o atacante.

### 6.4 Variante `avg-cold-start`
`use` e `na` dão resultados praticamente idênticos no agregado (TPR 0,664 em
ambos; FPR 0,364 vs 0,371). Em `ARR-Req-a1`, `na` reduz a FPR do Algoritmo 1 de
0,034 para 0,032 (4 falsos positivos de arranque), mas a FPR final mantém-se
0,386 nos dois casos (uma só marcação de sessão basta).

### 6.5 Nota
Estes números são o resultado **sem ajuste de parâmetros**. Estão longe dos
valores-alvo do artigo; ficam reportados e discutidos como resultado, não
corrigidos por afinação silenciosa de limiares.

---

## 7. Experimentos de validade (E1 e E2)

Baseline congelado em `results/baseline_v1/` (não sobrescrever). Cada experimento
foi corrido **isoladamente** sobre esse baseline
(`tools/evaluate_ids.py --identity ... --holdout ... --results-dir results/exp_*`).

### 7.1 E1 — FPR honesta (split temporal 70/30)

Treino = primeiros 70% de cada run normal; teste = últimos 30% retidos (gaps
temporais; os timestamps são monotónicos). **Limitação conhecida: os limiares de
discretização continuam a ser os da Fase 4, aprendidos com 100% dos normais** —
só o modelo de transições e a contagem de remetentes são reaprendidos no treino.

| métrica | baseline_v1 | E1 (holdout 30 %) |
|---|---|---|
| TPR (micro, 11 ataques) | 0,664 | 0,664 |
| FPR (normais **dentro** dos ataques) | 0,364 | 0,376 |
| **FPR (3 normais retidos)** | 0,000 | **0,894** |

A FPR de 0,000 do baseline era **fuga de treino** (treina e testa nos mesmos
pacotes). Com um split honesto, a FPR sobre tráfego limpo retido é **~89 %**
(`normal_rr` 0,047 · `normal_nepc` 0,252 · `normal_nec` 0,997). A causa é a mesma
do §5.7: a FPR do Algoritmo 1 continua baixa (~0,02 %), mas o gatilho V-C 2
transforma uns ~100 falsos positivos em sessões inteiras marcadas.

### 7.2 E2 — identidade do remetente sem MAC

A identidade do remetente usa `--identity`: `mac` (oráculo — o MAC só existe nos
ataques, nunca nos normais), `ip` (só IP) e `ip_client` (IP + `client_id`).
Nota: o **baseline_v1 já era, de facto, o cenário-oráculo** — treinava com
`(ip, "")` (os normais não têm `src_mac`) e detetava com `(ip, mac)`.

| métrica | baseline_v1 (oráculo) | E2 `ip` | E2 `ip_client` |
|---|---|---|---|
| TPR (micro) | 0,664 | **1,000** | 0,706 |
| FPR (normais nos ataques) | 0,364 | 0,364 | 0,333 |
| ARR-Res TPR / FPR | 0,00 / 0,37 | 1,00 / 0,37 | 1,00 / 0,37 |
| ANEpc TPR / FPR | 0,62 / 0,29 | 1,00 / 0,29 | 0,62 / 0,24 |
| % tempo-real / retroativo | 3,3 / 96,7 | 2,6 / 97,4 | 3,3 / 96,7 |

**O ganho de TPR do `ip` não é deteção genuína.** Quando o atacante impersona o
servidor (mesmo IP), a sessão `(serviço, IP)` funde o tráfego legítimo com o do
atacante; um único FP do Algoritmo 1 em pacotes legítimos envenena a sessão
fundida e arrasta também os pacotes do atacante. Ex.: `ARR-Res-a1`, sessão
`0x1234|192.168.2.4` = 787 legítimos + 745 do atacante → marcada; `ANEpc-a4`,
sessão `0x1235|192.168.2.4` = 284 legítimos + 1738 do atacante → marcada. A FPR
não melhora (é a mesma dos pacotes legítimos dessas sessões).

Com `ip_client`, a notificação do servidor (`client_id 0x0000`) fica numa sessão
separada das respostas (`0x1001`); como o número de remetentes **não aumenta**
(normal já tem 3 identidades por serviço), o CS nunca arma e os ataques de
payload (ANEpc) voltam a TPR 0 nos datasets em que a sessão de notificação não
tem nenhum hit do Algoritmo 1 (`a2`, `a4`, `a6`). Confirma o §5.5: sem MAC (e com
o atacante a partilhar IP/`client_id`), o detetor não separa o atacante.

Estes números de FPR de E2 são medidos com o protocolo do baseline (fuga de
treino); a FPR honesta continua a ser a de E1 (§7.1).

## 8. baseline_v2, diagnóstico (D1), métricas por sessão (M1) e experiência E4

A partir daqui **toda** a medição usa o protocolo E1 (split temporal holdout
70/30, §7.1) **e** identidade do remetente **sem MAC** (§7.2), reportando `ip` e
`ip_client`. O MAC passa a ser **apenas** o rótulo-verdade/oráculo e nunca entra
no detetor. Este protocolo foi congelado em `results/baseline_v2/`
(não sobrescrever; `results/baseline_v2/MANIFEST.json`).

Scripts: `tools/evaluate_ids.py --holdout 0.3 --identity ...` (avaliação) e
`tools/diagnose_ids.py` (D1a/D1b/M1a/M1b, só leitura dos CSVs por-pacote).

### 8.1 baseline_v2 (referência)

| métrica | `ip` | `ip_client` |
|---|---|---|
| TPR (micro, 11 ataques) | 1,000 | 0,706 |
| FPR (normais **dentro** dos ataques) | 0,376 | 0,346 |
| FPR (3 normais retidos) | 0,894 | 0,894 |
| macro TPR / FPR | 1,000 / 0,365 | 0,727 / 0,334 |
| ARR-Req TPR / FPR | 1,00 / 0,442 | 1,00 / 0,442 |
| ARR-Res TPR / FPR | 1,00 / 0,372 | 1,00 / 0,371 |
| ANEpc TPR / FPR | 1,00 / 0,296 | 0,62 / 0,252 |
| ANEc TPR / FPR | 1,00 / 0,842 | 1,00 / 0,842 |
| % tempo-real / retroativo | 2,7 / 97,3 | 3,4 / 96,6 |
| sessões marcadas por V-C3 (novas) | 0 | 0 |

Nota: o TPR de 1,000 do `ip` **não é deteção genuína** (§7.2); o `ip_client`
aproxima-se mais do que um detetor sem MAC consegue separar.

### 8.2 D1a — de onde vêm os falsos positivos do Algoritmo 1 (holdout)

No holdout dos 3 normais há **87 falsos positivos do Algoritmo 1** (não do
resultado final): `normal_rr` 1 · `normal_nepc` 3 · `normal_nec` 83 (a FPR do
Algoritmo 1 é ~0,02 %; é o gatilho V-C 2 que os amplifica, §5.7). A classificação
de cada FP (a tupla de estado é independente da identidade, logo isto vale para
`ip` e `ip_client`):

| classe | nº | definição |
|---|---|---|
| **(ii) no treino de 100 % mas não nos 70 %** | **86** | a tupla existe no modelo dos 100 % mas ficou de fora da amostra de treino dos 70 % |
| (i) arranque da média móvel (`avg_full=0`) | 1 | a janela W=10 ainda não estava completa (e essa tupla também existe nos 100 %) |
| (iii) nunca vista em nenhum treino | 0 | — |

**Domina a classe (ii): 86 de 87 (99 %).** Não é um artefacto de arranque: são
transições raras que só ocorrem no segmento retido — p.ex.
`0x1235|RESPONSE state=medium|medium|medium|long|0|1|0` (35×),
`0x1235|RESPONSE state=medium|long|medium|long|0|1|0` (8×),
`0x1236|REQUEST state=long|long|medium|medium|1|1|0` (8×). A posição temporal é
dispersa (ex.: [497 s, 1679 s] numa captura de 7100 s), não concentrada no
início. Conclusão: com treino honesto, a FPR residual do Algoritmo 1 é dominada
por **cobertura de treino insuficiente para estados raros**, não por má
calibração de arranque.

### 8.3 D1b — o atacante estabelece sessão SD?

Em **todos os 11** datasets de ataque, os pacotes SD (Subscribe/Offer/SubAck)
têm `label=0` e vêm dos MAC legítimos; **0 pacotes SD têm o MAC do atacante**
(ex.: `ARR-Req-a1` 213 SD, todas legítimas; `ANEc-a1` 60; `ANEpc-*` 44–51). O
`ecu6` **não estabelece** sessão SD com servidor/cliente — ao contrário do
atacante MITM da Sec. IV-A do artigo, que se regista via SD. Aqui o atacante só
**encaminha/adultera** o tráfego SOME/IP *a seguir* ao handshake SD legítimo.

Isto explica porque o gatilho de CS quase nunca arma. O nº de remetentes por
serviço, face ao máximo aprendido nos normais:

| dataset | `ip` (máx vs normais) | `ip_client` (máx vs normais) | CS arma? |
|---|---|---|---|
| ARR-Req-a1 | 0x1234: **3** vs 2 | 0x1234: **4** vs 2 | **sim** |
| ARR-Res-a1 | 0x1234: 2 vs 2 | 0x1234: 3 vs 3 | não |
| ANEpc-* | 0x1235: 2 vs 2 | 0x1235: 3 vs 3 | não |
| ANEc-a1 | 0x1234/5/6: 2 vs 2 | 0x1235/6: 3 vs 3 | não |

Como o atacante NE/Res reutiliza o **IP do servidor** (e, com `ip_client`, o
`client_id` do servidor) e não faz SD próprio, o número de remetentes **não
cresce** — o CS não arma. Só `ARR-Req-a1` arma (o atacante-cliente usa um IP
novo). Sem MAC, o atacante que se faz passar pelo servidor é invisível a este
gatilho.

### 8.4 M1a — deteção "direta" vs "por contágio"

"Direta" = o próprio pacote teve hit do Algoritmo 1 (`alert_transition`);
"contágio" = marcado só porque a sessão foi marcada (§5.7).

| | `ip` | `ip_client` |
|---|---|---|
| TP diretos | 508 (2,9 %) | 508 (2,9 %) |
| TP por contágio | 17 090 (97,1 %) | 11 916 (97,1 %) |
| FP diretos (normais nos ataques) | 232 (2,3 %) | 232 (2,5 %) |
| FP por contágio | 10 073 (97,7 %) | 9 232 (97,5 %) |
| contágio-TP com sessão envenenada por pacote **de ataque** | 11 171 | 11 171 |
| contágio-TP com sessão envenenada por pacote **normal** | **5 919** | 745 |
| contágio-FP com sessão envenenada por pacote normal | 5 720 | 4 887 |

Com `ip`, **5 919 dos TP por contágio (34 % de todos os TP) só são marcados
porque um pacote *legítimo* fez um FP do Algoritmo 1** e envenenou a sessão
fundida. O caso-limite é `ARR-Res-a1`: a sessão mista `0x1234|192.168.2.4` tem
`hits1=0` (nenhum pacote do atacante é "direto") e `hits0=4` — o TPR de 1,0 vem
inteiramente de FPs legítimos. Com `ip_client`, a notificação fica separada e o
efeito cai (745), mas em `ANEpc-a2/a4/a6` a sessão do atacante não tem sequer
contágio (`marked=False`) → TPR 0.

### 8.5 M1b — métricas por sessão

Sessões classificadas por composição (`n0`=pacotes legítimos, `n1`=pacotes do
atacante) e "marcada" = a sessão inteira foi assinalada.

| classe de sessão | `ip` | `ip_client` |
|---|---|---|
| ataques puras marcadas | 1/1 | 1/1 |
| normais puras marcadas | 16/52 | 32/71 |
| mistas (legítimo+atacante) marcadas | 12/12 | 9/12 |

As sessões **mistas** (listadas em `results/baseline_v2/diagnose.json`,
`M1.*.mixed_sessions`) são o problema de fundo: são exactamente as sessões em que
o atacante partilha o remetente com tráfego legítimo; como quase todas são
marcadas, o TPR por sessão parece bom, mas a custa de marcar dezenas de milhares
de pacotes legítimos. Não há nenhuma sessão de ataque **pura** para além de uma
(com `ip`, o atacante-cliente de `ARR-Req-a1`).

### 8.6 E4 — sessões delimitadas por eventos SD

Semântica SOME/IP-SD implementada (`tools/ids_realtime.py` →
`sd_service_boundaries`, `tools/ids_retroactive.py --session-source sd`): um
Offer/Subscribe com TTL>0 **renova** a concessão do serviço até `ts+TTL`; um
StopOffer/StopSubscribe (TTL=0) fecha a sessão; se a concessão expirar sem
renovação, a sessão termina aí. A regra "pacotes futuros do mesmo remetente são
anómalos" (V-C 2) fica limitada ao fim da sessão.

Observado nas capturas: renovações a cada ~1 s com **TTL = 3 s** → a concessão
está **sempre** coberta; apenas os StopOffer/StopSubscribe (no fim da captura, e
um no início em `ARR-Req-a1`/`ANEc-a1`) e as expirações geram fronteiras. Logo o
SD delimita sessões **menos** fragmentadas que o timeout de 10 s, não mais.

| métrica | `ip` bv2 → E4 | `ip_client` bv2 → E4 |
|---|---|---|
| TPR (micro) | 1,000 → 1,000 | 0,706 → 0,706 |
| FPR (ataques) | 0,3763 → 0,3763 | 0,3456 → 0,3457 |
| FPR (3 normais) | 0,8943 → 0,8943 | 0,8942 → 0,8943 |
| macro FPR | 0,3654 → 0,3654 | 0,3337 → 0,3338 |
| ARR-Req FPR | 0,4420 → 0,4420 | 0,4416 → 0,4420 |
| ARR-Res FPR | 0,3715 → 0,3715 | 0,3708 → 0,3715 |
| ANEpc TPR / FPR | 1,00/0,296 → 1,00/0,296 | 0,624/0,252 → 0,624/0,252 |
| sessões (total) | 83 → 83 | **188 → 101** |
| sessões marcadas | 38 → 38 | **58 → 50** |
| **V-C3 (novas sessões)** | **0 → 0** | **0 → 0** |

`results/exp_E4/E4_vs_baseline_v2.json`.

**V-C 3 dispara 0 vezes** em ambos os protocolos. A condição (CS armado **e**
intervalo médio da sessão a desviar-se) é satisfeita **exactamente 1 vez** — na
sessão de `ARR-Req-a1` — mas essa sessão **já tinha sido envenenada por V-C 2**;
o `poison()` não reconta, logo a contribuição marginal de V-C 3 é nula. Isto
é igual em baseline_v2 e E4.

**Porque é que E4 não muda nada (e piora uma fracção)?**
* Com `ip`, as streams (por IP) nunca têm intervalos >10 s, portanto as sessões
  do timeout **já** coincidiam com as sessões SD → E4 é idêntico (0 datasets com
  diferença).
* Com `ip_client`, as streams `(ip, client_id)` são esparsas (um `client_id` só
  usado em respostas pode ter gaps >10 s): o timeout fragmentava-as em até 78
  sessões (`normal_nec`) e o SD funde-as em 11. Menos sessões = contágio mais
  grosso → FPR sobe uma fracção (0,3456→0,3457; `ARR-Res` 0,3708→0,3715). O TPR
  não muda (o contágio já era o mecanismo).
* O limite "futuro do mesmo remetente até ao fim da sessão" não altera nada
  porque as sessões não foram *divididas* pelo SD nestas capturas.

### 8.7 Leitura conjunta

Com o protocolo honesto (E1) e sem MAC, o detetor marca ~97 % dos ataques em
retroativo, mas fá-lo sobretudo por **contágio** a partir de FPs do Algoritmo 1
em pacotes legítimos (5 919/17 598 dos TP com `ip`; FPR final ~0,89 em tráfego
limpo). O gatilho de CS quase nunca arma (o atacante não faz SD e partilha o
remetente) e o V-C 3 nunca acrescenta deteção. As direções úteis a seguir são
(a) alargar o treino para cobrir estados raros (D1a-classe ii) e (b) o estado de
payload por sinal (E3, ainda não implementado), que ataca precisamente os ataques
ANEpc onde o Algoritmo 1 tem TPR 0 sem contágio.

## 9. R1 (treino mais justo) e R2 (curva de amplificação do V-C 2)

Ferramentas novas: `tools/experiment_r1.py` (regimes de treino) e
`tools/experiment_r2.py` (janela de retroação). Nada do detetor foi escolhido
por estes resultados.

### 9.1 R1 — quanto da FPR é cobertura de treino vs amplificação do V-C 2

| regime | A1 FP | FPR(A1) | FPR final | amplificação | TPR final |
|---|---|---|---|---|---|
| baseline_v2 70/30 (`ip`) | 87 | 0,000151 | **0,894** | ×5 914 | 1,000 |
| holdout 90/10 (`ip`) | 19 | 0,000099 | **0,894** | ×9 019 | 1,000 |
| holdout 90/10 (`ip_client`) | 19 | 0,000099 | **0,893** | ×9 011 | 0,706 |
| 5 blocos, treino em 4 (`ip`) | 1 108 | 0,000578 | **0,407** | ×704 | 1,000 |
| 5 blocos, treino em 4 (`ip_client`) | 1 108 | 0,000578 | **0,379** | ×656 | 0,765 |

Os 5 blocos (por fold, `ip`):

| fold (teste) | A1 FP | FPR(A1) | FPR final |
|---|---|---|---|
| 0 (1.º quinto) | 1 084 | 0,00283 | **1,000** |
| 1 | 0 | 0,00000 | 0,000 |
| 2 | 1 | 0,00000 | 0,002 |
| 3 | 2 | 0,00001 | 0,139 |
| 4 (último quinto) | 21 | 0,00005 | 0,894 |

**Resposta à pergunta:** a FPR de 0,89 **não é cobertura de treino** — é
**amplificação do gatilho V-C 2**. A FPR do Algoritmo 1 é 0,01 % (70/30) e cai
para ~0,010 % com 90 % de treino (87→19 FP, −78 %); a FPR final fica **igual**
(0,894→0,894). A amplificação é de ~700× a ~9 000×: cada FP (a) fecha uma sessão
inteira, e (b) as sessões têm milhares de pacotes. Logo o que domina o 0,89 é o
**tamanho da sessão marcada**, não a taxa de FP do Algoritmo 1.

A CV de 5 blocos mostra ainda **assimetria temporal**: testar o **1.º** quinto
(treinando nos 4 seguintes) explode (FPR(A1)=0,28 %, FPR final=100 %) — e estes
FPs **não** são arranque de média móvel (só 116/1084 têm `avg_full=0`); são
estados iniciais genuínos fora da amostra de treino. Fica assim confirmada a
classe (ii) de D1a: é **cobertura**, mas num patamar ~0,1 % que, sem amplificação,
seria irrelevante.

### 9.2 R2 — retroação com janela T (isolada, vs baseline_v2)

Contágio limitado a `|ts − ts_hit| ≤ T` (o hit continua sempre "direto").
`literal` reproduz o baseline_v2 exactamente (validação do refactor).

`ip`:

| T | TPR | FPR(ataques) | FPR(normais) | TP direta/total | TP contágio (origem ataque/normal) |
|---|---|---|---|---|---|
| literal | 1,000 | 0,3763 | 0,8943 | 508 (2,9 %) | 11 171 / 5 919 |
| 1 s | 0,778 | 0,1419 | **0,0203** | 508 (3,7 %) | 8 921 / 4 267 |
| 5 s | 0,967 | 0,2498 | **0,0691** | 508 (3,0 %) | 11 168 / 5 338 |
| 30 s | 1,000 | 0,3688 | **0,2245** | 508 (2,9 %) | 11 171 / 5 919 |

`ip_client`:

| T | TPR | FPR(ataques) | FPR(normais) | TP direta/total | TP contágio (origem ataque/normal) |
|---|---|---|---|---|---|
| literal | 0,706 | 0,3456 | 0,8942 | 508 (4,1 %) | 11 171 / 745 |
| 1 s | 0,273 | 0,0730 | **0,0011** | 508 (10,6 %) | 4 288 / 6 |
| 5 s | 0,548 | 0,1800 | **0,0050** | 508 (5,3 %) | 9 105 / 25 |
| 30 s | 0,672 | 0,3152 | **0,0298** | 508 (4,3 %) | 11 171 / 145 |

Observações (a decisão do T fica para o utilizador; a curva completa está em
`results/exp_R2/*/report.json`):
- A janela **corta exactamente a amplificação**, e a curva TPR/FPR é monótona.
  T=1 s faz cair a FPR em tráfego limpo de 0,894 para 0,020 (`ip`) e 0,001
  (`ip_client`), pagando com TPR 0,78/0,27.
- Com `ip_client`, a janela **elimina o contágio de origem normal** (745→6 a
  1 s): o TPR que sobra é quase todo de origem de ataque (~4 288). Com `ip`, há
  sempre contágio de origem normal (4 267 a 1 s) porque as sessões estão fundidas.
- Cada hit é "direto", logo a métrica **por sessão** é insensível a T (uma sessão
  continua "marcada" se contiver o hit): `ip` 16/52 normais e 12/12 mistas em
  todas as T; `ip_client` 32/71 e 9/12. Só a métrica **por pacote** muda com T.

### 9.3 R3

Plano (não implementado) em [`attacker_sd_plan.md`](attacker_sd_plan.md).
Smoke test de mecanismo (S1, só diagnóstico) em §10.4: simula o SD do atacante e
mostra que o gatilho de CS arma, mas que V-C 1+3 só dispara com renovação lenta.

## 10. D2 (baseline_v3, T = 3 s), E3/E3b (estado por sinal do payload) e S1 (smoke R3)

### 10.1 D2 — janela a priori T = 3 s (baseline_v3)

T = 3 s é fixado **antes** de ver o resultado, por critério físico: é o TTL do
SD medido na captura (`config/*/ids_*.json`, `ttl=3`). 1 / 5 / 30 s ficam só
como sensibilidade. Curva do R2 (`results/exp_R2/*/report.json`):

`ip`:

| T | TPR | FPR(ataques) | FPR(normais) |
|---|---|---|---|
| literal | 1,000 | 0,3763 | 0,8943 |
| 1 s | 0,778 | 0,1419 | 0,0203 |
| **3 s** | **0,948** | **0,2222** | **0,0546** |
| 5 s | 0,967 | 0,2498 | 0,0691 |
| 30 s | 1,000 | 0,3688 | 0,2245 |

`ip_client`:

| T | TPR | FPR(ataques) | FPR(normais) |
|---|---|---|---|
| literal | 0,706 | 0,3456 | 0,8942 |
| 1 s | 0,273 | 0,0730 | 0,0011 |
| **3 s** | **0,487** | **0,1446** | **0,0030** |
| 5 s | 0,548 | 0,1800 | 0,0050 |
| 30 s | 0,672 | 0,3152 | 0,0298 |

**`baseline_v3`** congelado em `results/baseline_v3/` (MANIFEST incluído):
E1 (holdout 70/30) + V-C 2 com T = 3 s + identidades `ip` / `ip_client`. O
Algoritmo 1 é **bit-idêntico** ao `baseline_v2` (verificado: hash das transições
e coluna `alert_transition` dos CSVs iguais) — a mudança é só o Algoritmo 2.

| métrica | `ip` | `ip_client` |
|---|---|---|
| TPR final (micro) | 0,9477 | 0,4866 |
| FPR final (3 normais retidos) | 0,0546 | 0,0030 |
| FPR final (normais nos ataques) | 0,2222 | 0,1446 |
| deteções tempo-real | 3,3 % | 5,9 % |
| deteções retroativas | 96,7 % | 94,1 % |

Por categoria (TPR / FPR final):

| categoria | `ip` | `ip_client` |
|---|---|---|
| ARR-Req | 0,9255 / 0,3011 | 0,8889 / 0,2644 |
| ARR-Res | 0,1356 / 0,0519 | 0,0201 / 0,0152 |
| ANEpc | 0,9923 / 0,1652 | 0,4713 / 0,1032 |
| ANEc | 0,9512 / 0,6652 | 0,5978 / 0,4191 |

FPR por fold dos 5 blocos com T = 3 s (`results/exp_R1/blocks5T3_*/report.json`),
comparada com a do literal (§9.1):

| fold | A1 FP | fin_FPR literal | fin_FPR **T=3 s** |
|---|---|---|---|
| 0 (1.º quinto) | 1 084 | **1,000** | **0,0216** |
| 1 | 0 | 0,000 | 0,0000 |
| 2 | 1 | 0,002 | 0,0002 |
| 3 | 2 | 0,139 | 0,0018 |
| 4 (último quinto) | 21 | 0,894 | 0,0104 |
| pooled (`ip`) | 1 108 | 0,407 | **0,0068** (amplif. ×11,8) |
| pooled (`ip_client`) | 1 108 | 0,379 | **0,0044** (amplif. ×7,6) |

A janela **elimina a catástrofe do fold 0** (1,000 → 0,0216): com T = 3 s o
contágio deixa de arrastar a sessão inteira. A FPR do Algoritmo 1 não muda
(1 084 FPs no fold 0 continuam lá) — muda só o quanto cada FP arrasta.

### 10.2 E3 — estado por sinal do payload (implementação: `feature_model.md` §7)

Tupla estendida com o estado por sinal do payload (aprendido só nos normais),
sobre `baseline_v3` (T = 3 s). Efeito no **modelo**: 130 → 16 229 estados
(`0x1235|NOTIFICATION` 15 → 8 090).

`E3` vs `baseline_v3` (`results/exp_E3/E3_vs_baseline_v3.json`):

| métrica | `ip` b3 → E3 | `ip_client` b3 → E3 |
|---|---|---|
| A1 FP (normais holdout) | 87 → **14 567** (×167) | 87 → **14 567** |
| A1 FPR (sobre checkable) | 0,000151 → **0,025320** | 0,000151 → **0,025320** |
| TPR direta (Alg. 1) | 0,0289 → **0,5963** | 0,0289 → **0,5963** |
| TPR final (micro) | 0,9477 → 0,9603 | 0,4866 → **0,9539** |
| FPR final (3 normais) | 0,0546 → **0,6771** | 0,0030 → **0,6482** |
| FPR final (normais nos ataques) | 0,2222 → 0,2270 | 0,1446 → 0,2201 |
| % deteções tempo-real | 3,3 → **50,0** | 5,9 → **50,6** |

Por categoria (TPR direta → TPR final / FPR final):

| categoria | `ip` dir | `ip` fin TPR / FPR | `ip_client` dir | `ip_client` fin TPR / FPR |
|---|---|---|---|---|
| ARR-Req | 0,5569 → 0,5569 | 0,9255 → 0,9255 / 0,3011 | 0,5569 → 0,5569 | 0,8889 → 0,8889 / 0,2644 |
| ARR-Res | 0,0000 → 0,0000 | 0,1356 → 0,1356 / 0,0519 | 0,0000 → 0,0000 | 0,0201 → 0,0201 / 0,0152 |
| ANEpc | 0,0065 → **0,6167** | 0,9923 → **1,0000** / 0,1664 | 0,0065 → **0,6167** | 0,4713 → **1,0000** / 0,1664 |
| ANEc | 0,0034 → **0,6780** | 0,9512 → **1,0000** / 0,7018 | 0,0034 → **0,6780** | 0,5978 → **1,0000** / 0,7011 |

Leitura:

- E3 faz exactamente o que se pretendia **na deteção directa dos ataques de
  payload**: ANEpc e ANEc passam de ~0,5 % para ~62–68 % de pacotes detectados
  pelo Algoritmo 1, e o TPR final das duas categorias chega a **1,000** nas duas
  identidades (o `ip_client` deixa de depender do contágio). As deteções
  passam de ~3–6 % para ~50 % em tempo real.
- **ARR-Res não melhora nada** (0,0000 → 0,0000): é o ataque de response
  payload-idêntico; o estado de payload não o distingue (limitação já conhecida,
  `feature_model.md` §4).
- **ARR-Req também não muda**: já era detectado por timing (0,5569 direto).
- O custo é uma **explosão de falsos positivos**: 87 → 14 567 (+16 600 %), FPR
  do Algoritmo 1 de 0,015 % para 2,53 %, e a FPR final nos 3 normais de 0,055 →
  **0,677** (`ip`) e 0,003 → **0,648** (`ip_client`). Ou seja, E3 troca
  contágio por ruído: o TPR final sobe mas a FPR final fica inutilizável.

**Distribuição por classe dos FP do Algoritmo 1 (D1a, como pedido).**
`results/exp_E3/diagnose.json` (contra o modelo E3 de 100 %):

| classe | baseline_v2 | E3 | % dos FP E3 |
|---|---|---|---|
| (i) arranque da média móvel | 1 | 18 | 0,1 % |
| (ii) em 100 % mas não em 70 % | 86 | 1 534 | 10,5 % |
| (iii) nunca visto | 0 | **13 015** | **89,3 %** |
| **total** | **87** | **14 567** | |

E há **um único grupo dominante**: `0x1234|REQUEST`,
`short|short|short|short|1|1|1|seq:1|seq:high`, **n = 12 754** (87,5 % de todos
os FP), todo em `normal_nepc` no intervalo `idx[203 164, 255 826]` (o fim da
captura). É um sinal **contínuo** (`seq`, o contador do ECHO) quantizado numa
faixa ("high") aprendida como tercil **global**: como o contador é monótono
dentro de uma captura, qualquer troço retido cujo contador caia fora da gama
dos trechos de treino é sistematicamente "nunca visto".

Não proponho correção aqui (só diagnóstico, como pedido). Registo duas
observações de método: (a) os `payload_bands` do modelo de 70 % e do de 100 %
são aprendidos em amostras diferentes, pelo que a classe (iii) está ligeiramente
inflada por fronteiras de faixa diferentes — mas o grupo dominante (`seq:high`)
é explicado pelo contador relativo à captura, não pela fronteira; (b) as classes
(i)/(ii) mantêm a leitura de D1a: cobertura de treino é secundária.

### 10.3 E3b — exclusão dos contadores monótonos do estado de payload

Correcção isolada do **defeito de modelagem** identificado em §10.2, sobre
`baseline_v3` (T = 3 s, mesmo protocolo E1 70/30 + no-MAC). Exclui-se `seq`
(contador do ECHO) e só ele — lista e justificação em `feature_model.md` §7.4.
Implementação: `--payload-exclude seq`.

**(a) FP do Algoritmo 1 e classes D1a** (normais do holdout, `results/exp_E3b/diagnose.json`):

| | baseline_v3 | E3 | **E3b** |
|---|---|---|---|
| A1 FP (total) | 87 | 14 567 | **1 553** |
| A1 FPR (sobre checkable) | 0,000151 | 0,025320 | **0,002699** |
| (i) arranque da média móvel | 1 | 18 | **18** |
| (ii) em 100 % mas não em 70 % | 86 | 1 534 | **1 535** |
| (iii) nunca visto | 0 | 13 015 | **0** |

O grupo dominante do E3 **desaparece**: a classe (iii) vai de 13 015 a **0** —
ou seja, *todos* os FP "nunca vistos" do E3 eram o `seq` do ECHO (o grupo
`0x1234|REQUEST ...|seq:1|seq:high`, n = 12 754, mais as restantes combinações de
faixa do mesmo contador). O que resta são 18 FPs de arranque e 1 535 estados que
**existem** no modelo de 100 % (classe ii): não são estado "impossível", é
cobertura de treino em falta (o split 70/30 não viu aquela combinação).

**(b) TPR direta e TPR/FPR final por categoria** (`E3b_vs_baseline_v3.json`):

| métrica | `ip` b3 → E3 → **E3b** | `ip_client` b3 → E3 → **E3b** |
|---|---|---|
| TPR direta (Alg. 1) | 0,0289 → 0,5963 → **0,5963** | 0,0289 → 0,5963 → **0,5963** |
| TPR final (micro) | 0,9477 → 0,9603 → **0,9603** | 0,4866 → 0,9539 → **0,9539** |
| FPR final (3 normais) | 0,0546 → 0,6771 → **0,6548** | 0,0030 → 0,6482 → **0,6259** |
| FPR final (normais nos ataques) | 0,2222 → 0,2270 → **0,2270** | 0,1446 → 0,2201 → **0,2201** |
| % deteções tempo-real | 3,3 → 50,0 → **50,0** | 5,9 → 50,6 → **50,6** |

Por categoria (TPR direta → TPR final / FPR final), `ip` = `ip_client` no direto:

| categoria | `ip` E3b dir | `ip` E3b fin TPR/FPR | `ip_client` E3b fin TPR/FPR |
|---|---|---|---|
| ARR-Req | 0,5569 | 0,9255 / 0,3011 | 0,8889 / 0,2644 |
| ARR-Res | 0,0000 | 0,1356 / 0,0519 | 0,0201 / 0,0152 |
| ANEpc | 0,6167 | 1,0000 / 0,1664 | 1,0000 / 0,1664 |
| ANEc | 0,6780 | 1,0000 / 0,7018 | 1,0000 / 0,7011 |

**Leitura.** A correção do defeito é eficaz: retira **13 014 dos 14 567 FPs**
(×9,4; FPR do Algoritmo 1 2,53 % → 0,27 %) **sem custo nenhum na deteção** (TPR
direta e final idênticos ao E3, por categoria também). O TPR final de ANEpc/ANEc
continua 1,000 e o `ip_client` continua a deixar de depender do contágio.

Mas **a FPR final quase não melhora** (0,677 → 0,655 no `ip`; 0,648 → 0,626 no
`ip_client`): os 1 553 FPs restantes, espalhados no tempo, continuam a envenenar
sessões inteiras via V-C 2 (a amplificação ×700–×9000 já medida em §9.1). Ou
seja, o `seq` era o defeito *de modelagem*, mas o que mantém a FPR final alta é a
**amplificação** (o mesmo problema de fundo de §9.1), não a qualidade do estado.

**(c) distribuição por sinal dos FP restantes** (`results/exp_E3b/per_signal.json`).
Atribuição por *causa suficiente* contra o modelo de 70 %: para cada FP e cada
posição da tupla, verifica-se se existe um estado de treino que coincide em
**todas** as outras posições (trocar só essa posição "repara" o FP).

| causa (sinal.tipo) | n de FPs em que é causa suficiente |
|---|---|
| `steer.band` (faixa de sinal contínuo) | 874 |
| `gear.trans` (transição de enumerado) | 833 |
| `dt_prev_req_avg_bin` (**base**, média móvel) | 670 |
| `dt_prev_req_bin` (**base**, timing) | 662 |
| `speed.band` (faixa de sinal contínuo) | 489 |
| `turn.trans` | 386 |
| `speed.chg` | 217 |
| `dt_prev_res_avg_bin` (base) | 56 |
| `acc.trans` | 43 |
| `dt_prev_res_bin` (base) | 20 |
| `dp_prev_res`, `mode.trans` | 2 / 1 |

Distribuição de **faixa** nos FP (sinais contínuos), vs tercil de treino (~⅓ cada):

| sinal | low | mid | high |
|---|---|---|---|
| `speed` | 617 | **1 695 (58 %)** | 594 |
| `steer` | 1 099 (38 %) | 839 | 968 |

Razões de contagem (1443 dos 1535 FP de classe ii têm ≥ 1 causa suficiente;
110 são multi-componente; o maior grupo isolado tem n = 9, ou seja **0,6 %** dos
FP).

**Resposta à pergunta (c): não**, os FP restantes já **não** são dominados por
faixas de tercil de sinais contínuos. Dois factos:

1. **Classe (iii) = 0.** Nenhum FP é um estado ausente do modelo de 100 %;
   portanto já não há um "tercil global" a criar sistematicamente estados
   impossíveis. Os FP restantes são **classe (ii)** — estados que existem nos
   normais completos mas que o subconjunto de treino (70 %) não cobriu: é
   cobertura de amostragem, não modelagem.
2. **Nenhum grupo domina.** O maior grupo é 0,6 %; a contribuição das faixas
   contínuas (`steer.band` + `speed.band` = 1 363) é **comparável** à das
   componentes base de timing (`dt_prev_req*_bin` = 1 332) e à das transições de
   enumerados (`gear` 833, `turn` 386, `acc` 43). Há uma sobre-representação
   moderada de `speed=mid` (58 % vs 33 %) que registo, mas não é um grupo
   dominante nem um estado impossível.

Registo a distribuição e **paro** (como pedido): não proponho nem aplico outra
correção. Fica claro que o que resta não se corrige removendo sinais — corrige-se
com mais cobertura de treino ou atacando a amplificação do V-C 2 (§9.1).

### 10.4 S1 — smoke test do R3 (SD do atacante), só diagnóstico

Teste de mecanismo, **não** é um dataset publicado. Injeção *offline* sintética
(não se correram contentores; não se tocaram `datasets/` nem o baseline):
`tools/smoke_s1_sd_injection.py` injeta Offer/Subscribe do **atacante**
(`src_ip=192.168.1.50`, `src_mac=ae:10:c5:48:47:b3`, i.e. o MAC do atacante de
`ARR-Req-a1`) em `ARR-Req-a1` truncado a 10 % da duração (`--scale 0.10`);
Fase 4 com os limiares existentes e Fase 5 com os modelos de `baseline_v3`
(T = 3 s). Artefactos: `results/exp_S1_smoke/` (resumo + CSVs brutos injetados),
variantes `ctrl` (sem SD do atacante), `sd15` (renovação 1,5 s = ttl/2) e `sd80`
(8 s).

**(1) O gatilho de CS (V-C 1) arma?** Sim. A contagem de remetentes do serviço
`0xFFFF` passa de 2 para 3 (> máximo aprendido 2) apenas com o SD do atacante:

| identidade | variante | `0xFFFF` (remetentes vs máx) | CS armado |
|---|---|---|---|
| `ip` | ctrl | 2 vs 2 | — |
| `ip` | sd15 / sd80 | 3 vs 2 | **0xFFFF** |
| `ip_client` | ctrl | 2 vs 2 | — |
| `ip_client` | sd15 / sd80 | 3 vs 2 | **0xFFFF** |

Nota lateral: com `ip_client` o atacante de `ARR-Req-a1`, sozinho, **não** arma
CS (`0x1234` fica 3 vs 3); é o SD injetado que cria o único sinal de CS. Ou seja,
o R3 dá a este ataque um gatilho que o ataque puro não tem.

**(2) O caminho V-C 1+3 dispara?** Depende do intervalo de renovação — e no caso
realista **não**:

| variante | sessão SD do atacante | intervalo médio | desvia? | gatilho que a marca |
|---|---|---|---|---|
| sd15 (1,5 s) | `0xFFFF\|192.168.1.50#0` | 1,500 s | **não** | `realtime`/`realtime-window` (V-C 2) |
| sd80 (8 s) | `0xFFFF\|192.168.1.50#0` | 8,000 s | **sim** | `realtime` **e** `session-interval` (V-C 3) |

O *anchor* normal de `0xFFFF|SD:Offer` é `[2,3·10⁻⁵, 2,66]`. Com renovação a
ttl/2 = 1,5 s o intervalo médio cai **dentro** da banda normal → V-C 3 não
dispara; só com uma renovação anormalmente lenta (8 s) é que o desvio existe.
Como o `min` do anchor é ~0, o desvio é **unilateral** na prática: só "demasiado
lento" desvia ("demasiado rápido" é impossível numa média).

**(3) Resultado que interessa para o R3.** Independentemente de V-C 3, o SD
injetado do atacante **já é um hit do Algoritmo 1** no seu 2.º pacote:

| pacote | estado (tupla) | no modelo? | Alg. 1 |
|---|---|---|---|
| 1.º (stream nova, médias frias) | `NA\|NA\|NA\|NA\|NA\|NA\|NA` | não | 0 |
| 2.º (1,5 s) | `NA\|medium\|NA\|NA\|NA\|0\|1` | **não** | **1** |
| 3.º+ (médias estabilizadas) | `NA\|medium\|NA\|medium\|NA\|0\|1` | sim | 0 |

O 2.º pacote tem `dt_prev_res_avg_bin = NA` (médias ainda frias numa stream nova)
combinado com `dt_prev_res_bin = medium`; essa combinação não foi vista nos
normais (as streams SD normais são *bursty*, com intervalos `short` ou já com
média cheia) → é hit. Consequência: **V-C 2 marca a sessão de qualquer maneira**,
pelo que **V-C 1+3 não acrescenta nenhuma sessão nova** (`session-interval` = 0).
O que V-C 3 faz de útil no `sd80` é marcar os 2 primeiros pacotes, que estão
**fora** da janela T = 3 s em torno do hit.

Com T = 3 s, a marcação do SD do atacante em `sd15` fica **limitada à vizinhança
do único hit**: 8 dos 18 pacotes SD ficam marcados (os que estão a ≤ 3 s do hit);
os 10 restantes (a cauda da sessão) ficam **por marcar**, apesar de o serviço
`0xFFFF` ter o CS armado. É exactamente a lacuna que o item V-C 1+3 do artigo
devia cobrir — e que falha quando o atacante renova ao ritmo normal.

**Números finais** (`results/exp_S1_smoke/S1_summary.json`):

| identidade | variante | sessões | V-C 3 (marca) | TP / FP finais |
|---|---|---|---|---|
| `ip` | ctrl | 5 | 1 | 92/92 (TPR 1,000) · 85/248 (FPR 0,343) |
| `ip` | sd15 | 6 | **1** | 100/110 (0,909) · 85/248 (0,343) |
| `ip` | sd80 | 6 | **2** | 96/96 (1,000) · 85/248 (0,343) |
| `ip_client` | ctrl | 5 | 0 | 92/92 (1,000) · 85/248 (0,343) |
| `ip_client` | sd15 | 6 | **0** | 100/110 (0,909) · 85/248 (0,343) |
| `ip_client` | sd80 | 6 | **1** | 96/96 (1,000) · 85/248 (0,343) |

(O TPR de `sd15` < 1 é só o efeito das 10 caudas SD por marcar descritas acima;
os 92 pacotes do ataque de `ARR-Req-a1` continuam todos marcados. A FPR não muda
em nenhuma variante.)

**Conclusões do S1** (para a decisão de implementar o R3 completo): o R3 cumpre a
hipótese de **armar o CS** (o atacante passa a ter o seu próprio remetente SD),
mas o caminho V-C 1+3 do artigo, tal como implementado, **não é quem apanha** o
atacante num caso realista (renovação normal) — o SD do atacante cai primeiro no
Algoritmo 1 e é o V-C 2 que marca. O valor marginal de V-C 3 existe apenas para
renovações anormalmente lentas (ou para estender a marcação a pacotes fora da
janela T). Ressalva: o hit do Algoritmo 1 no SD injetado depende de a stream do
atacante ser **nova e isolada** (médias frias); um atacante que reutilize uma
identidade de remetente existente não produziria este hit — mas é precisamente
a premissa do R3 que o remetente SD do atacante é distinto.

---

## 11. Modo online (Fase 6) — ver `ids_live.md`

A Fase 6 acrescenta um **modo de operação em tempo real** (`tools/ids_live.py`)
que captura tráfego ao vivo (scapy) e classifica cada pacote SOME/IP com os
**mesmos dois algoritmos** documentados neste documento, na configuração
congelada `baseline_v3` / identidade `ip`, **sem payload-state (E3)** e com a
janela retroactiva **T = 3 s** (§10.1).

O modo offline continua a existir e a ser a referência: nada em
`results/baseline_v3/`, `datasets/*`, `features/*` ou neste documento foi
alterado pela Fase 6.

Pontos que tocam este documento:

| tópico deste documento | equivalente no modo online |
|---|---|
| §1.1 tupla de estado | idêntica; calculada por `ids_common.state_tuple` sobre as mesmas features |
| §1.5 `avg-cold-start` | idêntico (`use`), agora por stream recém-vista em vez de por CSV |
| §3.1 definição de sessão (timeout 10 s) | idêntica; implementada incrementalmente (`expiry_heap`). Diferença: no online **não há fim de captura** — uma sessão que nunca fica inactiva nunca fecha (`ids_live.md` §5.3) |
| §3.2 gatilhos V-C 1+3 e V-C 2 | idênticos; o V-C 2 usa a janela T = 3 s do §10.1 |
| §5 cold start / primeiros pacotes | idêntico, documentado em `ids_live.md` §4 |

**Teto de tempo/memória (só no online):** uma sessão **fechada** cujo serviço
nunca excede os CSs ficaria em espera para sempre; existe o teto rígido
`--session-hold-timeout` (**300 s**, `0` = desligar) que a finaliza **sem** o
gatilho V-C 1+3 e liberta o estado (`ids_live.md` §5.1, auto-teste 10/10 no
relatório de validação). Uma sessão que nunca fica inactiva nunca fecha — o
`--session-max-age` corta-a como o EOF faria (`ids_live.md` §5.3).

**Ordem de saída:** o `retro_*.csv` do modo online vai por ordem de **decisão**
(sessão fechada), sem ordem global por `idx`. Isto é correcto porque a marca
retroativa é **por sessão** (como no offline, §3.2: `hits[skey]`,
`interval_poisoned`): o veredito de uma linha não depende da ordem das outras.
Quem precisar de ordem global reordena pelo `idx` — é o que faz o comparador
de validação (`ids_live.md` §5.2).

**Não duplicar lógica:** as features de transição (dt, médias W = 10, bins,
`n_cs`, `os`, `dp`) estão em `tools/feature_logic.py`, **partilhado** entre o
`extract_features.py` (offline) e o `ids_live.py` (online). A descodificação
SOME/IP está partilhada em `pcap_to_csv.packet_to_rows`.

**Latência de decisão (inerente ao Algoritmo 2):** o veredito final de um pacote
não é imediato — V-C 2 exige segurar até **T = 3 s** (um hit futuro pode marcar
pacotes anteriores da mesma sessão) e V-C 1+3 exige esperar pelo **fim da
sessão** (timeout de 10 s). Ver `ids_live.md` §3.

**Validação de equivalência:** o modo online foi confrontado com o `baseline_v3`
congelado, pacote a pacote (`tools/validate_ids_live.py`, artefacto em
`results/ids_live_validation/report.json`, `ok: true`): **0 diferenças** em
3 ataques — `ANEpc-a1` (4 135 linhas, byte-idêntico), `ARR-Res-a1` (3 310, lado
ARR *Response*) e `ANEc-a1` (5 368) — e em 2 normais com holdout — `normal_rr`
(1 998) e `normal_nepc` (76 750), estes dois só com `src_mac` de metadado
(ausente nos CSVs normais da Fase 2 e não usado por `identity=ip`).
`ARR-Req-a1` não serve para este teste porque o pcap em disco já não é o da
execução congelada; a divergência foi **corrida e quantificada** à parte em
`report_arrreqa1.json` (19 050 / 21 907 diffs no prefixo comum, todas as
`timestamp` diferentes) — ver `nota_divergencia_arrreqa1.md` e `ids_live.md`
§6.2.

**Validação ao vivo (Estágio B):** o mesmo tráfego reenviado por uma stack de
rede real (`scripts/stage_b_live_replay.sh`) **não** é bit-idêntico — e não deve
ser. Medido: jitter de captura mediana 0,082 ms (p95 0,527 ms) → 10 de 4 135
linhas mudam de `state` discretizado → 3 alertas extra → **314 linhas**
reclassificadas pelo Algoritmo 2; TPR 1,000 → 1,000, FPR 0,123 → 0,254. A
margem operacional do modelo é, portanto, da ordem de 0,1 ms — e a amplificação
do V-C 2 (§5.7) é o factor de risco real. Ver `ids_live.md` §8.

Arquitetura, latência, cold start, limites de memória e como correr a demo:
**[`ids_live.md`](ids_live.md)**.


