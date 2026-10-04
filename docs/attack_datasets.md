# Fase 3 — Datasets de ataque (Koyama et al., VTC2022-Spring)

> **Estado: TABELA APROVADA pelo utilizador (conta contra a Tabela II verificada de forma independente).**
> Decisões registadas: (1) 3.º set de `Request (c)` = repetição de variante existente sobre **outro sinal do payload** (premissa de projeto, §7.2); (2) volumes da Tabela III em interpretação **(A)** — total da linha dividido proporcionalmente pelos sets da linha (§5.2).
> Fonte: T. Koyama, M. Tanaka, A. Miyajima, S. Ukai, T. Sugashima, M. Egawa,
> *"SOME/IP Intrusion Detection System Using Real-Time and Retroactive Anomaly Detection"*,
> 2022 IEEE 95th VTC (VTC2022-Spring), pp. 1–7. DOI: `10.1109/VTC2022-Spring54318.2022.9860928`.
> PDF local (na raiz do projeto, fora do git): `2022 SOME_IP_Intrusion_Detection_System_Using_Real-Time_and_Retroactive_Anomaly_Detection - Takuma Koyama et. al.pdf`.
> Conteúdo seguinte extraído de Sec. IV (Figs. 1–6, Tabelas I–III); anotações em `[ ]` são perguntas/hipóteses nossas.

---

## 1. Padrões de ataque (Figs. 1–3 do artigo)

Legenda do artigo: **azul = fluxo normal**, **vermelho tracejado = fluxo de ataque**.
Cada figura aplica-se a uma direção de mensagem e tem 3 variantes: **(a) MITM**, **(b) Anomaly (attack) only**, **(c) Normal & anomaly (attack)**.

### Fig. 1 — Notification Events (fluxo servidor → cliente)
| Variante | Desenho do artigo | Significado |
|---|---|---|
| (a) MITM | `Server ↔ Relay (Attacker) ↔ Client` | Atacante relaya/ARP-spoofa entre servidor e cliente legítimos |
| (b) Anomaly only | `Server (Attacker) → Client` | **Só** pacotes do servidor do atacante (servidor normal substituído) |
| (c) Normal & anomaly | `Server → Client` + `Server (Attacker) → Client` | Pacotes do servidor normal **e** do servidor do atacante chegam ao cliente |

### Fig. 2 — Requests (fluxo cliente → servidor)
| Variante | Desenho do artigo | Significado |
|---|---|---|
| (a) MITM | `Client ↔ Relay (Attacker) ↔ Server` | Atacante media o request |
| (b) Anomaly only | `Client (Attacker) → Server` | **Só** pacotes do cliente do atacante |
| (c) Normal & anomaly | `Client → Server` + `Client (Attacker) → Server` | Pacotes do cliente normal **e** do cliente do atacante |

### Fig. 3 — Responses (fluxo servidor → cliente, resposta a request)
| Variante | Desenho do artigo | Significado |
|---|---|---|
| (a) MITM | `Client ↔ Relay (Attacker) ↔ Server` (nos dois sentidos, request e response) | Atacante media request **e** response |
| (b) Anomaly only | `Client ↔ Server (Attacker)`; nota: *"no requests to normal server"* | Comunicação **só** com o servidor do atacante; o servidor normal não recebe requests |
| (c) Normal & anomaly | `Client ↔ Server` + `Client ↔ Server (Attacker)` | Respostas do servidor normal **e** do servidor do atacante |

- **※ Nota da Fig. 3: "Assuming attacker wiretap"** — para fabricar responses plausíveis, o atacante pressupõe wiretap (escuta) dos requests.
- Escopo do artigo: interface **Request/Response** e **Notification Events** apenas. *Fire & Forget* e *Fields* são considerados subconjuntos destes (Sec. VII-A), fora do escopo.
- Anomalias consideradas: **system-specific violations** + **timing issues**. *Malformed packets* e *protocol violations* ficam **fora** (fáceis de detetar; não integram os datasets de anomalia).

---

## 2. Datasets base (Tabela I) e contagens

| Nome | Descrição (artigo) | Contagem no artigo | Gerado na Fase 2 |
|---|---|---|---|
| Normal_RR | Pacotes Request/Response normais | 6,455 | 6,455 ✓ |
| Normal_NEpc | Notification Events normais (periódicos **ou** por mudança de valor) | 255,128 | 255,128 ✓ |
| Normal_NEc | Notification Events normais (**só** por mudança de valor) | 1,722,011 | 1,722,011 ✓ |
| Anomaly_RR | Pacotes de ataque contra Request/Response **em Normal_RR** | — | a gerar |
| Anomaly_NEpc | Pacotes de ataque contra NE de Normal_NEpc | — | a gerar |
| Anomaly_NEc | Pacotes de ataque contra NE de Normal_NEc | — | a gerar |

✓ = idêntico ao gerado/validado na Fase 2 (as três contagens batem certo ao dígito).

---

## 3. Os 25 datasets de anomalia (Tabela II do artigo)

### 3.1 Grelha original (Tabela II, verbatim)

| Pacote-alvo | (a) MITM | (b) Anomaly only | (c) Normal & anomaly |
|---|---|---|---|
| **Request** | Anomaly_RR ×1 set | Anomaly_RR ×1 set | Anomaly_RR ×3 sets |
| **Response** | Anomaly_RR ×1 set | Anomaly_RR ×1 set | – |
| **Notification Events (\\*)** | Anomaly_NEpc ×8 sets | Anomaly_NEc ×5 sets (§) | Anomaly_NEpc ×2 sets |
| **Notification Events (†)** | Anomaly_NEc ×1 set | – | Anomaly_NEc ×2 sets |

- `*`: enviado periódicamente ou quando o valor muda. `†`: enviado só quando o valor muda.
- `§`: *Anomaly_NEpc is included in the Anomaly_NEc datasets* — os 5 sets (b) são **nomeados** Anomaly_NEc e incluem também o tráfego NEpc (porque em Normal_NEc os dois tipos de NE coexistem e o ARP-spoof de servidor apanha ambos).
- Soma: Request 1+1+3=5, Response 1+1=2, NE(\\*) 8+5+2=15, NE(†) 1+2=3 → **5+2+15+3 = 25 sets** ✓ (o artigo diz explicitamente *"We created a total of 25 anomaly datasets"*).

### 3.2 Enumeração proposta (25 linhas)

IDs `ARR-*` = Anomaly_RR, `ANEpc-*` = Anomaly_NEpc, `ANEc-*` = Anomaly_NEc.
**Volume-alvo por set** = total da linha (Tabela III) ÷ nº de sets da linha, com divisão proporcional de anomalia e total (**interpretação (A)**, §5.2); **proporção-alvo** = a da linha (idêntica por set, porque o split é proporcional). Restos de arredondamento distribuídos pelo gerador (diferença ≤1 pacote/set).

| # | ID do set | Base | Alvo (Tabela II) | Padrão (Figs) | Volume-alvo por set (Anomaly/All) | Proporção-alvo |
|---|---|---|---|---|---|---|
| 1 | `ARR-Req-a1` | Normal_RR | Request × (a) | MITM de request (Fig. 2a) | 772 / 3,291 | 23.5 % |
| 2 | `ARR-Req-b1` | Normal_RR | Request × (b) | Só cliente atacante (Fig. 2b) | 284 / 2,936 | 9.7 % |
| 3 | `ARR-Req-c1` | Normal_RR | Request × (c) | Cliente normal + atacante; atacante **conhece** o padrão de variação | 255 / 1,271 | 20.1 % |
| 4 | `ARR-Req-c2` | Normal_RR | Request × (c) | Idem; atacante **não conhece** o padrão de variação | 255 / 1,271 | 20.1 % |
| 5 | `ARR-Req-c3` | Normal_RR | Request × (c) | Repetição de uma das variantes acima sobre **outro sinal do payload** (premissa §7.2) | 256 / 1,272 | 20.1 % |
| 6 | `ARR-Res-a1` | Normal_RR | Response × (a) | MITM de response (Fig. 3a) | 773 / 3,291 | 23.5 % |
| 7 | `ARR-Res-b1` | Normal_RR | Response × (b) | Só servidor atacante, sem requests ao normal (Fig. 3b) | 284 / 2,937 | 9.7 % |
| 8–15 | `ANEpc-a1 … a8` | Normal_NEpc | NE(\\*) × (a) | MITM de NE (Fig. 1a); **8 variantes** de payload/valores de ataque | ≈1,732 / ≈4,078 | 42.5 % |
| 16–17 | `ANEpc-c1 … c2` | Normal_NEpc | NE(\\*) × (c) | Servidor normal + servidor atacante (Fig. 1c) | 1,412–1,413 / 4,237 | 33.3 % |
| 18–22 | `ANEc-b1 … b5` | Normal_NEc | NE(\\*) × (b) | Só servidor atacante via ARP-spoof (Fig. 1b); **inclui NEpc** (§) | ≈180 / ≈978 | 18.4 % |
| 23 | `ANEc-a1` | Normal_NEc | NE(†) × (a) | MITM de NE só-por-mudança (Fig. 1a) | 2,313 / 5,385 | 43.0 % |
| 24 | `ANEc-c1` | Normal_NEc | NE(†) × (c) | Servidor normal + atacante, só-por-mudança (Fig. 1c) | 6,350 / 12,154 | 52.3 % |
| 25 | `ANEc-c2` | Normal_NEc | NE(†) × (c) | Idem (segundo sinal/valores) | 6,351 / 12,154 | 52.3 % |

Contagem por categoria: **ARR = 7**, **ANEpc = 10**, **ANEc = 8** → **25** ✓.
Corpus total (interpretação (A)): **91,947 pacotes**, dos quais **35,477 de ataque (38.6 %)** = soma das linhas da Tabela III.

---

## 4. Implementações descritas no artigo (Sec. IV-C)

O artigo descreve 4 dos 25; os restantes *"were implemented in the same way"*:

1. **ARR-MITM (Fig. 5)** — atacante liga um dispositivo ao **ECU 2**; durante a SOME/IP entre cliente e servidor normais, reescreve as tabelas ARP (**ARP spoofing**) para passar a relay; estabelece publish/subscribe com servidor **e** cliente via SOME/IP-SD; depois **recebe o request ilegalmente e envia a response**. Fig. 5 mostra o atacante com identidades *False ECU3* (192.168.2.2) e *False ECU5* (192.168.2.4); IDS e Wireshark em ECU2 e ECU3.
2. **ARR (c) normal & anomaly** — cliente normal **e** cliente atacante subscrevem serviços do servidor normal via SD e ambos fazem Request/Response; variantes em que o atacante **sabe / não sabe** o padrão de variação de valores.
3. **ARR (b) anomaly only** — cliente normal e atacante subscrevem via SD no servidor normal; **quando o cliente normal não envia nada, o atacante envia o request**. (Figs. 5/6: *client impersonation* com identidade falsa de Client.)
4. **ANEc (b)** — ARP-spoof põe um **MAC inválido para o servidor usado pelo cliente**, cortando o subscribe do cliente ao servidor real; o atacante estabelece P/S **com o cliente** via SD → as notificações chegam **só do atacante**. Em Normal_NEc os dois tipos de NE têm o mesmo src/dst, portanto nenhuma NE do servidor legítimo sobrevive.

Pressupostos do atacante (Sec. IV-A): obtém à partida MAC/IP/service IDs; envia pacotes plausíveis seguindo a especificação SOME/IP; padrões de entrada = dispositivo ligado / intrusão remota / modificação de nó; localização relativa = MITM ou outro; estado do recetor = só-atrás-de-atacante ou misto.

---

## 5. Volumes e proporções (Tabela III do artigo)

### 5.1 Grelha original (verbatim) + %

| Categoria | Padrão | Anomaly/All [packets] | % |
|---|---|---|---|
| Anomaly_RR | (a) MITM | 1,545 / 6,582 | 23.5 % |
| Anomaly_RR | (b) Anomaly only | 568 / 5,873 | 9.7 % |
| Anomaly_RR | (c) Normal & Anomaly | 766 / 3,814 | 20.1 % |
| Anomaly_NEpc | (a) MITM | 13,858 / 32,623 | 42.5 % |
| Anomaly_NEpc | (b) Anomaly only | – | – |
| Anomaly_NEpc | (c) Normal & Anomaly | 2,825 / 8,474 | 33.3 % |
| Anomaly_NEc | (a) MITM | 2,313 / 5,385 | 43.0 % |
| Anomaly_NEc | (b) Anomaly only | 901 / 4,888 | 18.4 % |
| Anomaly_NEc | (c) Normal & Anomaly | 12,701 / 24,308 | 52.3 % |

Definição do artigo: **numerador** = nº de pacotes de ataque; **denominador** = total de pacotes SOME/IP **e** SOME/IP-SD (normais + de ataque).

### 5.2 Interpretação adotada: **(A) — total da linha, dividido entre os sets da linha**

O artigo não diz se cada set repete o total da linha ou se a linha é o agregado dos sets
("Table III **summarizes** the generated anomaly datasets and their ratios" — leitura natural de agregado).
Decisão: **(A)**, por três razões:

1. Mantém o **volume agregado fiel à Tabela III** (corpus total = soma das linhas = 91,947 pacotes);
   (B) inflaria o corpus para ~392,725 pacotes (~4,3×).
2. Com divisão **proporcional** dentro de cada linha, **cada set atinge a razão da linha** e
   **a soma dos sets atinge o volume da linha** — os dois critérios de aceite (±10 % em volume
   e em proporção) cumprem-se em simultâneo, por set e agregado.
3. Recomendação explícita do utilizador (dono dos critérios de aceite).

Aritmética por linha (n = nº de sets da linha):

| Linha (Tabela III) | Total da linha | n | Volume por set | Ataque por set (aprox.) |
|---|---|---|---|---|
| RR (a) | 1,545 / 6,582 | 2 | 772–773 / 3,291 | 772 ou 773 |
| RR (b) | 568 / 5,873 | 2 | 284 / 2,936–2,937 | 284 |
| RR (c) | 766 / 3,814 | 3 | 255–256 / 1,271–1,272 | 255, 255, 256 |
| NEpc (a) | 13,858 / 32,623 | 8 | 1,732–1,733 / 4,077–4,078 | 6×1.732 + 2×1.733 |
| NEpc (c) | 2,825 / 8,474 | 2 | 1,412–1,413 / 4,237 | 1,412 e 1,413 |
| NEc (a) | 2,313 / 5,385 | 1 | 2,313 / 5,385 | 2,313 |
| NEc (b) | 901 / 4,888 | 5 | 180–181 / 977–978 | 181 + 4×180 |
| NEc (c) | 12,701 / 24,308 | 2 | 6,350–6,351 / 12,154 | 6,350 e 6,351 |

Critérios de aceite da Fase 3 (fixados aqui):
- **por set**: proporção anomalia/total dentro de ±10 % (relativo) da razão da linha;
- **por linha**: soma dos volumes dos sets dentro de ±10 % (relativo) do *All* da linha;
- contagem exata de anomalia por set dentro de ±10 % (relativo) do valor da tabela de cima;
- restos de arredondamento: diferença ≤1 pacote por set face ao valor médio.

Nota honesta: há coincidências que sugeririam (B) (6,582 ≈ tamanho de Normal_RR 6,455;
8 × 32,623 ≈ 255,128 = Normal_NEpc), mas o texto não o confirma e não justifica inflar o corpus.

---

## 6. Reconciliação de contagens (briefing vs artigo)

| | Briefing do utilizador | Tabela II do artigo |
|---|---|---|
| Anomaly_RR | 5 (contando `Request(a)(b)(c)` + `Response(a)(b)` como 5 linhas) | **7 sets**: Request 1+1+**3** + Response 1+1 |
| Anomaly_NEpc | 8 (a) + 2 (c) = 10 | **10 sets** ✓ |
| Anomaly_NEc | 1 (a) + 5 (b) + 2 (c) = 8 | **8 sets** ✓ |
| **Total** | 5+10+8 = **23** ≠ 25 | **7+10+8 = 25** ✓ |

A divergência 23 vs 25 é **exclusivamente** `Request (c) ×3 sets` (contado como 1). O total 25 do briefing está certo; a tabela acima fecha-lo.

---

## 7. Notas e abertos (ANTES de implementar)

1. **[PENDÊNCIA — manter visível]** Bug de contabilidade do validador no *wrap* de Session-ID (`0xFFFF`→`0x0001`, `0x0000` reservado) → `missing=1` fantasma. Documentado em `docs/relatorio_fase2.md` §8.2 e `docs/documentacao.md`. **Não corrigir agora**; revisitar **antes** do parser de features (Fase 4). A validação da Fase 3 deve separar métricas **por label** (desvios do atacante ≠ perda de rede) para não confundir o fantasma com ataque.
2. **[RESOLVIDO — premissa de projeto (decisão do utilizador)]** O 3.º set de `Request (c)` (`ARR-Req-c3`) não é comportamento novo: é **repetição de uma das duas variantes já descritas** (atacante sabe / não sabe o padrão de variação), mas atacando **um sinal diferente do payload** (ex.: c1/c2 atacam velocidade, c3 ataca ângulo de volante/marcha). Justificativa: o artigo diz que os 25 datasets variam por *"various target payloads and attack values"*, não necessariamente por comportamento novo — logo a lacuna do texto não exige regra nova.
3. **[RESOLVIDO]** Interpretação de volume da Tabela III: **(A)**, total da linha dividido proporcionalmente entre os sets da linha — ver §5.2 (aritmética e critérios de aceite fixados lá).
4. Sec. VI diz *"nine attack patterns listed in Table III"* mas a Tabela III tem 8 linhas não vazias (a linha NEpc (b) é "–"); possível subdivisão Request/Response em (a). Não bloqueante para geração — só para reproduzir TPR/FPR por padrão.
5. Nomenclatura `§`: sets NE(\\*)-(b) chamam-se **Anomaly_NEc** mas incluem NEpc — manter para bater certo com o artigo.
6. **Fora de escopo** (artigo): *Fire & Forget*, *Fields*, malformed packets, protocol violations, NE só-periódicos (sem variação de valor).

## 8. Decisões de implementação (só após aprovação desta tabela)

- Atacante: **container ecu6 novo** (recomendado; ecu4 fica observador) vs reusar ecu4 — escolha a registar.
- Regra raw do `gen_dataset.sh`: hoje 2 ACCEPT + 6 DROP; se o atacante tiver rota própria pode ser preciso uma **3.ª ACCEPT** — registar novo valor e ajustar a checagem.
- ARP spoofing com código próprio (scapy) no container atacante (NET_ADMIN), alvos tipo *False ECU3/ECU5* conforme Figs. 5/6.
- App atacante parametrizada (MITM / anomaly-only / normal&anomaly, serviço-alvo, % de substituição, payload plausível-fora-padrão).
- `pcap_to_csv.py` estendido com coluna `label` (0/1) sem reescrever o parser multi-mensagem; `validate_dataset.py` com métricas por label.
- `scripts/gen_attack_dataset.sh` no padrão de `gen_dataset.sh`; regressão `smoke_test.sh` C1..C5 + raw 2/6 antes e depois de **cada** geração; `datasets/normal/*` intocados (`git diff` vazio).
- Runs reduzidos (2–3 datasets: um de cada categoria) **antes** dos 25 completos; PARAR e REPORTAR antes de gerar a totalidade.
