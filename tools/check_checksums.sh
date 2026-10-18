#!/usr/bin/env bash
# tools/check_checksums.sh -- Verifica datasets/CHECKSUMS.sha256.
#
# Uso:
#   tools/check_checksums.sh
#
# Correr ANTES das Fases 4/5 (extracao de features + treino/avaliacao do IDS),
# para garantir que os datasets (pcap + CSV) em disco sao exactamente aqueles
# sobre os quais os resultados foram medidos.
#
# Sai 0 se todos os ficheiros batem certo; 1 se algum foi alterado ou removido.
# Linhas comecadas por '#' no ficheiro de checksums sao ignoradas.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FILE="datasets/CHECKSUMS.sha256"
[[ -f "$FILE" ]] || { echo "check_checksums: falta $FILE" >&2; exit 2; }

N=$(grep -cvE '^[[:space:]]*(#|$)' "$FILE")
echo "check_checksums: a verificar $N ficheiros contra $FILE"

if sha256sum -c --strict <(grep -vE '^[[:space:]]*(#|$)' "$FILE"); then
    echo "check_checksums: OK ($N ficheiros intactos)"
    exit 0
else
    echo "check_checksums: FALHA -- dataset alterado ou em falta (ver acima)." >&2
    echo "  Nao sobrescrevas os datasets congelados. Se foram alterados, regenera-os" >&2
    echo "  com os scripts em scripts/ (--scale 1.0) e re-corre a validacao." >&2
    exit 1
fi
