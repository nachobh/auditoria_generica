#!/usr/bin/env bash
# Ataque de máscara alfanumérica larga (10-12 por defecto) con pausa y
# reanudación. Cada longitud es una sesión hashcat independiente: al
# detenerse (Ctrl-C o --parar) hashcat deja el punto exacto en un .restore
# y la siguiente ejecución continúa donde lo dejó.
#
# Uso:
#   ./run_mascara_larga.sh --hash hash.22000                  # longitudes 10,11,12
#   ./run_mascara_larga.sh --hash h.22000 --longitudes 10-12 --charset '?l?u?d'
#   ./run_mascara_larga.sh --hash h.22000 --parar             # pausa ordenada
#   ./run_mascara_larga.sh --hash h.22000 --estado            # progreso
#
# Estado, log y pot quedan en --dir (por defecto ~/ataques_mascara, fuera
# del repositorio). Las sesiones separan objetivo y configuración.
set -euo pipefail
umask 077

HC="${AUDITOR_HASHCAT:-$HOME/.local/share/hashcat-7.1.2/hashcat}"
[ -x "$HC" ] || HC=$(command -v hashcat)
[ -d /opt/rocm/lib ] && export LD_LIBRARY_PATH="/opt/rocm/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

uso(){ sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

HASH="" DIR="$HOME/ataques_mascara" LONGS="10,11,12" CHARSET='?l?u?d'
MODO=22000 W="" ACCION="atacar"
while [ $# -gt 0 ]; do
  case "$1" in
    --hash) HASH=${2:?}; shift 2;;
    --dir) DIR=${2:?}; shift 2;;
    --longitudes) LONGS=${2:?}; shift 2;;
    --charset) CHARSET=${2:?}; shift 2;;
    --modo) MODO=${2:?}; shift 2;;
    --workload) W=${2:?}; shift 2;;
    --parar) ACCION=parar; shift;;
    --estado) ACCION=estado; shift;;
    --help|-h) uso 0;;
    *) echo "opción desconocida: $1" >&2; uso 2;;
  esac
done
[ -n "$HASH" ] || { echo "falta --hash" >&2; uso 2; }
[ -f "$HASH" ] || { echo "no existe el hash: $HASH" >&2; exit 2; }
[[ "$MODO" =~ ^[0-9]{1,8}$ ]] || { echo "modo inválido" >&2; exit 2; }
MODO=$((10#$MODO))
[[ "$LONGS" =~ ^[0-9]{1,2}([,-][0-9]{1,2})*$ ]] || { echo "longitudes inválidas" >&2; exit 2; }
[ -z "$W" ] || [[ "$W" =~ ^[1-4]$ ]] || { echo "workload fuera de 1..4" >&2; exit 2; }
[ -n "$CHARSET" ] && [ "${#CHARSET}" -le 256 ] || { echo "charset inválido" >&2; exit 2; }
# resolver a ruta absoluta ANTES de cd: con rutas relativas el hash dejaría
# de apuntar al archivo original tras cambiar de directorio
HASH=$(readlink -f "$HASH")
HC=$(readlink -f "$HC")
mkdir -p "$DIR"
DIR=$(cd "$DIR" && pwd)
cd "$DIR"   # hashcat 7.1.2 escribe <sesion>.restore en el cwd
lista=$(python3 - "$LONGS" <<'PY'
import sys
valor = sys.argv[1]
if '-' in valor:
    if ',' in valor or valor.count('-') != 1:
        sys.exit('usa un rango o una lista de longitudes')
    inicio, fin = map(int, valor.split('-'))
    if not 1 <= inicio <= fin <= 64:
        sys.exit('rango de longitudes fuera de 1..64')
    longitudes = range(inicio, fin + 1)
else:
    longitudes = list(dict.fromkeys(map(int, valor.split(','))))
    if any(not 1 <= n <= 64 for n in longitudes):
        sys.exit('longitudes fuera de 1..64')
print(' '.join(map(str, longitudes)))
PY
)
OBJ_ID=$(python3 - "$HASH" "$MODO" "$CHARSET" "$DIR" "$W" <<'PY'
import hashlib, json, sys
contenido = hashlib.sha256()
with open(sys.argv[1], 'rb') as archivo:
    for bloque in iter(lambda: archivo.read(65536), b''):
        contenido.update(bloque)
identidad = json.dumps([*sys.argv[1:], contenido.hexdigest()], ensure_ascii=True).encode()
print(hashlib.sha256(identidad).hexdigest()[:24])
PY
)
POT="$DIR/$OBJ_ID.potfile"
sesion(){ printf 'm%s_%s_l%s' "$MODO" "$OBJ_ID" "$1"; }

case "$ACCION" in
  parar)
    for L in $lista; do
      if pkill -TERM -f "hashcat.*--session $(sesion "$L")( |$)" 2>/dev/null; then
        echo "[i] pausa pedida a la sesión $(sesion "$L") (SIGTERM; guarda .restore)"
      fi
    done
    exit 0;;
  estado)
    for L in $lista; do
      s=$(sesion "$L")
      printf '%s: ' "$s"
      if pgrep -f "hashcat.*--session $s( |$)" >/dev/null 2>&1; then
        printf 'EN EJECUCIÓN. '
      fi
      if [ -f "$DIR/$s.restore" ]; then
        echo "hay .restore (se reanuda relanzando el script)"
        tail -c 4000 "$DIR/$s.log" 2>/dev/null | grep -E 'Status|Progress|Speed' | tail -2 | sed 's/^/    /' || true
      elif [ -f "$DIR/$s.log" ]; then
        echo "agotada (ver $DIR/$s.log)"
      else
        echo "sin empezar"
      fi
    done
    [ -s "$POT" ] && echo "hallazgos privados en $POT" || true
    exit 0;;
esac

for L in $lista; do
  s=$(sesion "$L")
  if pgrep -f "hashcat.*--session $s( |$)" >/dev/null 2>&1; then
    echo "[i] $(sesion "$L") ya en ejecución; usa --parar antes de relanzar"
    continue
  fi
  mask=""
  for ((posicion=0; posicion<L; posicion++)); do mask+=$CHARSET; done
  wopt=(); [ -n "$W" ] && wopt=(-w "$W")
  rst="$DIR/$s.restore"
  set +e
  if [ -f "$rst" ]; then
    echo "[i] reanudando longitud $L desde $rst"
    "$HC" --restore --session "$s" \
      --restore-file-path "$rst" --potfile-path "$POT" --status --status-timer 60 \
      2>&1 | tee -a "$DIR/$s.log"
  else
    echo "[i] iniciando longitud $L (máscara ${CHARSET}×${L})"
    "$HC" -m "$MODO" "$HASH" -a 3 "$mask" "${wopt[@]}" --session "$s" \
      --restore-file-path "$rst" --potfile-path "$POT" --status --status-timer 60 \
      2>&1 | tee -a "$DIR/$s.log"
  fi
  rc=${PIPESTATUS[0]}
  set -e
  case $rc in
    0) echo "[+] clave encontrada (longitud $L); pot: $POT"; exit 0;;
    1) echo "[i] longitud $L agotada sin hallazgo";;
    *) echo "[!] longitud $L interrumpida (código $rc); estado en $DIR/$s.restore — relanza este script para reanudar"; exit "$rc";;
  esac
done
echo "[i] todas las longitudes agotadas sin hallazgo"
