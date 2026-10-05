#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C

BASE="${SECLISTS_RAW:-https://raw.githubusercontent.com/danielmiessler/SecLists/master}"
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DEST="$DIR"
MAN="$DIR/manifest.tsv"
SOLO=()
FUERZA=0
COMPROBAR=0

uso(){
cat <<'EOF'
descargar_wordlists.sh — trae las wordlists del manifiesto desde SecLists

Uso: descargar_wordlists.sh [opciones] [archivo ...]

Sin argumentos descarga todo lo que falte. Con nombres sólo esos archivos.

Opciones:
  --destino DIR   dónde dejar los ficheros (por defecto este mismo directorio)
  --comprobar     sólo verifica sha256 de lo ya descargado
  --fuerza        vuelve a descargar aunque el fichero exista
  --url BASE      otra base raw (por defecto el repositorio SecLists)
  --help          esta ayuda
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --destino|--url)
      [ $# -ge 2 ] && [[ "$2" != --* ]] || { printf 'falta valor para %s\n' "$1" >&2; exit 2; }
      if [ "$1" = --destino ]; then DEST=$2; else BASE=$2; fi
      shift 2;;
    --comprobar) COMPROBAR=1; shift;;
    --fuerza) FUERZA=1; shift;;
    --help|-h) uso; exit 0;;
    -*) printf 'opción desconocida: %s\n' "$1" >&2; exit 2;;
    *) SOLO+=("$1"); shift;;
  esac
done

[ -f "$MAN" ] || { printf 'falta %s\n' "$MAN" >&2; exit 2; }
# Rechazar todos los nombres desconocidos antes de descargar o crear temporales.
for solicitado in "${SOLO[@]}"; do
  encontrado=0
  while IFS=$'\t' read -r archivo resto; do
    [ "$archivo" = "$solicitado" ] && encontrado=1
  done < "$MAN"
  if [ "$encontrado" -eq 0 ]; then
    printf 'nombre fuera del manifiesto: %s\n' "$solicitado" >&2
    exit 2
  fi
done
if [ "$COMPROBAR" -eq 0 ]; then
  mkdir -p "$DEST"
  TMPD=$(mktemp -d "$DEST/.wl_tmp.XXXXXX") || exit 2
  trap 'rm -f "$TMPD/desc" "$TMPD/extraido"; rmdir "$TMPD"' EXIT
fi

sha_de(){ sha256sum "$1" | cut -d' ' -f1; }

procesar(){
  local archivo=$1 lineas=$2 sha=$3 modo=$4 origen=$5
  local dst="$DEST/$archivo" contenido
  if [ -L "$dst" ] || { [ -e "$dst" ] && [ ! -f "$dst" ]; }; then
    printf 'ERROR: destino no regular o enlace simbólico: %s\n' "$dst" >&2
    return 1
  fi
  if [ "$COMPROBAR" -eq 1 ]; then
    if [ -f "$dst" ] && [ "$(sha_de "$dst")" = "$sha" ]; then
      printf 'ok        %s\n' "$archivo"; return 0
    fi
    printf 'falta/difiere %s\n' "$archivo"; return 1
  fi
  if [ "$FUERZA" -eq 0 ] && [ -f "$dst" ] && [ "$(sha_de "$dst")" = "$sha" ]; then
    printf 'ya está   %s\n' "$archivo"; return 0
  fi
  printf 'bajando   %s ... ' "$archivo"
  if ! curl -fsSL --connect-timeout 15 --max-time 900 --retry 3 -o "$TMPD/desc" "$BASE/$origen"; then
    printf 'ERROR: descarga fallida (%s)\n' "$origen" >&2; return 1
  fi
  case "$modo" in
    txt) contenido="$TMPD/desc";;
    gz:*)
      if ! tar -xzf "$TMPD/desc" -O "${modo#gz:}" > "$TMPD/extraido" 2>/dev/null; then
        printf 'ERROR: no se pudo extraer %s del tarball\n' "${modo#gz:}" >&2; return 1
      fi
      contenido="$TMPD/extraido";;
    *)
      printf 'ERROR: modo desconocido en el manifiesto: %s\n' "$modo" >&2; return 1;;
  esac
  if [ "$(sha_de "$contenido")" != "$sha" ]; then
    printf 'ERROR: sha256 distinto del manifiesto\n' >&2; return 1
  fi
  if ! mv -fT "$contenido" "$dst"; then
    printf 'ERROR: no se pudo guardar %s\n' "$archivo" >&2
    return 1
  fi
  printf 'ok (%s líneas)\n' "$lineas"
}

total=0
fallos=0
while IFS=$'\t' read -r archivo lineas sha modo origen; do
  case "$archivo" in ''|'#'*) continue;; esac
  if [ ${#SOLO[@]} -gt 0 ]; then
    dentro=0
    for s in "${SOLO[@]}"; do [ "$s" = "$archivo" ] && dentro=1; done
    [ "$dentro" -eq 1 ] || continue
  fi
  total=$((total+1))
  procesar "$archivo" "$lineas" "$sha" "$modo" "$origen" || fallos=$((fallos+1))
done < "$MAN"

if [ "$total" -eq 0 ]; then
  printf 'ningún nombre del argumento coincide con el manifiesto\n' >&2
  exit 2
fi
printf '\n%s procesados, %s fallos → %s\n' "$total" "$fallos" "$DEST"
[ "$fallos" -eq 0 ]
