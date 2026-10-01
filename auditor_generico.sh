#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C

SCRIPT_DIR=$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")
WL_DIR="${AUDITOR_WORDLISTS:-$SCRIPT_DIR/wordlists}"

HC="${AUDITOR_HASHCAT:-}"
[ -x "$HC" ] || HC=$(command -v hashcat 2>/dev/null)
[ -x "$HC" ] || HC="$HOME/.hermes/cache/scratch/hc712/hashcat-7.1.2/hashcat"
[ -x "$HC" ] || HC="/home/ignacia/.hermes/cache/scratch/hc712/hashcat-7.1.2/hashcat"
HC_DIR=$(dirname -- "$HC")
RULES="${AUDITOR_RULES:-$HC_DIR/rules}"
[ -d "$RULES" ] || RULES=/usr/share/hashcat/rules

JOHN="${AUDITOR_JOHN:-}"
[ -x "$JOHN" ] || JOHN=$(command -v john 2>/dev/null)
[ -x "$JOHN" ] || JOHN="$HOME/john-src/run/john"
[ -x "$JOHN" ] || JOHN="/home/ignacia/john-src/run/john"
JOHN_RUN=$(dirname -- "$JOHN")

RC_BIN="${AUDITOR_RAINBOW:-$SCRIPT_DIR/rainbowcrack/bin}"
[ -x "$RC_BIN/rcrack" ] || RC_BIN=$(dirname -- "$(command -v rcrack 2>/dev/null || printf 'x')")
RC_TAB="${RC_TABLAS:-${AUDITOR_RAINBOW_TABLES:-$SCRIPT_DIR/rainbowcrack/tables}}"
DIR_BASE="${AUDITORIA_DIR:-${AUDITOR_LOGS:-$HOME/auditoria_logs}}"

[ -d /opt/rocm/lib ] && export LD_LIBRARY_PATH="/opt/rocm/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
if [ -n "${AUDITOR_PERL5LIB:-}" ]; then
  export PERL5LIB="$AUDITOR_PERL5LIB${PERL5LIB:+:$PERL5LIB}"
fi
for _pd in "$HOME/perl5/deb/usr/lib/x86_64-linux-gnu/perl5/5.40" \
           "/home/ignacia/perl5/deb/usr/lib/x86_64-linux-gnu/perl5/5.40"; do
  [ -d "$_pd" ] && { export PERL5LIB="$_pd${PERL5LIB:+:$PERL5LIB}"; break; }
done
unset _pd

buscar_wl(){
  local n=$1 c
  for c in "$WL_DIR/$n" "$HOME/Descargas/$n" "/home/ignacia/Descargas/$n" \
           "$HOME/.hermes/cache/scratch/$n" "/home/ignacia/.hermes/cache/scratch/$n"; do
    [ -f "$c" ] && { printf '%s' "$c"; return 0; }
  done
  if [ -f "$WL_DIR/manifest.tsv" ] \
     && awk -F'\t' -v n="$n" '$1==n{ok=1} END{exit ok?0:1}' "$WL_DIR/manifest.tsv"; then
    PISTAS[wordlists]="wordlists sin descargar ($n): ejecuta wordlists/descargar_wordlists.sh"
  fi
  return 1
}

john_tool(){
  local n=$1 c
  [ -x "$JOHN_RUN/$n" ] && { printf '%s' "$JOHN_RUN/$n"; return 0; }
  c=$(command -v "$n" 2>/dev/null)
  [ -x "$c" ] && { printf '%s' "$c"; return 0; }
  printf '%s' "$JOHN_RUN/$n"
}

TIPO_ARG=auto
NIVEL=1-3
MOTOR_ARG=auto
MODO_ARG=
FMTJ_ARG=
DRY=0
SI=0
GUARDAR_SECRETOS=0
SIN_CAL=0
MAXMIN=0
WL_ARG=
EXT_CMD=
RUTA=
NIVEL_DE=1
NIVEL_HA=3
MOTOR=
MODO=
FMTJ=
FMT=
FASE=
INT=0
TASA_HC=10000
TASA_JOHN=10000
TASA_EXT=0
MEDIDA=0
declare -A TASA_CACHE=()
JOBS=()
declare -A JOB_SKIP=()
declare -A PISTAS=()

trap 'INT=1' INT

info(){ printf '[i] %s\n' "$*"; }
ok(){ printf '[+] %s\n' "$*"; }
aviso(){ printf '[!] %s\n' "$*" >&2; }
err(){ printf '[-] %s\n' "$*" >&2; }

uso(){
cat <<'EOF'
auditor_generico.sh — auditoría guiada de contraseñas (de lo simple a lo complejo)

Uso: auditor_generico.sh [opciones] [fichero]

Tipos (--tipo):
  archivo  fichero cifrado (rar/zip/7z/pdf/keepass, autodetecta)
  office   doc/xls/ppt y variantes office (docx/xlsx/pptx/odt...)
  wifi     captura .cap/.pcap/.hccapx o hash .22000
  hash     hash suelto (hex 16/32/40/64 o formato $...$)
  externo  formato no reconocido (p.ej. .xdf): usa un verificador externo
  auto     detección por extensión y magia (por defecto)

Niveles (--nivel): 1..5 o rango 1-3 (por defecto 1-3)
  1) probado inmediato          2) diccionarios comunes
  3) listas grandes + reglas    4) listas masivas, combinaciones
  5) máscaras y rainbow tables

Opciones:
  --motor auto|hashcat|john    motor principal (por defecto auto)
  --modo N                     modo hashcat para hash crudo (ej. 0, 1000)
  --formato NOMBRE             formato john si hay duda (auto por defecto)
  --dry-run                    plan sin motores/verificadores ni archivos nuevos
  --guardar-secretos           conserva contraseña, potfiles y logs locales
  --yes                        no pregunta: acepta los valores por defecto
  --sin-calibrar               no mide la velocidad (estimaciones aproximadas)
  --max-min N                  omite trabajos estimados en más de N minutos
  --wl A,B,...                 listas propias que sustituyen a los niveles 1 y 2
  --externo-cmd 'CMD %F %P'    verificador externo para formato externo
                               (%P=candidato, %F=fichero; argumentos independientes)
  --rainbow-dir DIR            directorio con tablas .rt para rcrack
  --help                       esta ayuda

Ejemplos:
  auditor_generico.sh /ruta/este.rar
  auditor_generico.sh --nivel 1-5 --max-min 240 /ruta/documento.zip
  auditor_generico.sh --tipo externo --externo-cmd '/ruta/verificador.sh %P' fichero.xdf
  auditor_generico.sh --tipo hash --modo 0 --nivel 5 hash_md5.txt

Variables de entorno (opcional):
  AUDITOR_WORDLISTS        directorio con las wordlists (por defecto ./wordlists)
  AUDITOR_HASHCAT          ruta al binario de hashcat
  AUDITOR_JOHN             ruta al binario de john
  AUDITOR_RULES            directorio de reglas hashcat
  AUDITOR_RAINBOW          directorio con rcrack/rtgen
  AUDITOR_RAINBOW_TABLES   directorio con tablas .rt
  AUDITORIA_DIR            directorio de resultados (por defecto ~/auditoria_logs)
EOF
}

preguntar(){
  if [ "$SI" -eq 1 ]; then printf '%s' "$2"; return; fi
  local r
  read -r -p "$1 [$2]: " r || r=""
  printf '%s' "${r:-$2}"
}

confirmar(){
  if [ "$SI" -eq 1 ]; then return 0; fi
  local r
  read -r -p "$1 [s/N]: " r || r=""
  case "$r" in s|S|si|SI|si|Si|sí|Sí) return 0;; *) return 1;; esac
}

fmt_tiempo(){
  awk -v s="${1:-0}" 'BEGIN{
    if (s < 0) { print "?"; exit }
    if (s < 60) printf "%ds", s
    else if (s < 3600) printf "%dm%02ds", int(s/60), int(s%60)
    else if (s < 86400) printf "%dh%02dm", int(s/3600), int((s%3600)/60)
    else printf "%dd%02dh", int(s/86400), int((s%86400)/3600)
  }'
}

n_rules(){
  awk 'NF==0 || /^#/ {next} {c++} END{print c+0}' "$1"
}

keyspace(){
  local m=$1 k=1 i c
  for ((i=0;i<${#m};i++)); do
    c=${m:i:1}
    if [ "$c" = "?" ]; then
      i=$((i+1))
      c=${m:i:1}
      case "$c" in
        d) k=$((k*10));;
        l|u) k=$((k*26));;
        s) k=$((k*32));;
        a) k=$((k*95));;
        *) k=$((k*1));;
      esac
    fi
  done
  echo "$k"
}

ext_minuscula(){
  local b=${RUTA##*/}
  printf '%s' "${b##*.}" | tr 'A-Z' 'a-z'
}

magic(){
python3 - "$1" <<'PY'
import sys
p = sys.argv[1]
try:
    b = open(p, 'rb').read(8192)
except Exception:
    print('error'); sys.exit()
if b[:4] in (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'):
    print('zip'); sys.exit()
if b[:5] == b'%PDF-':
    print('pdf'); sys.exit()
if b[:4] == b'Rar!':
    print('rar'); sys.exit()
if b[:6] == b'7z\xbc\xaf\x27\x1c':
    print('7z'); sys.exit()
if b[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
    print('office'); sys.exit()
if b[:4] == b'WPA*':
    print('wifi22000'); sys.exit()
if b[:6] == b'$WPAPSK' or b'WPAPSK' in b[:64]:
    print('wifi_john'); sys.exit()
s = b.decode('latin1', 'replace').strip()
s = s.split()[0] if s.split() else s
if s and all(c in '0123456789abcdefABCDEF' for c in s) and len(s) in (16, 32, 40, 64):
    print('raw'); sys.exit()
if '$' in s:
    print('pre'); sys.exit()
print('desconocido')
PY
}

detectar_fmt(){
  local ext tipo
  ext=$(ext_minuscula)
  if [ "$TIPO_ARG" = externo ]; then FMT=externo; return; fi
  if [ "$TIPO_ARG" = wifi ]; then
    case "$ext" in
      22000) FMT=wifi22000;;
      16800|16801) FMT=wifi16800;;
      hccapx) FMT=wifi_hccapx;;
      *) FMT=wifi_cap;;
    esac
    return
  fi
  if [ "$TIPO_ARG" = hash ]; then
    tipo=$(magic "$RUTA")
    case "$tipo" in
      raw) FMT=raw;;
      pre) FMT=pre;;
      *) FMT=$tipo;;
    esac
    return
  fi
  case "$ext" in
    rar) FMT=rar; return;;
    zip) FMT=zip; return;;
    7z|7zip) FMT=7z; return;;
    pdf) FMT=pdf; return;;
    kdb|kdbx) FMT=keepass; return;;
    doc|xls|ppt|dot|xlsb|docx|xlsx|pptx|docm|xlsm|odt|ods|odp|rtf) FMT=office; return;;
    cap|pcap|pcapng|hccapx) FMT=wifi_cap; return;;
    22000) FMT=wifi22000; return;;
  esac
  tipo=$(magic "$RUTA")
  case "$tipo" in
    raw) FMT=raw;;
    pre) FMT=pre;;
    desconocido) FMT=externo;;
    *) FMT=$tipo;;
  esac
}

conv(){
  local out="$DIR/hash.raw"
  "$@" >"$out" 2>"$DIR/conversion.err"
  if ! grep -qE '[$:]' "$out"; then
    err "el conversor no produjo un hash válido"
    [ -s "$DIR/conversion.err" ] && sed -n '1,6p' "$DIR/conversion.err" >&2
    return 1
  fi
  awk 'index($0,"$") && substr($0,1,1)!="$" {sub(/^[^$]*/,"")} /[$:]/ {print}' "$out" >"$DIR/hash.hc"
  grep -E '[$:]' "$out" >"$DIR/hash.john"
  if [ ! -s "$DIR/hash.hc" ] || [ ! -s "$DIR/hash.john" ]; then
    err "conversión vacía tras limpiar etiquetas"
    return 1
  fi
  HASHHC="$DIR/hash.hc"
  HASHJOHN="$DIR/hash.john"
  return 0
}

convertir(){
  HASHHC=$RUTA
  HASHJOHN=$RUTA
  case "$FMT" in
    raw|pre) return 0;;
    rar) conv "$(john_tool rar2john)" "$RUTA" ;;
    zip) conv "$(john_tool zip2john)" "$RUTA" ;;
    7z)
      if perl -MCompress::Raw::Lzma -e1 2>/dev/null; then
        conv perl "$(john_tool 7z2john.pl)" "$RUTA"
      else
        PISTAS[7z]="falta libcompress-raw-lzma-perl (sudo apt-get install -y libcompress-raw-lzma-perl)"
        return 1
      fi;;
    pdf)
      if [ -x "$(john_tool pdf2john.pl)" ]; then
        conv perl "$(john_tool pdf2john.pl)" "$RUTA"
      else
        conv python3 "$(john_tool pdf2john.py)" "$RUTA"
      fi;;
    keepass) conv "$(john_tool keepass2john)" "$RUTA" ;;
    office)
      if python3 -c 'import olefile' 2>/dev/null; then
        conv python3 "$(john_tool office2john.py)" "$RUTA"
      else
        PISTAS[office]="falta olefile (sudo apt-get install -y python3-olefile)"
        return 1
      fi;;
    wifi_cap)
      if command -v hcxpcapngtool >/dev/null 2>&1; then
        if hcxpcapngtool -o "$DIR/hash.22000" "$RUTA" >/dev/null 2>&1 && [ -s "$DIR/hash.22000" ]; then
          FMT=wifi22000
          HASHHC="$DIR/hash.22000"
          HASHJOHN="$DIR/hash.22000"
          return 0
        fi
      fi
      PISTAS[wifi]="sin hcxtools: sólo se puede atacar con john (lento). sudo apt-get install -y aircrack-ng hcxtools"
      conv "$(john_tool wpapcap2john)" "$RUTA";;
    wifi22000|wifi16800|wifi_hccapx) return 0;;
    externo) return 0;;
    *)
      err "tipo no soportado: $FMT"
      return 1;;
  esac
}

identificar_modos(){
  timeout 240 "$HC" --identify "$HASHHC" 2>/dev/null \
    | awk -F'|' '/^ *[0-9]+ \|/{gsub(/ /,"",$1); if($1 ~ /^[0-9]+$/) print $1}'
}

probe_modo(){
  local out
  out=$(timeout 300 "$HC" -m "$1" "$HASHHC" -a 3 '?d' --potfile-path "$POT" --quiet 2>&1)
  if printf '%s' "$out" | grep -qiE 'No hashes loaded|Token length exception|Separator missing|unsupported|Token out of range|Error #'; then
    return 1
  fi
  return 0
}

elegir_modo(){
  MODO=""
  if [ -n "$MODO_ARG" ]; then MODO=$MODO_ARG; return 0; fi
  case "$FMT" in
    wifi22000) MODO=22000; return 0;;
    wifi16800) MODO=16800; return 0;;
    wifi_hccapx) MODO=2500; return 0;;
  esac
  if [ "$FMT" = raw ]; then
    err "hash hexadecimal ambiguo: indica --modo (por ejemplo, 0=MD5, 100=SHA1, 1000=NTLM)"
    return 1
  fi
  local cands n m
  cands=$(identificar_modos)
  [ -z "$cands" ] && return 1
  n=$(printf '%s\n' "$cands" | grep -c .)
  if [ "$n" -eq 1 ]; then MODO=$cands; return 0; fi
  while read -r m; do
    [ -z "$m" ] && continue
    if probe_modo "$m"; then MODO=$m; return 0; fi
  done <<<"$cands"
  return 1
}

elegir_motor(){
  if [ "$FMT" = externo ]; then
    if [ -z "$EXT_CMD" ]; then err "tipo externo: falta --externo-cmd 'CMD %P'"; return 1; fi
    MOTOR=externo
    return 0
  fi
  case "$MOTOR_ARG" in
    hashcat|john) MOTOR=$MOTOR_ARG;;
    *) MOTOR=hashcat;;
  esac
  if [ "$MOTOR" = hashcat ] && [ ! -x "$HC" ]; then
    aviso "hashcat no encontrado en $HC"
    MOTOR=john
  fi
  if [ "$MOTOR" = hashcat ]; then
    if [ -z "$MODO" ]; then
      if ! elegir_modo; then
        [ "$FMT" = raw ] && return 1
        aviso "hashcat no reconoce este hash; se usará john"
        MOTOR=john
      fi
    fi
  fi
  if [ "$MOTOR" = john ]; then
    if [ ! -x "$JOHN" ]; then err "john no encontrado en $JOHN"; return 1; fi
    case "$FMT" in
      wifi22000|wifi_hccapx|wifi16800)
        err "john no lee ese formato de wifi ($FMT); usa --motor hashcat"
        return 1;;
    esac
    if [ -z "$MODO" ] && [ -n "$MODO_ARG" ]; then MODO=$MODO_ARG; fi
  fi
  return 0
}

detectar_formato_john(){
  FMTJ=$FMTJ_ARG
  [ -n "$FMTJ" ] && return 0
  [ "$MOTOR" = john ] || return 0
  local out
  out=$(timeout 20 "$JOHN" --pot="$JPOT" --session="$DIR/ses_detect" --wordlist=/dev/null "$HASHJOHN" 2>&1)
  FMTJ=$(printf '%s\n' "$out" | sed -n 's/.*Loaded [0-9]\+ password hash\{1,2\} (\([^ ,]*\).*/\1/p' | head -1)
  return 0
}

calibrar_hashcat(){
  [ "$SIN_CAL" -eq 1 ] && { MEDIDA=0; return 0; }
  local k="hc_$1" val out med=0
  if [ -n "${TASA_CACHE[$k]:-}" ]; then
    TASA_HC=${TASA_CACHE[$k]%% *}
    MEDIDA=${TASA_CACHE[$k]##* }
    return 0
  fi
  out=$(timeout 300 "$HC" -b -m "$1" 2>/dev/null)
  val=$(printf '%s\n' "$out" | awk '/Speed\.#/{for(i=1;i<=NF;i++){ if($i ~ /^[0-9]+\.?[0-9]*$/ && $(i+1) ~ /^(k|M|G)?H\/s$/){u=$(i+1); v=$i+0; if(u ~ /^k/) v=v*1000; else if(u ~ /^M/) v=v*1000000; else if(u ~ /^G/) v=v*1000000000; printf "%d", v; exit}}}')
  if [ -n "$val" ] && [ "$val" -gt 0 ]; then
    med=1
  else
    case "$1" in
      12500) val=21000;;
      *) val=10000;;
    esac
  fi
  TASA_CACHE[$k]="$val $med"
  TASA_HC=$val
  MEDIDA=$med
}

calibrar_john(){
  MEDIDA=0
  [ "$SIN_CAL" -eq 1 ] && return 0
  [ -n "$FMTJ" ] || return 0
  local out t
  out=$(timeout 240 "$JOHN" --test=2 --format="$FMTJ" 2>&1)
  t=$(printf '%s\n' "$out" | awk '
    {
      if (match($0, /[0-9]+(\.[0-9]+)?[ ]?[kKmMgG]?[ ]?[cp]\/s real/)) {
        s = substr($0, RSTART, RLENGTH)
        if (match(s, /[0-9]+(\.[0-9]+)?/)) num = substr(s, RSTART, RLENGTH) + 0
        else next
        if (s ~ /K/) num *= 1000
        else if (s ~ /M/) num *= 1000000
        else if (s ~ /G/) num *= 1000000000
        val = num
      }
    } END { if (val > 0) printf "%d", val; else print 0 }')
  if [ -n "$t" ] && [ "$t" -gt 0 ]; then
    TASA_JOHN=$t
    MEDIDA=1
  fi
  return 0
}

preparar_externo(){
  EXT_ARGV=()
  mapfile -d '' -t EXT_ARGV < <(python3 -c 'import shlex,sys; a=shlex.split(sys.argv[1]); sys.exit(2) if a.count("%P") != 1 or not a else sys.stdout.buffer.write(b"\0".join(x.encode() for x in a)+b"\0")' "$EXT_CMD")
  if [ ${#EXT_ARGV[@]} -eq 0 ]; then
    err "--externo-cmd requiere una orden válida con %P como argumento independiente"
    return 1
  fi
  local n=0 a
  for a in "${EXT_ARGV[@]}"; do [ "$a" = '%P' ] && n=$((n+1)); done
  [ "$n" -eq 1 ] || { err "--externo-cmd requiere un único %P"; return 1; }
}

ejecutar_externo(){
  local pw=$1 i
  local -a argv=("${EXT_ARGV[@]}")
  for i in "${!argv[@]}"; do
    [ "${argv[$i]}" = '%P' ] && argv[$i]=$pw
    [ "${argv[$i]}" = '%F' ] && argv[$i]=$RUTA
  done
  timeout 15 "${argv[@]}"
}

calibrar_externo(){
  # Un verificador puede tener efectos secundarios; no se invoca para calibrarlo.
  TASA_EXT=100
  MEDIDA=0
  return 0
}

tasa_de(){
  case "$1" in
    hashcat) echo "$TASA_HC";;
    john) echo "$TASA_JOHN";;
    externo) echo "$TASA_EXT";;
    rainbow) echo 40;;
    *) echo 10000;;
  esac
}

agregar_wl(){
  local nom=$1 cand=$2 wl=$3 regla=$4
  case "$MOTOR" in
    hashcat)
      local -a args=("$HC" --restore-disable -w 2 -m "$MODO" --potfile-path "$POT" -a 0 "$HASHHC" "$wl")
      [ -n "$regla" ] && args+=(-r "$RULES/$regla.rule")
      agregar_job "$nom" hashcat "$cand" "${args[@]}";;
    john)
      local -a args=("$JOHN" "--pot=$JPOT" "--session=$DIR/ses_$nom" "--wordlist=$wl")
      [ -n "$regla" ] && args+=(--rules)
      [ -n "$FMTJ" ] && args+=("--format=$FMTJ")
      args+=("$HASHJOHN")
      agregar_job "$nom" john "$cand" "${args[@]}";;
    externo)
      agregar_job "$nom" externo "$cand" "$wl";;
  esac
}

agregar_mascara(){
  local nom=$1 cand=$2 m=$3
  case "$MOTOR" in
    hashcat) agregar_job "$nom" hashcat "$cand" "$HC" --restore-disable -w 2 -m "$MODO" --potfile-path "$POT" -a 3 "$HASHHC" "$m";;
    john)
      local -a args=("$JOHN" "--pot=$JPOT" "--session=$DIR/ses_$nom" "--mask=$m")
      [ -n "$FMTJ" ] && args+=("--format=$FMTJ")
      args+=("$HASHJOHN")
      agregar_job "$nom" john "$cand" "${args[@]}";;
  esac
}

agregar_job(){
  local idx=${#JOBS[@]} name="JOB_CMD_${#JOBS[@]}"
  JOBS+=("$1|$2|$3")
  shift 3
  declare -ag "$name=()"
  local -n args_ref="$name"
  args_ref=("$@")
}

wl_o(){
  local wl
  wl=$(buscar_wl "$1") || return 0
  printf '%s|%s\n' "$wl" "$2"
}

lista_nivel(){
  local w
  case $1 in
    1)
      if [ ${#WL_CUSTOM[@]} -gt 0 ]; then
        for w in "${WL_CUSTOM[@]}"; do printf '%s|\n' "$w"; done
      else
        wl_o custom.txt ""
        wl_o stupid-ones-in-production.txt ""
        wl_o unkown-azul.txt ""
      fi;;
    2)
      if [ ${#WL_CUSTOM[@]} -gt 0 ]; then
        for w in "${WL_CUSTOM[@]}"; do printf '%s|best66\n' "$w"; done
      else
        wl_o days.txt best66
        wl_o months.txt best66
        wl_o Most-Popular-Letter-Passes.txt ""
        wl_o scraped-JWT-secrets.txt ""
      fi;;
    3)
      wl_o Merriam-Webster-SCRABBLE-4thEdition.txt best66
      wl_o SCRABBLE-large.txt best66
      wl_o darkc0de.txt best66;;
    4)
      wl_o Pwdb_top-10000000.txt ""
      wl_o rockyou.txt ""
      wl_o rockyou.txt best66;;
  esac
}

planificar(){
  JOBS=()
  local nivel wl regla nombre cand lines rl wl_az wl_d wl_c
  for ((nivel=NIVEL_DE; nivel<=NIVEL_HA; nivel++)); do
    if [ "$nivel" -le 4 ]; then
      while IFS='|' read -r wl regla; do
        [ -z "$wl" ] && continue
        [ -f "$wl" ] || continue
        lines=$(wc -l < "$wl")
        rl=0
        if [ -n "$regla" ] && [ -f "$RULES/$regla.rule" ]; then
          rl=$(n_rules "$RULES/$regla.rule")
        else
          regla=
        fi
        if [ "$MOTOR" = externo ]; then
          regla=
          cand=$lines
        elif [ "$MOTOR" = john ]; then
          if [ -n "$regla" ]; then cand=$((lines*36)); else cand=$lines; fi
        else
          if [ -n "$regla" ] && [ "$rl" -gt 0 ]; then cand=$((lines*rl)); else cand=$lines; fi
        fi
        nombre="n${nivel}_$(basename "$wl" .txt)${regla:+_$regla}"
        nombre=$(printf '%s' "$nombre" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-48)
        agregar_wl "$nombre" "$cand" "$wl" "$regla"
      done < <(lista_nivel "$nivel")
    fi
    if [ "$nivel" -eq 4 ] && [ "$MOTOR" = hashcat ]; then
      wl_az=$(buscar_wl unkown-azul.txt || true)
      wl_d=$(buscar_wl days.txt || true)
      wl_c=$(buscar_wl custom.txt || true)
      if [ -n "$wl_az" ] && [ -n "$wl_d" ]; then
        cand=$(($(wc -l < "$wl_az") * $(wc -l < "$wl_d")))
        agregar_job "n4_comb_azul_x_dias" hashcat "$cand" \
          "$HC" --restore-disable -w 2 -m "$MODO" --potfile-path "$POT" -a 1 "$HASHHC" "$wl_az" "$wl_d"
      fi
      if [ -n "$wl_c" ]; then
        lines=$(wc -l < "$wl_c")
        agregar_job "n4_hibrido_custom_6digitos" hashcat "$((lines*1000000))" \
          "$HC" --restore-disable -w 2 -m "$MODO" --potfile-path "$POT" -a 6 "$HASHHC" "$wl_c" '?d?d?d?d?d?d'
      fi
    fi
    if [ "$nivel" -eq 5 ]; then
      local msk nom i=1
      for msk in '?d?d?d?d?d?d?d?d' '?d?d?d?d?l?l?l?l' '?l?l?l?l?l?l?d?d'; do
        if [ "$MOTOR" = externo ]; then continue; fi
        cand=$(keyspace "$msk")
        nom="n5_mascara_$(printf '%s' "$msk" | tr -c 'A-Za-z0-9' '_')"
        agregar_mascara "$nom" "$cand" "$msk"
        i=$((i+1))
      done
      if [ "$FMT" = raw ] && { [ "$MODO" = 0 ] || [ "$MODO" = 100 ]; }; then
        if ls "$RC_TAB"/*.rt >/dev/null 2>&1 && [ -x "$RC_BIN/rcrack" ]; then
          cand=0
          agregar_job "n5_rainbow_tablas" rainbow "$cand" "$RC_BIN/rcrack" "$RC_TAB"/*.rt -l "$HASHHC"
        fi
      fi
    fi
  done
}

imprimir_pistas(){
  local k
  [ ${#PISTAS[@]} -eq 0 ] && return 0
  printf '\nHerramientas opcionales que faltan:\n'
  for k in "${!PISTAS[@]}"; do printf '  - %s\n' "${PISTAS[$k]}"; done
  printf '\n'
}

mostrar_plan(){
  local i=1 idx=0 total=0 t nom mot cand visible
  printf '\nPlan de ataque (motor: %s%s) — nivel %s\n' "$MOTOR" "${MODO:+, modo $MODO}" "$NIVEL"
  printf '%-3s %-42s %-8s %14s %10s\n' '#' 'trabajo' 'motor' 'candidatos' 'tiempo'
  printf '%s\n' '-----------------------------------------------------------------------'
  for job in "${JOBS[@]}"; do
    if [ "${JOB_SKIP[$idx]:-0}" -eq 1 ]; then idx=$((idx+1)); continue; fi
    IFS='|' read -r nom mot cand <<<"$job"
    t=$(awk -v c="$cand" -v r="$(tasa_de "$mot")" 'BEGIN{ if(r<=0 || c<=0) print -1; else printf "%d", c/r }')
    if [ "$t" -lt 0 ]; then
      visible='?'
    else
      total=$((total+t))
      visible=$(fmt_tiempo "$t")
    fi
    printf '%-3s %-42s %-8s %14s %10s\n' "$i" "$nom" "$mot" "$cand" "$visible"
    i=$((i+1))
    idx=$((idx+1))
  done
  printf '%s\n' '-----------------------------------------------------------------------'
  printf 'Total estimado: %s' "$(fmt_tiempo "$total")"
  [ "$i" -eq 1 ] && printf ' (sin trabajos)'
  printf '\n'
  printf 'Estimación orientativa; los trabajos con tiempo ? no entran en el total.\n'
  if [ "$MOTOR" = hashcat ]; then
    if [ "$MEDIDA" -eq 1 ]; then
      printf 'Velocidad medida: %s H/s\n' "$TASA_HC"
    else
      printf 'Velocidad aproximada: %s H/s (medición omitida o fallida)\n' "$TASA_HC"
    fi
  fi
  if [ "$MOTOR" = john ]; then
    if [ "$MEDIDA" -eq 1 ]; then
      printf 'Velocidad medida (john): %s H/s\n' "$TASA_JOHN"
    else
      printf 'Velocidad aproximada (john): %s H/s\n' "$TASA_JOHN"
    fi
  fi
  [ "$DRY" -eq 1 ] && printf '(dry-run: no se ejecuta nada)\n'
  imprimir_pistas
  printf '\n'
}

tiempo_trabajo(){
  local cand=$1 mot=$2
  awk -v c="$cand" -v r="$(tasa_de "$mot")" 'BEGIN{ if(r<=0 || c<=0) print 0; else printf "%d", c/r }'
}

bucle_externo(){
  local wl=$1 pw
  while IFS= read -r pw; do
    [ -z "$pw" ] && continue
    if ejecutar_externo "$pw" >>"$DIR/externo.log" 2>&1; then
      printf '%s' "$pw" >"$PASSFILE.tmp"
      mv "$PASSFILE.tmp" "$PASSFILE"
      return 0
    fi
  done < "$wl"
  return 1
}

extraer_pass(){
  local tmp="$PASSFILE.tmp" line pass
  : > "$tmp"
  if [ "$MOTOR" = hashcat ] && [ -s "$POT" ] && [ -n "$MODO" ]; then
    line=$("$HC" -m "$MODO" "$HASHHC" --potfile-path "$POT" --show --outfile-format 2 2>/dev/null | head -1)
    [ -n "$line" ] && printf '%s' "$line" > "$tmp"
  fi
  if [ ! -s "$tmp" ] && [ -s "$JPOT" ]; then
    line=$("$JOHN" --show --pot="$JPOT" ${FMTJ:+--format="$FMTJ"} "$HASHJOHN" 2>/dev/null | grep -v 'password hashes' | head -1)
    if [ -n "$line" ]; then
      pass=${line#*:}
      pass=${pass%%:*}
      printf '%s' "$pass" > "$tmp"
    fi
  fi
  if [ -s "$tmp" ]; then
    mv "$tmp" "$PASSFILE"
    return 0
  fi
  rm -f "$tmp"
  return 1
}

extraer_rainbow_pass(){
  python3 - "$RUTA" "$DIR/n5_rainbow_tablas.log" "$PASSFILE.tmp" "$MODO" <<'PY'
import hashlib
import re
import sys

algoritmo = {'0': 'md5', '100': 'sha1'}.get(sys.argv[4])
if not algoritmo:
    sys.exit(1)
objetivo = open(sys.argv[1], encoding='ascii').read().strip().lower()
with open(sys.argv[2], encoding='utf-8', errors='replace') as registro:
    for linea in registro:
        match = re.fullmatch(r'plaintext of ([0-9a-fA-F]+) is (.*)\n?', linea)
        if not match or match.group(1).lower() != objetivo:
            continue
        candidato = match.group(2).rstrip('\r\n')
        if hashlib.new(algoritmo, candidato.encode()).hexdigest() == objetivo:
            with open(sys.argv[3], 'wb') as destino:
                destino.write(candidato.encode())
            sys.exit(0)
sys.exit(1)
PY
  if [ -s "$PASSFILE.tmp" ]; then
    mv "$PASSFILE.tmp" "$PASSFILE"
    return 0
  fi
  return 1
}

ejecutar(){
  local i=1 idx=0 nom mot cand
  for job in "${JOBS[@]}"; do
    if [ "${JOB_SKIP[$idx]:-0}" -eq 1 ]; then idx=$((idx+1)); continue; fi
    IFS='|' read -r nom mot cand <<<"$job"
    local -n args_ref="JOB_CMD_$idx"
    info "[$i/${#JOBS[@]}] $nom · $mot · ~$(fmt_tiempo "$(tiempo_trabajo "$cand" "$mot")")"
    case "$mot" in
      hashcat|john)
        "${args_ref[@]}" </dev/null >>"$DIR/$nom.log" 2>&1;;
      rainbow)
        (cd "$RC_BIN" && "${args_ref[@]}") >>"$DIR/$nom.log" 2>&1;;
      externo)
        bucle_externo "${args_ref[0]}" || true;;
    esac
    if [ "$mot" = rainbow ] && extraer_rainbow_pass; then
      FASE=$nom
      MOTOR=rainbow
      return 0
    fi
    if [ -s "$PASSFILE" ]; then FASE=$nom; return 0; fi
    if extraer_pass; then FASE=$nom; return 0; fi
    if [ "$INT" -eq 1 ]; then aviso "interrumpido por el usuario"; break; fi
    i=$((i+1))
    idx=$((idx+1))
  done
  return 1
}

verificar(){
  local p=$1
  case "$FMT" in
    rar|zip|7z)
      if 7z t -p"$p" -y "$RUTA" >/dev/null 2>&1; then
        7z l -p"$p" -y "$RUTA" 2>/dev/null | awk '/^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] / && $0 !~ /[0-9] files$/{c++} END{printf "    contenido verificado: %d ficheros\n", c+0}'
        return 0
      fi
      return 1;;
    pdf)
      pdfinfo -upw "$p" "$RUTA" >/dev/null 2>&1 && return 0
      return 1;;
    office)
      return 2;;
    externo)
      return 0;;
    raw)
      case "$MODO" in 0|100|1400) ;; *) return 2;; esac
      python3 - "$RUTA" "$PASSFILE" "$MODO" <<'PY'
import hashlib
import sys

algoritmo = {'0': 'md5', '100': 'sha1', '1400': 'sha256'}[sys.argv[3]]
objetivo = open(sys.argv[1], encoding='ascii').read().strip().lower()
candidato = open(sys.argv[2], 'rb').read()
sys.exit(0 if hashlib.new(algoritmo, candidato).hexdigest() == objetivo else 1)
PY
      return $?;;
    *)
      return 2;;
  esac
}

guardar_resultado(){
  local pass=$1 ver=$2 tmp
  tmp=$(mktemp "$DIR/.res.XXXXXX")
  {
    printf 'fecha=%s\n' "$(date -Is)"
    if [ "$GUARDAR_SECRETOS" -eq 1 ]; then
      printf 'objetivo=%s\n' "$RUTA"
      printf 'fase=%s\n' "$FASE"
    else
      printf 'objetivo=omitido\n'
      printf 'fase=%s\n' "${FASE%%_*}"
    fi
    printf 'objetivo_id=%s\n' "$OBJ_ID"
    printf 'tipo=%s\n' "$FMT"
    printf 'motor=%s\n' "$MOTOR"
    printf 'modo=%s\n' "${MODO:-n/a}"
    if [ "$GUARDAR_SECRETOS" -eq 1 ]; then
      printf 'contrasena=%s\n' "$pass"
    else
      printf 'contrasena=omitida\n'
    fi
    printf 'verificacion=%s\n' "$ver"
  } > "$tmp"
  mv "$tmp" "$DIR/resultado.txt"
}

resumen_final(){
  local pass ver rc ver_txt
  pass=$(cat "$PASSFILE")
  if [ -n "$pass" ]; then
    if [ "$GUARDAR_SECRETOS" -eq 1 ]; then
      ok "CANDIDATO ENCONTRADO: $pass"
    else
      ok "CANDIDATO ENCONTRADO (oculto; usa --guardar-secretos sólo en un entorno privado)"
    fi
    printf '    fase: %s · motor: %s\n' "${FASE%%_*}" "$MOTOR"
    verificar "$pass"
    rc=$?
    case $rc in
      0) ver="ok"; ver_txt="verificación externa correcta";;
      1) ver="rechazado"; ver_txt="la verificación externa RECHAZA el candidato";;
      *) ver="motor"; ver_txt="coincidencia según el motor; sin verificación independiente";;
    esac
    printf '    %s\n' "$ver_txt"
    guardar_resultado "$pass" "$ver"
    printf '    trabajo: %s\n' "$DIR"
    [ "$rc" -eq 1 ] && return 2
    return 0
  fi
  err "no se encontró la contraseña con los niveles $NIVEL"
  printf '    trabajos ejecutados: %d\n' "${#JOBS[@]}"
  printf '    logs: %s\n' "$DIR"
  printf '    sugiere: --nivel 4-5, --max-min 0, o instalar herramientas opcionales\n'
  return 1
}

guia(){
  printf '=== Auditoría guiada de contraseñas ===\n'
  printf '  1) Fichero cifrado (rar/zip/7z/pdf/keepass...)\n'
  printf '  2) Office / Excel\n'
  printf '  3) WiFi (captura .cap/.pcap o hash .22000)\n'
  printf '  4) Hash suelto\n'
  printf '  5) Formato no reconocido (.xdf) con verificador externo\n'
  local op
  op=$(preguntar "Tipo de objetivo" 1)
  case "$op" in
    2) TIPO_ARG=office;;
    3) TIPO_ARG=wifi;;
    4) TIPO_ARG=hash;;
    5) TIPO_ARG=externo;;
    *) TIPO_ARG=archivo;;
  esac
  RUTA=$(preguntar "Ruta del fichero" "")
  while [ -z "$RUTA" ] || [ ! -f "$RUTA" ]; do
    err "el fichero no existe"
    RUTA=$(preguntar "Ruta del fichero" "")
  done
  NIVEL=$(preguntar "Niveles (1, 1-3, 1-5)" "1-3")
  MOTOR_ARG=$(preguntar "Motor (auto/hashcat/john)" "auto")
  if [ "$TIPO_ARG" = externo ]; then
    EXT_CMD=$(preguntar "Verificador (CMD con %P para la contraseña)" "")
    while [ -z "$EXT_CMD" ]; do
      err "hace falta un verificador"
      EXT_CMD=$(preguntar "Verificador (CMD con %P)" "")
    done
  fi
}

parsear_nivel(){
  case "$NIVEL" in
    *-*) NIVEL_DE=${NIVEL%-*}; NIVEL_HA=${NIVEL#*-};;
    *) NIVEL_DE=$NIVEL; NIVEL_HA=$NIVEL;;
  esac
  if ! [[ "$NIVEL_DE" =~ ^[1-5]$ && "$NIVEL_HA" =~ ^[1-5]$ ]]; then
    err "nivel inválido: $NIVEL (usa 1..5 o 1-3)"; exit 2
  fi
  [ "$NIVEL_DE" -le "$NIVEL_HA" ] || { err "rango de niveles invertido"; exit 2; }
  return 0
}

parsear(){
  while [ $# -gt 0 ]; do
    case "$1" in
      --help|-h) uso; exit 0;;
      --tipo|--nivel|--motor|--modo|--formato|--max-min|--wl|--externo-cmd|--rainbow-dir)
        [ $# -ge 2 ] && [[ "$2" != --* ]] || { err "falta valor para $1"; exit 2; }
        case "$1" in
          --tipo) TIPO_ARG=$2;; --nivel) NIVEL=$2;; --motor) MOTOR_ARG=$2;;
          --modo) MODO_ARG=$2;; --formato) FMTJ_ARG=$2;;
          --max-min) MAXMIN=$2;; --wl) WL_ARG=$2;;
          --externo-cmd) EXT_CMD=$2;; --rainbow-dir) RC_TAB=$2;;
        esac
        shift 2;;
      --dry-run) DRY=1; shift;;
      --guardar-secretos) GUARDAR_SECRETOS=1; shift;;
      --yes|-y) SI=1; shift;;
      --sin-calibrar) SIN_CAL=1; shift;;
      --) shift; break;;
      -*) err "opción desconocida: $1"; uso; exit 2;;
      *) RUTA=$1; shift;;
    esac
  done
  if [ $# -gt 0 ]; then RUTA=$1; fi
  [[ "$MAXMIN" =~ ^[0-9]+$ ]] || { err "--max-min debe ser un entero no negativo"; exit 2; }
  [ "${#MAXMIN}" -le 7 ] || { err "--max-min demasiado grande"; exit 2; }
  MAXMIN=$((10#$MAXMIN))
  [ -z "$MODO_ARG" ] || [[ "$MODO_ARG" =~ ^[0-9]+$ ]] || { err "--modo debe ser numérico"; exit 2; }
  case "$TIPO_ARG" in auto|archivo|office|wifi|hash|externo) ;; *) err "--tipo desconocido: $TIPO_ARG"; exit 2;; esac
  case "$MOTOR_ARG" in auto|hashcat|john) ;; *) err "--motor desconocido: $MOTOR_ARG"; exit 2;; esac
  parsear_nivel
  WL_CUSTOM=()
  if [ -n "$WL_ARG" ]; then
    IFS=',' read -r -a WL_CUSTOM <<<"$WL_ARG"
    local wl
    for wl in "${WL_CUSTOM[@]}"; do
      [ -f "$wl" ] || { err "lista no encontrada: $wl"; exit 2; }
      [[ "$wl" != *'|'* && "$wl" != *$'\n'* ]] || { err "ruta de lista no admitida: $wl"; exit 2; }
    done
  fi
}

mostrar_plan_seco(){
  local nivel wl regla
  printf 'Plan orientativo (sin motores, verificadores ni archivos nuevos): %s · niveles %s\n' "$FMT" "$NIVEL"
  for ((nivel=NIVEL_DE; nivel<=NIVEL_HA; nivel++)); do
    if [ "$nivel" -le 4 ]; then
      while IFS='|' read -r wl regla; do
        [ -n "$wl" ] && printf '  nivel %s: %s%s\n' "$nivel" "$(basename "$wl")" "${regla:+ + regla $regla}"
      done < <(lista_nivel "$nivel")
    else
      printf '  nivel 5: máscaras; tablas rainbow sólo para MD5/SHA1 sin salt\n'
    fi
  done
  printf 'El modo, las velocidades y la compatibilidad se comprueban al ejecutar.\n'
  imprimir_pistas
}

limpiar_sensibles(){
  if [ "$GUARDAR_SECRETOS" -eq 0 ] && [ -n "${DIR:-}" ] && [ -d "$DIR" ]; then
    find "$DIR" -maxdepth 1 -type f ! -name resultado.txt -delete
  fi
}

main(){
  parsear "$@"
  if [ -z "$RUTA" ]; then
    if [ "$SI" -eq 1 ]; then uso; exit 2; fi
    guia
    parsear_nivel
  fi
  if [ ! -f "$RUTA" ]; then err "no existe el fichero: $RUTA"; exit 2; fi
  RUTA=$(readlink -f "$RUTA")
  OBJ_ID=$(python3 -c 'import secrets; print(secrets.token_hex(8))')
  detectar_fmt
  if [ "$DRY" -eq 1 ]; then
    mostrar_plan_seco
    return 0
  fi
  case "$FMT" in
    office) TIPO=office;;
    wifi*) TIPO=wifi;;
    raw|pre) TIPO=hash;;
    externo) TIPO=externo;;
    *) TIPO=archivo;;
  esac
  if [ "$FMT" = externo ]; then
    if [ -z "$EXT_CMD" ] && [ "$SI" -eq 0 ] && [ -t 0 ]; then
      EXT_CMD=$(preguntar "Formato no reconocido. Verificador (CMD con %P)" "")
    fi
    if [ -z "$EXT_CMD" ]; then
      err "formato no reconocido: $RUTA"
      err "define un verificador: --externo-cmd 'herramienta %F %P'"
      exit 2
    fi
  fi
  if ! confirmar "¿Preparar y ejecutar la auditoría?"; then
    info "cancelado"
    exit 0
  fi

  umask 077
  mkdir -p "$DIR_BASE"
  DIR=$(mktemp -d "$DIR_BASE/$(date +%Y%m%d_%H%M%S)_objetivo_${OBJ_ID}.XXXXXX") || exit 2
  trap limpiar_sensibles EXIT
  POT="$DIR/hashcat.pot"
  JPOT="$DIR/john.pot"
  PASSFILE="$DIR/password.txt"
  touch "$POT" "$JPOT"
  info "objetivo ID: $OBJ_ID · tipo: $FMT · trabajo: $DIR"

  if ! convertir; then
    exit 1
  fi
  if ! elegir_motor; then
    exit 1
  fi
  if [ "$MOTOR" = externo ]; then preparar_externo || exit 2; fi
  detectar_formato_john

  if [ "$MOTOR" = hashcat ]; then calibrar_hashcat "$MODO"; fi
  if [ "$MOTOR" = john ]; then calibrar_john; fi
  if [ "$MOTOR" = externo ]; then calibrar_externo; fi

  planificar

  if [ "$MAXMIN" -gt 0 ]; then
    local j nom mot cand idx=0
    for j in "${JOBS[@]}"; do
      IFS='|' read -r nom mot cand <<<"$j"
      if [ "$(tiempo_trabajo "$cand" "$mot")" -gt $((MAXMIN*60)) ]; then
        info "omitido por --max-min: $nom"
        JOB_SKIP[$idx]=1
      elif [ "$cand" -eq 0 ]; then
        aviso "--max-min no puede estimar $nom; permanece en el plan"
      fi
      idx=$((idx+1))
    done
  fi

  mostrar_plan
  local activos=0 idx
  for idx in "${!JOBS[@]}"; do
    [ "${JOB_SKIP[$idx]:-0}" -eq 0 ] && activos=$((activos+1))
  done
  if [ "$activos" -eq 0 ]; then
    err "no hay trabajos que ejecutar"
    exit 1
  fi
  if ejecutar && [ -s "$PASSFILE" ]; then
    resumen_final
    exit $?
  fi
  resumen_final
  exit $?
}

main "$@"
