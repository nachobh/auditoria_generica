#!/usr/bin/env bash
# Evidencia pasiva de WPS en un AP propio o expresamente autorizado.
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR=$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")
INTERFAZ=
BSSID=
CANAL=
OBSERVAR_SEG=20
CAPTURA_SEG=15
SALIDA_DIR=${AUDITOR_CAPTURAS_DIR:-}
SECO=0
RUN_DIR=
MON_IFACE=
MON_CREADA=0
CAP_PID=

error(){ printf 'Error: %s\n' "$*" >&2; exit 2; }
info(){ printf '[i] %s\n' "$*"; }

uso(){
cat <<'EOF'
Observa WPS de un AP y guarda una captura breve si lo anuncia.

Uso:
  sudo ./run_captura_wifi_wps.sh --interfaz wlan0 --bssid 02:11:22:33:44:55 --canal 6

Opciones:
  --interfaz NOMBRE       interfaz WiFi; acepta una ya en modo monitor
  --bssid MAC            AP elegido expresamente
  --canal N              canal del AP (1..233)
  --observar-seg N       duración de observación WPS (5..120; por defecto 20)
  --captura-seg N        duración de la captura de evidencia (5..60; por defecto 15)
  --salida DIR           directorio privado de resultados
  --dry-run              muestra el plan sin root, radio ni archivos
  --help                 esta ayuda

Sólo se observa tráfico. Un anuncio WPS no demuestra que el método PIN esté
habilitado ni que sea vulnerable. No se prueban PIN ni se obtiene la clave WPA.
EOF
}

valor(){ [ $# -ge 2 ] && [[ "$2" != --* ]] || error "falta valor para $1"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h) uso; exit 0;;
    --dry-run) SECO=1; shift;;
    --interfaz|--bssid|--canal|--observar-seg|--captura-seg|--salida)
      valor "$@"
      case "$1" in
        --interfaz) INTERFAZ=$2;; --bssid) BSSID=$2;; --canal) CANAL=$2;;
        --observar-seg) OBSERVAR_SEG=$2;; --captura-seg) CAPTURA_SEG=$2;;
        --salida) SALIDA_DIR=$2;;
      esac
      shift 2;;
    *) error "opción desconocida: $1";;
  esac
done

[[ "$INTERFAZ" =~ ^[A-Za-z0-9_.-]+$ ]] || error "indica una --interfaz válida"
[[ "$BSSID" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || error "indica un --bssid válido"
BSSID=${BSSID^^}
for nombre in CANAL OBSERVAR_SEG CAPTURA_SEG; do
  numero=${!nombre}
  [[ "$numero" =~ ^[0-9]+$ ]] && [ "${#numero}" -le 4 ] || error "$nombre debe ser un entero"
  printf -v "$nombre" '%d' "$((10#$numero))"
done
[ "$CANAL" -ge 1 ] && [ "$CANAL" -le 233 ] || error "canal fuera de 1..233"
[ "$OBSERVAR_SEG" -ge 5 ] && [ "$OBSERVAR_SEG" -le 120 ] || error "observación fuera de 5..120 s"
[ "$CAPTURA_SEG" -ge 5 ] && [ "$CAPTURA_SEG" -le 60 ] || error "captura fuera de 5..60 s"

if [ -z "$SALIDA_DIR" ]; then
  usuario=${SUDO_USER:-${USER:-root}}
  casa=$(getent passwd "$usuario" | cut -d: -f6 || true)
  [ -n "$casa" ] || casa=$HOME
  SALIDA_DIR="$casa/capturas_wifi"
fi

if [ "$SECO" -eq 1 ]; then
  info "interfaz=$INTERFAZ · BSSID=$BSSID · canal=$CANAL"
  info "observación pasiva=${OBSERVAR_SEG}s · captura de evidencia=${CAPTURA_SEG}s si se observa WPS"
  info "salida=$SALIDA_DIR"
  exit 0
fi

[ "$EUID" -eq 0 ] || error "ejecuta la observación con sudo; --dry-run funciona sin root"
for herramienta in wash airodump-ng iw timeout stdbuf python3; do
  command -v "$herramienta" >/dev/null 2>&1 || error "falta $herramienta"
done
umask 077
[ ! -L "$SALIDA_DIR" ] || error "el directorio de salida no puede ser un enlace simbólico"
BASE_NUEVA=0
if [ ! -d "$SALIDA_DIR" ]; then mkdir -p -- "$SALIDA_DIR"; BASE_NUEVA=1; fi
SALIDA_DIR=$(readlink -f -- "$SALIDA_DIR")
RUN_DIR=$(mktemp -d "$SALIDA_DIR/$(date +%Y%m%d_%H%M%S)_wps.XXXXXX")

parar_pid(){
  local pid=$1
  if [ -n "$pid" ]; then
    if kill -0 "$pid" 2>/dev/null; then kill -INT "$pid" 2>/dev/null || true; fi
    wait "$pid" 2>/dev/null || true
  fi
}
limpiar(){
  local rc=$?
  trap - EXIT INT TERM
  parar_pid "$CAP_PID"
  if [ "$MON_CREADA" -eq 1 ] && [ -n "$MON_IFACE" ]; then
    airmon-ng stop "$MON_IFACE" >/dev/null 2>&1 || true
  fi
  if [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ]; then
    find "$RUN_DIR" -maxdepth 1 -type f -name 'reaver.db*' -delete
    if [[ "${SUDO_UID:-}" =~ ^[0-9]+$ && "${SUDO_GID:-}" =~ ^[0-9]+$ ]]; then
      chown -R "${SUDO_UID}:${SUDO_GID}" "$RUN_DIR" || true
      [ "$BASE_NUEVA" -eq 0 ] || chown "${SUDO_UID}:${SUDO_GID}" "$SALIDA_DIR" || true
    fi
    info "archivos conservados en $RUN_DIR"
  fi
  exit "$rc"
}
trap limpiar EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

monitores(){ iw dev | awk '$1=="Interface" {nombre=$2} $1=="type" && $2=="monitor" {print nombre}'; }
es_monitor(){ iw dev "$1" info 2>/dev/null | awk '$1=="type" && $2=="monitor" {ok=1} END {exit !ok}'; }
if es_monitor "$INTERFAZ"; then
  MON_IFACE=$INTERFAZ
else
  command -v airmon-ng >/dev/null 2>&1 || error "falta airmon-ng"
  antes=$(monitores)
  info "activando modo monitor en $INTERFAZ"
  airmon-ng start "$INTERFAZ" >"$RUN_DIR/monitor.log" 2>&1 || error "airmon-ng no pudo activar monitor"
  if es_monitor "$INTERFAZ"; then
    MON_IFACE=$INTERFAZ
  else
    nuevos=()
    while IFS= read -r candidato; do
      [ -n "$candidato" ] || continue
      if ! printf '%s\n' "$antes" | grep -Fxq -- "$candidato"; then nuevos+=("$candidato"); fi
    done < <(monitores)
    [ ${#nuevos[@]} -eq 1 ] || error "no se pudo identificar una única interfaz monitor nueva"
    MON_IFACE=${nuevos[0]}
  fi
  MON_CREADA=1
fi

info "observando WPS de $BSSID en canal $CANAL durante ${OBSERVAR_SEG}s"
# wash en modo survey es pasivo. Su salida se filtra en memoria para no guardar
# otros SSID/BSSID ni repetir el error de logs de decenas de GB.
set +e
( cd "$RUN_DIR" && timeout --signal=INT --kill-after=3s "$OBSERVAR_SEG" \
  stdbuf -oL wash -u -i "$MON_IFACE" -c "$CANAL" 2>/dev/null ) | \
  python3 "$SCRIPT_DIR/wps_capture_utils.py" --bssid "$BSSID" --canal "$CANAL" \
    >"$RUN_DIR/estado_wps.txt"
codigos=("${PIPESTATUS[@]}")
set -e
if [ "${codigos[0]}" -ne 0 ] && [ "${codigos[0]}" -ne 124 ]; then
  error "wash falló (código ${codigos[0]}); no se puede determinar el estado WPS"
fi
if [ "${codigos[1]}" -eq 3 ]; then
  printf 'WPS no observado en %s segundos; resultado no concluyente.\n' \
    "$OBSERVAR_SEG" >"$RUN_DIR/estado_wps.txt"
  info "no se observó WPS en el AP durante esta ventana; estado no concluyente"
  exit 3
fi
[ "${codigos[1]}" -eq 0 ] || error "no se pudo interpretar la salida de wash"
read -r version bloqueo <"$RUN_DIR/estado_wps.txt"
printf 'WPS anunciado: sí\nVersión: %s\nBloqueo informado: %s\nWPS PIN: no verificado\n' \
  "$version" "$bloqueo" >"$RUN_DIR/estado_wps.txt"
info "WPS anunciado: versión=$version · bloqueo informado=$bloqueo"
info "esto no confirma que WPS PIN acepte intentos"

airodump-ng --channel "$CANAL" --bssid "$BSSID" --output-format pcap \
  -w "$RUN_DIR/wps_evidencia" "$MON_IFACE" >/dev/null 2>&1 &
CAP_PID=$!
sleep "$CAPTURA_SEG"
parar_pid "$CAP_PID"; CAP_PID=
[ -s "$RUN_DIR/wps_evidencia-01.cap" ] || error "no se generó la captura de evidencia"
set +e
( cd "$RUN_DIR" && timeout 10s wash -f "$RUN_DIR/wps_evidencia-01.cap" 2>/dev/null ) | \
  python3 "$SCRIPT_DIR/wps_capture_utils.py" --bssid "$BSSID" --canal "$CANAL" \
    >"$RUN_DIR/wps_captura.txt"
verificacion=("${PIPESTATUS[@]}")
set -e
if [ "${verificacion[0]}" -eq 0 ] && [ "${verificacion[1]}" -eq 0 ]; then
  printf 'Anuncio WPS presente en captura: sí\n' >>"$RUN_DIR/estado_wps.txt"
  info "anuncio WPS confirmado en la captura"
else
  printf 'Anuncio WPS presente en captura: no confirmado\n' >>"$RUN_DIR/estado_wps.txt"
  info "la captura no confirmó el anuncio WPS; conserva sólo evidencia parcial"
fi
rm -f -- "$RUN_DIR/wps_captura.txt"
info "captura guardada: $RUN_DIR/wps_evidencia-01.cap"
