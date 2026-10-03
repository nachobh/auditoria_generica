#!/usr/bin/env bash
# Captura dirigida de una red WiFi propia o expresamente autorizada.
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR=$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")
INTERFAZ=
SSID=
BSSID=
CANAL=
BANDA=abg
ESCANEO_SEG=20
MINUTOS=10
SALIDA_DIR=${AUDITOR_CAPTURAS_DIR:-}
DEAUTH=0
SECO=0
SOLO_CAPTURA=0
RUN_DIR=
MON_IFACE=
MON_CREADA=0
SCAN_PID=
CAP_PID=

error(){ printf 'Error: %s\n' "$*" >&2; exit 2; }
info(){ printf '[i] %s\n' "$*"; }

uso(){
cat <<'EOF'
Captura WiFi dirigida para auditoría autorizada. Sólo observa por defecto.

Uso:
  sudo ./run_captura_wifi.sh --interfaz wlan0 --ssid 'Mi red' [opciones]
  sudo ./run_captura_wifi.sh --interfaz wlan0mon --bssid AA:BB:CC:DD:EE:FF --canal 6 [opciones]

Opciones:
  --interfaz NOMBRE        interfaz WiFi; acepta una ya en modo monitor
  --ssid NOMBRE           nombre exacto de la red; si falta BSSID/canal, escanea
  --bssid MAC             selecciona un AP concreto; obligatorio para --deauth
  --canal N               escanea sólo ese canal y selecciona su AP (1..233)
  --banda bg|a|abg        bandas del escaneo (por defecto abg)
  --escaneo-seg N         duración del escaneo (5..1200, por defecto 20)
  --minutos N             duración de captura (1..600, por defecto 10)
  --salida DIR            directorio privado de capturas
  --solo-captura          conserva el .cap sin convertirlo a formato 22000
  --deauth N              envía N tandas de desconexión al BSSID explícito (1..3)
  --dry-run               valida y muestra el plan; no pide root ni crea archivos
  --help                  esta ayuda

Sin --deauth no se transmiten tramas para forzar un handshake. La captura no
ejecuta el auditor de contraseñas. Usa esta herramienta sólo sobre tu red o
con autorización expresa del titular.
EOF
}

valor(){
  [ $# -ge 2 ] && [[ "$2" != --* ]] || error "falta valor para $1"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h) uso; exit 0;;
    --dry-run) SECO=1; shift;;
    --solo-captura) SOLO_CAPTURA=1; shift;;
    --interfaz|--ssid|--bssid|--canal|--banda|--escaneo-seg|--minutos|--salida|--deauth)
      valor "$@"
      case "$1" in
        --interfaz) INTERFAZ=$2;; --ssid) SSID=$2;; --bssid) BSSID=$2;;
        --canal) CANAL=$2;; --banda) BANDA=$2;;
        --escaneo-seg) ESCANEO_SEG=$2;; --minutos) MINUTOS=$2;;
        --salida) SALIDA_DIR=$2;; --deauth) DEAUTH=$2;;
      esac
      shift 2;;
    *) error "opción o argumento desconocido: $1";;
  esac
done

[[ "$INTERFAZ" =~ ^[A-Za-z0-9_.-]+$ ]] || error "indica una --interfaz válida"
[[ -n "$SSID" || -n "$BSSID" ]] || error "indica --ssid o --bssid"
[[ "$SSID" != *$'\n'* && "$SSID" != *$'\r'* ]] || error "SSID no admitido"
if [ -n "$BSSID" ]; then
  [[ "$BSSID" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || error "BSSID inválido"
  BSSID=${BSSID^^}
fi
for nombre in CANAL ESCANEO_SEG MINUTOS DEAUTH; do
  valor=${!nombre}
  if [ -n "$valor" ]; then
    [[ "$valor" =~ ^[0-9]+$ ]] && [ "${#valor}" -le 4 ] || error "$nombre debe ser un entero"
    printf -v "$nombre" '%d' "$((10#$valor))"
  fi
done
[ -z "$CANAL" ] || { [ "$CANAL" -ge 1 ] && [ "$CANAL" -le 233 ]; } || error "canal fuera de 1..233"
[ "$ESCANEO_SEG" -ge 5 ] && [ "$ESCANEO_SEG" -le 1200 ] || error "escaneo fuera de 5..1200 s"
[ "$MINUTOS" -ge 1 ] && [ "$MINUTOS" -le 600 ] || error "duración fuera de 1..600 min"
[ "$DEAUTH" -ge 0 ] && [ "$DEAUTH" -le 3 ] || error "--deauth admite 1..3"
case "$BANDA" in bg|a|abg) ;; *) error "--banda debe ser bg, a o abg";; esac
[ "$DEAUTH" -eq 0 ] || [ -n "$BSSID" ] || error "--deauth requiere --bssid explícito"
[ -n "$SSID" ] || [ -n "$CANAL" ] || error "con sólo --bssid indica también --canal"

if [ -z "$SALIDA_DIR" ]; then
  usuario=${SUDO_USER:-${USER:-root}}
  casa=$(getent passwd "$usuario" | cut -d: -f6 || true)
  [ -n "$casa" ] || casa=$HOME
  SALIDA_DIR="$casa/capturas_wifi"
fi

if [ "$SECO" -eq 1 ]; then
  info "interfaz=$INTERFAZ · SSID=${SSID:-sin indicar} · BSSID=${BSSID:-por resolver} · canal=${CANAL:-por resolver}"
  info "banda=$BANDA · escaneo=${ESCANEO_SEG}s · captura=${MINUTOS}min · deauth=$DEAUTH"
  info "salida de captura=$([ "$SOLO_CAPTURA" -eq 1 ] && printf 'cap' || printf 'cap + 22000')"
  info "salida=$SALIDA_DIR"
  if [ -z "$BSSID" ] || [ -z "$CANAL" ]; then
    info "se hará un escaneo pasivo para resolver el AP${CANAL:+ en el canal $CANAL}"
  fi
  exit 0
fi

[ "$EUID" -eq 0 ] || error "ejecuta la captura con sudo; --dry-run funciona sin root"
for herramienta in airodump-ng iw python3; do
  command -v "$herramienta" >/dev/null 2>&1 || error "falta $herramienta"
done
[ "$SOLO_CAPTURA" -eq 1 ] || command -v hcxpcapngtool >/dev/null 2>&1 || error "falta hcxpcapngtool; usa --solo-captura si quieres conservar sólo el .cap"
[ "$DEAUTH" -eq 0 ] || command -v aireplay-ng >/dev/null 2>&1 || error "falta aireplay-ng"
umask 077
[ ! -L "$SALIDA_DIR" ] || error "el directorio de salida no puede ser un enlace simbólico"
BASE_NUEVA=0
if [ ! -d "$SALIDA_DIR" ]; then mkdir -p -- "$SALIDA_DIR"; BASE_NUEVA=1; fi
SALIDA_DIR=$(readlink -f -- "$SALIDA_DIR")
RUN_DIR=$(mktemp -d "$SALIDA_DIR/$(date +%Y%m%d_%H%M%S)_wifi.XXXXXX")

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
  parar_pid "$SCAN_PID"
  parar_pid "$CAP_PID"
  if [ "$MON_CREADA" -eq 1 ] && [ -n "$MON_IFACE" ]; then
    airmon-ng stop "$MON_IFACE" >/dev/null 2>&1 || true
  fi
  if [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ]; then
    find "$RUN_DIR" -maxdepth 1 -type f \( -name 'scan-*' -o -name 'captura-*.csv' -o -name 'todos.22000' \) -delete
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
  airmon-ng start "$INTERFAZ" >"$RUN_DIR/monitor.log" 2>&1 || error "airmon-ng no pudo activar monitor; revisa $RUN_DIR/monitor.log"
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
info "monitor=$MON_IFACE"

if [ -z "$BSSID" ] || [ -z "$CANAL" ]; then
  sintonizacion=(--band "$BANDA")
  if [ -n "$CANAL" ]; then
    sintonizacion=(--channel "$CANAL")
    info "escaneando ${ESCANEO_SEG}s en canal $CANAL"
  else
    info "escaneando ${ESCANEO_SEG}s en banda $BANDA"
  fi
  # airodump-ng repinta la pantalla sin parar; redirigirla a un archivo puede
  # consumir decenas de GB aun durante una captura breve.
  airodump-ng "${sintonizacion[@]}" --output-format csv --write-interval 1 \
    -w "$RUN_DIR/scan" "$MON_IFACE" >/dev/null 2>&1 &
  SCAN_PID=$!
  sleep "$ESCANEO_SEG"
  parar_pid "$SCAN_PID"; SCAN_PID=
  [ -f "$RUN_DIR/scan-01.csv" ] || error "el escaneo no creó CSV; comprueba la interfaz"
  selector=(seleccionar "$RUN_DIR/scan-01.csv")
  [ -z "$SSID" ] || selector+=(--ssid "$SSID")
  [ -z "$BSSID" ] || selector+=(--bssid "$BSSID")
  [ -z "$CANAL" ] || selector+=(--canal "$CANAL")
  seleccion=$(python3 "$SCRIPT_DIR/wifi_capture_utils.py" "${selector[@]}") || exit 2
  read -r mac_encontrada canal_encontrado <<<"$seleccion"
  BSSID=$mac_encontrada
  CANAL=$canal_encontrado
fi
info "objetivo: BSSID=$BSSID · canal=$CANAL · SSID=${SSID:-no indicado}"

airodump-ng --channel "$CANAL" --bssid "$BSSID" --output-format pcap,csv \
  -w "$RUN_DIR/captura" "$MON_IFACE" >/dev/null 2>&1 &
CAP_PID=$!
if [ "$DEAUTH" -gt 0 ]; then
  sleep 5
  info "enviando $DEAUTH tandas de desconexión al BSSID indicado expresamente"
  aireplay-ng --ignore-negative-one -0 "$DEAUTH" -a "$BSSID" "$MON_IFACE" >"$RUN_DIR/deauth.log" 2>&1 || \
    info "no se pudo completar --deauth; la captura pasiva continúa"
fi
info "capturando durante $MINUTOS min"
sleep "$((MINUTOS * 60))"
parar_pid "$CAP_PID"; CAP_PID=
CAP_FILE="$RUN_DIR/captura-01.cap"
[ -s "$CAP_FILE" ] || error "no se generó una captura .cap"

if [ "$SOLO_CAPTURA" -eq 1 ]; then
  info "captura guardada sin conversión WPA 22000"
  printf 'Siguiente paso, por separado:\n  '
  printf '%q ' "$SCRIPT_DIR/auditor_generico.sh" --tipo wifi "$CAP_FILE"
  printf '\n'
  exit 0
fi

HASH_TODOS="$RUN_DIR/todos.22000"
HASH_OBJETIVO="$RUN_DIR/objetivo.22000"
if ! hcxpcapngtool -o "$HASH_TODOS" "$CAP_FILE" >"$RUN_DIR/conversion.log" 2>&1 || [ ! -s "$HASH_TODOS" ]; then
  info "captura guardada; no se obtuvo material WPA 22000 utilizable"
  exit 3
fi
set +e
filtro=(filtrar "$HASH_TODOS" "$HASH_OBJETIVO" --bssid "$BSSID")
[ -z "$SSID" ] || filtro+=(--ssid "$SSID")
resumen=$(python3 "$SCRIPT_DIR/wifi_capture_utils.py" "${filtro[@]}")
filtrado_rc=$?
set -e
rm -f -- "$HASH_TODOS"
if [ "$filtrado_rc" -ne 0 ]; then
  info "captura guardada; no hay PMKID/EAPOL válido del objetivo seleccionado"
  exit 3
fi
info "material del objetivo: $resumen"
printf 'Siguiente paso, por separado:\n  '
printf '%q ' "$SCRIPT_DIR/auditor_generico.sh" --tipo wifi --motor hashcat "$HASH_OBJETIVO"
printf '\n'
