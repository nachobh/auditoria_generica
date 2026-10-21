#!/usr/bin/env python3
"""Extrae sólo el estado WPS del AP elegido de la salida pasiva de wash."""

import argparse
import re
import sys


MAC = re.compile(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)?\Z")

# Claves del volcado "-j" de wash (texto cuasi-JSON, no siempre válido con
# json.loads por comas finales, de ahí el parseo tolerante por regex).
_CAMPOS_JSON = (
    "bssid", "essid", "channel", "rssi", "wps_version", "wps_locked",
    "wps_manufacturer", "wps_model_name", "wps_model_number",
    "wps_device_name", "wps_primary_device_type", "wps_uuid", "wps_state",
)
_CAMPO_RE = {
    campo: re.compile(r'"%s"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+))' % re.escape(campo))
    for campo in _CAMPOS_JSON
}


def lista_wps(lineas):
    """Todas las filas WPS de la salida de wash: (bssid, canal, version, lock, essid)."""
    filas = []
    for linea in lineas:
        campos = linea.split()
        if len(campos) < 6 or not MAC.fullmatch(campos[0].upper()):
            continue
        try:
            canal = int(campos[1])
        except ValueError:
            continue
        if not 1 <= canal <= 233 or not VERSION.fullmatch(campos[3]):
            continue
        essid = " ".join(campos[6:])[:64] if len(campos) > 6 else ""
        filas.append((campos[0].upper(), canal, campos[3], campos[4], essid))
    return list(dict.fromkeys(filas))


def estado_wps(lineas, bssid, canal):
    objetivo = bssid.upper()
    if not MAC.fullmatch(objetivo):
        raise ValueError("BSSID inválido")
    encontrado = None
    for linea in lineas:
        campos = linea.split()
        if len(campos) < 5 or campos[0].upper() != objetivo:
            continue
        if campos[1] != str(canal) or not VERSION.fullmatch(campos[3]):
            continue
        encontrado = (campos[3], campos[4])
    return encontrado


def parse_wash_json(texto):
    """Filas enriquecidas del volcado "-j" de wash: lista de diccionarios.

    wash sólo rellena wps_manufacturer/model_name/model_number/device_name
    cuando el AP los incluyó en el beacon o respondió a un probe request
    (--scan); en supervisión puramente pasiva pueden venir vacíos. Ese dato
    lo emite el propio router como parte del protocolo WPS: no es un dato
    que esta herramienta extraiga de forma activa ni oculta.

    El parseo es por regex (no json.loads) porque la salida de wash no es
    JSON estricto: repite claves por cada AP sin separador de objeto fiable
    y puede llevar comas finales.
    """
    filas = []
    actual = {}
    for m in re.finditer(r'"([a-z_]+)"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+))', texto):
        campo, val_str, val_num = m.groups()
        if campo not in _CAMPOS_JSON:
            continue
        if campo == "bssid" and "bssid" in actual:
            if actual.get("bssid"):
                filas.append(actual)
            actual = {}
        actual[campo] = val_str if val_str is not None else val_num
    if actual.get("bssid"):
        filas.append(actual)
    normalizadas = []
    for fila in filas:
        bssid = (fila.get("bssid") or "").upper()
        if not MAC.fullmatch(bssid):
            continue
        try:
            canal = int(fila.get("channel", "0"))
        except ValueError:
            continue
        normalizadas.append({
            "bssid": bssid,
            "canal": canal,
            "essid": fila.get("essid", "")[:64],
            "version": fila.get("wps_version", ""),
            "locked": "Yes" if fila.get("wps_locked") in ("1", 1) else "No",
            "manufacturer": (fila.get("wps_manufacturer") or "").strip(),
            "model_name": (fila.get("wps_model_name") or "").strip(),
            "model_number": (fila.get("wps_model_number") or "").strip(),
            "device_name": (fila.get("wps_device_name") or "").strip(),
        })
    return normalizadas


def etiqueta_modelo(fila, vendor_oui=None):
    """Texto legible de fabricante/modelo para una fila de parse_wash_json.

    Prioriza el fabricante/modelo que el propio router anunció por WPS
    (dato directo); si no está disponible, usa vendor_oui (fabricante del
    chip de red por MAC, una pista, no el modelo exacto del router) y lo
    marca como estimado.
    """
    partes = [fila.get("manufacturer", ""), fila.get("model_name", ""),
              fila.get("model_number", "")]
    texto = " ".join(p for p in partes if p and p.lower() not in ("unknown", "n/a")).strip()
    if texto:
        return texto
    if vendor_oui:
        return f"{vendor_oui} (estimado por MAC, no es el modelo exacto)"
    return ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bssid", required=True)
    parser.add_argument("--canal", required=True, type=int)
    args = parser.parse_args()
    try:
        resultado = estado_wps(sys.stdin, args.bssid, args.canal)
    except ValueError as exc:
        parser.error(str(exc))
    if resultado is None:
        return 3
    print(*resultado)
    return 0


if __name__ == "__main__":
    sys.exit(main())
