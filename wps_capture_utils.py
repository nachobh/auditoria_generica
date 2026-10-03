#!/usr/bin/env python3
"""Extrae sólo el estado WPS del AP elegido de la salida pasiva de wash."""

import argparse
import re
import sys


MAC = re.compile(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)?\Z")


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
