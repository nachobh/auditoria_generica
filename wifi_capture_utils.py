#!/usr/bin/env python3
"""Selecciona un AP en CSV de airodump-ng y filtra hashes WPA 22000 por AP."""

import argparse
import csv
import os
from pathlib import Path
import re
import sys
import tempfile


MAC = re.compile(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\Z")


def normalizar_mac(valor):
    mac = valor.strip().upper()
    if not MAC.fullmatch(mac):
        raise ValueError("BSSID inválido")
    return mac


def seleccionar_ap(csv_path, ssid=None, bssid=None, canal=None):
    bssid = normalizar_mac(bssid) if bssid else None
    encontrados = []
    with Path(csv_path).open(newline="", encoding="utf-8", errors="replace") as archivo:
        for fila in csv.reader(archivo):
            if not fila:
                continue
            primero = fila[0].strip()
            if primero == "Station MAC":
                break
            if primero == "BSSID" or len(fila) < 14:
                continue
            try:
                mac = normalizar_mac(primero)
                canal_detectado = int(fila[3].strip())
            except ValueError:
                continue
            if not 1 <= canal_detectado <= 233:
                continue
            nombre = fila[13].strip()
            if ((ssid is None or nombre == ssid)
                    and (bssid is None or mac == bssid)
                    and (canal is None or canal == canal_detectado)):
                encontrados.append((mac, canal_detectado))
    unicos = list(dict.fromkeys(encontrados))
    if not unicos:
        raise ValueError("no se encontró el SSID/BSSID en el escaneo")
    if len(unicos) != 1:
        detalle = ", ".join(f"{mac} (canal {canal})" for mac, canal in unicos)
        raise ValueError(f"objetivo ambiguo; indica --canal o --bssid: {detalle}")
    return unicos[0]


def filtrar_hashes(origen, destino, bssid, ssid=None):
    mac_ap = normalizar_mac(bssid).replace(":", "").lower()
    recuento = {"01": 0, "02": 0}
    destino = Path(destino)
    temporal = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="ascii", dir=destino.parent,
                                         prefix=".wifi_hash_", delete=False) as salida:
            temporal = Path(salida.name)
            with Path(origen).open(encoding="ascii", errors="replace") as entrada:
                for linea in entrada:
                    campos = linea.rstrip("\r\n").split("*")
                    if len(campos) < 6 or campos[0] != "WPA" or campos[1] not in recuento:
                        continue
                    if campos[3].lower() != mac_ap:
                        continue
                    if ssid is not None:
                        try:
                            nombre = bytes.fromhex(campos[5]).decode("utf-8")
                        except (ValueError, UnicodeError):
                            continue
                        if nombre != ssid:
                            continue
                    salida.write(linea.rstrip("\r\n") + "\n")
                    recuento[campos[1]] += 1
        if sum(recuento.values()):
            os.replace(temporal, destino)
            temporal = None
        return recuento
    finally:
        if temporal is not None:
            temporal.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="accion", required=True)
    scan = sub.add_parser("seleccionar")
    scan.add_argument("csv", type=Path)
    scan.add_argument("--ssid")
    scan.add_argument("--bssid")
    scan.add_argument("--canal", type=int)
    filtrar = sub.add_parser("filtrar")
    filtrar.add_argument("origen", type=Path)
    filtrar.add_argument("destino", type=Path)
    filtrar.add_argument("--bssid", required=True)
    filtrar.add_argument("--ssid")
    args = parser.parse_args()
    try:
        if args.accion == "seleccionar":
            mac, canal = seleccionar_ap(args.csv, args.ssid, args.bssid, args.canal)
            print(mac, canal)
        else:
            counts = filtrar_hashes(args.origen, args.destino, args.bssid, args.ssid)
            print(f"PMKID={counts['01']} EAPOL={counts['02']}")
            if not sum(counts.values()):
                return 3
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
