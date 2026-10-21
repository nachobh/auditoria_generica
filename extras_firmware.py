#!/usr/bin/env python3
# Copyright 2026 Ignacio Benito Herrero
# Licensed under the Apache License, Version 2.0.
"""Triage YARA de firmwares de router: reglas Broadcom WPS Monitor (WPSplinter).

Genérico por modelo y proveedor: el usuario descarga el firmware del sitio de
soporte de su operadora (Orange, Movistar, Vodafone, Proximus…) y este modo
extrae el archivo (7z/tar/zip/gz/squashfs según proceda) y pasa las reglas
`third_party/broadcom-wps/broadcom_wps_monitor.yar` (Quentin Kaiser, MIT).
Las reglas buscan los binarios WPS Monitor de Broadcom en ELF32 ARM/MIPS;
`VULN_BRCM_WPS_EAP_Fragment_Reassembly_ELF` es la que apunta a la ruta de
reensamblado vulnerable. Son ayudas de triage: un firmware parcheado puede
conservar cuerdas/bytes de la firma (ver README del toolkit del autor).
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


REGLAS = Path(__file__).resolve().parent / "third_party" / "broadcom-wps" / "broadcom_wps_monitor.yar"
MAGICAS = {
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"PK\x03\x04": "zip",
    b"\x1f\x8b": "gz",
    b"hsqs": "squashfs(le)",
    b"sqsh": "squashfs(be)",
    b"Ustar": "tar",
}
# squashfs va por cabecera al final también; se comprueba aparte.


def _magicas(ruta, tope=64 * 1024 * 1024):
    with Path(ruta).open("rb") as archivo:
        cabecera = archivo.read(256)
        archivo.seek(0, os.SEEK_END)
        tam = archivo.tell()
        if tam <= tope:
            archivo.seek(max(0, tam - 256))
            pie = archivo.read()
        else:
            pie = b""
    for firma, nombre in MAGICAS.items():
        if cabecera.startswith(firma):
            return nombre
    if b"hsqs" in pie or b"sqsh" in pie:
        return "squashfs"
    if tam > 0 and cabecera[:4] in (b"\x7fELF",):
        return "elf"
    return None


def extraer(ruta, destino, profundidad=0):
    """Desenvuelve contenedores conocidos. Devuelve nº de capas tratadas."""
    if profundidad > 4:
        return 0
    tipo = _magicas(ruta)
    hecha = 0
    if tipo == "zip" or zipfile.is_zipfile(ruta):
        with zipfile.ZipFile(ruta) as z:
            z.extractall(destino)
        hecha = 1
    elif tipo == "tar" or tarfile.is_tarfile(ruta):
        with tarfile.open(ruta, "r:*") as t:
            t.extractall(destino, filter="data")
        hecha = 1
    elif tipo in ("7z", "gz") or str(ruta).endswith((".gz", ".7z", ".xz", ".bin", ".img")):
        siete = shutil.which("7z")
        if siete and tipo in ("7z", "gz"):
            rc = subprocess.run([siete, "x", f"-o{destino}", "-y", str(ruta)],
                                capture_output=True, timeout=600, check=False).returncode
            hecha = 1 if rc == 0 else 0
    if tipo and "squashfs" in tipo:
        unsquash = shutil.which("unsquashfs")
        if unsquash:
            rc = subprocess.run([unsquash, "-d", str(Path(destino) / "squashfs-root"),
                                 "-f", "-q", str(ruta)],
                                capture_output=True, timeout=600, check=False).returncode
            hecha = 1 if rc == 0 else hecha
    if hecha:
        # el contenedor suele dejar dentro otro archivo firmware: una capa más
        nuevos = [p for p in Path(destino).iterdir()
                  if p.is_file() and p.stat().st_size > 4096
                  and _magicas(p) in ("7z", "zip", "gz", "squashfs", "squashfs(le)",
                                      "squashfs(be)", "tar")]
        for nuevo in nuevos[:4]:
            hecha += extraer(nuevo, nuevo.parent / (nuevo.name + "_x"), profundidad + 1)
    return hecha


def escanear(ruta, reglas, seco=False):
    yara = shutil.which("yara")
    if not yara:
        raise ValueError("falta el binario yara (sudo apt-get install -y yara)")
    if not Path(reglas).is_file():
        raise ValueError(f"faltan las reglas en {reglas}")
    orden = [yara, "-w", "-r", str(reglas), str(ruta)]
    if seco:
        print("Plan: " + " ".join(orden))
        return 0
    proceso = subprocess.run(orden, capture_output=True, text=True, timeout=3600,
                             check=False)
    if proceso.returncode not in (0, 1):
        detalle = proceso.stderr.strip()
        raise ValueError(f"yara falló: {detalle or proceso.returncode}")
    aciertos = []
    for linea in proceso.stdout.splitlines():
        partes = linea.split(None, 1)
        if len(partes) == 2:
            aciertos.append((partes[1].strip(), partes[0]))
    return aciertos


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", help="ruta al firmware descargado")
    parser.add_argument("--url", help="URL de la que descargarlo si aún no lo tienes")
    parser.add_argument("--extraer", action="store_true",
                        help="desenvuelve contenedores antes de escanear (recomendado)")
    parser.add_argument("--conservar", help="directorio donde dejar el firmware extraído")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    reglas = str(REGLAS)
    origen = Path(args.firmware).expanduser()
    if args.dry_run and not args.url:
        print(f"Plan: yara -w -r {REGLAS} {origen}"
              + (" (tras extraer contenedores)" if args.extraer else ""))
        return 0
    if args.url and not origen.exists():
        origen.parent.mkdir(parents=True, exist_ok=True)
        if args.dry_run:
            print(f"Plan: curl -L {args.url} -o {origen} y escanear con yara")
            return 0
        rc = subprocess.run(["curl", "-sSL", "--max-time", "600", "-o", str(origen),
                             args.url], check=False).returncode
        if rc != 0 or not origen.is_file() or origen.stat().st_size == 0:
            print(f"Error: descarga fallida ({args.url})", file=sys.stderr)
            return 2
    if not origen.is_file() and not origen.is_dir():
        print(f"Error: no existe {origen} (pasa --url o descarga el firmware de tu "
              "operadora a mano)", file=sys.stderr)
        return 2
    destino = Path(args.conservar).expanduser() if args.conservar else None
    temporal = None
    objetivo = origen
    try:
        if args.extraer and origen.is_file():
            if destino:
                destino.mkdir(parents=True, exist_ok=True)
            else:
                temporal = tempfile.TemporaryDirectory(prefix="kit-firmware-")
                destino = Path(temporal.name)
            capas = extraer(origen, destino)
            print(f"Extracción: {capas} contenedor(es) desarrollados en {destino}")
            objetivo = destino
        aciertos = escanear(objetivo, reglas)
    finally:
        if temporal is not None and not args.conservar:
            pass  # TemporaryDirectory se limpia solo al salir el proceso
    if not aciertos:
        print("Sin coincidencias YARA: no se encontró el WPS Monitor de Broadcom "
              "en lo analizado. No es prueba de ausencia (reglas de triage): "
              "prueba --extraer si no lo usaste, o revisa el formato del "
              "firmware con file(1).")
        return 1
    vulnerables = [a for a in aciertos if a[1].startswith("VULN_")]
    for archivo, regla in aciertos:
        marca = "VULNERABLE" if regla.startswith("VULN_") else "detector"
        print(f"[{marca}] {regla} → {archivo}")
    if vulnerables:
        print("\nLa regla de la ruta de reensamblado vulnerable coincidió: firmware "
              "de la familia WPSplinter. Contrasta con el fingerprinter en aire "
              "(wifi-wpsplinter) antes de dar por hecho que está sin parchear.")
        return 0
    print("\nSólo detectores genéricos: hay WPS Monitor Broadcom pero la firma "
          "opcode de la ruta vulnerable no apareció (puede estar parcheado o "
          "ofuscada por compilación).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
