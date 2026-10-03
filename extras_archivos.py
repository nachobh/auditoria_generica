#!/usr/bin/env python3
"""Pruebas acotadas de ZipCrypto y restricciones de PDF."""

import argparse
from pathlib import Path
import resource
import shutil
import subprocess
import tempfile
import zipfile


def limitar_log():
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))


def zip_conocido(archivo, entrada, plano, max_seg=120, seco=False):
    archivo, plano = Path(archivo), Path(plano)
    if not archivo.is_file() or not plano.is_file():
        raise ValueError("falta el ZIP o el texto conocido")
    with zipfile.ZipFile(archivo) as zip_obj:
        try:
            dato = zip_obj.getinfo(entrada)
        except KeyError as exc:
            raise ValueError("entrada no encontrada en el ZIP") from exc
        if not dato.flag_bits & 1 or dato.compress_type == 99:
            raise ValueError("la entrada no usa ZipCrypto heredado")
    if plano.stat().st_size < 12:
        raise ValueError("se necesitan al menos 12 bytes de texto conocido")
    if not 1 <= max_seg <= 6000:
        raise ValueError("--max-seg debe estar entre 1 y 6000")
    if seco:
        print(f"Plan: bkcrack sobre {archivo.name}, entrada {entrada}, límite {max_seg}s")
        return 0
    binario = shutil.which("bkcrack")
    if not binario:
        raise ValueError("falta bkcrack; consulta su instalación opcional en README")
    with tempfile.TemporaryFile() as salida:
        try:
            proceso = subprocess.run([binario, "-C", str(archivo), "-c", entrada,
                                      "-p", str(plano)], stdout=salida,
                                     stderr=subprocess.STDOUT, timeout=max_seg,
                                     check=False, preexec_fn=limitar_log)
        except subprocess.TimeoutExpired:
            print("Tiempo agotado; no se demostró la debilidad en este plazo")
            return 3
        salida.seek(0)
        informe = salida.read(1024 * 1024).decode(errors="replace")
    if proceso.returncode == 0 and "Found a solution" in informe:
        print("Estado interno ZipCrypto recuperado; claves y contenido ocultos")
        return 0
    print("No se recuperó el estado interno; comprueba que el texto coincide con la entrada cifrada")
    return 1


def pdf_permisos(archivo, seco=False):
    archivo = Path(archivo)
    if not archivo.is_file():
        raise ValueError("PDF no encontrado")
    if seco:
        print(f"Plan: inspeccionar permisos y probar apertura sin clave en {archivo.name}")
        return 0
    binario = shutil.which("qpdf")
    if not binario:
        raise ValueError("falta qpdf; consulta su instalación opcional en README")
    datos = subprocess.run([binario, "--show-encryption", str(archivo)],
                           capture_output=True, text=True, timeout=15, check=False)
    if datos.returncode != 0:
        print("No se pudo leer el cifrado del PDF")
        return 3
    if "File is not encrypted" in datos.stdout:
        print("PDF sin cifrar; no aplica la prueba de permisos")
        return 1
    lineas = dict(linea.split("=", 1) for linea in datos.stdout.splitlines() if " = " in linea)
    usuario = lineas.get("User password ", "desconocido").strip()
    restringido = "extract for any purpose: not allowed" in datos.stdout
    with tempfile.TemporaryDirectory() as temporal:
        destino = Path(temporal) / "abierto.pdf"
        apertura = subprocess.run([binario, "--decrypt", str(archivo), str(destino)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=15, check=False)
        accesible = apertura.returncode == 0 and destino.is_file()
    if usuario == "" and restringido and accesible:
        print("PDF accesible sin clave de apertura pese a prohibir extracción; permiso no equivale a cifrado de acceso")
        return 0
    print("No se observó el patrón de PDF con acceso libre y extracción restringida")
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="accion", required=True)
    zip_arg = sub.add_parser("zip-conocido")
    zip_arg.add_argument("archivo")
    zip_arg.add_argument("--entrada", required=True)
    zip_arg.add_argument("--plano", required=True)
    zip_arg.add_argument("--max-seg", type=int, default=120)
    zip_arg.add_argument("--dry-run", action="store_true")
    pdf_arg = sub.add_parser("pdf-permisos")
    pdf_arg.add_argument("archivo")
    pdf_arg.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.accion == "zip-conocido":
            return zip_conocido(args.archivo, args.entrada, args.plano,
                                args.max_seg, args.dry_run)
        return pdf_permisos(args.archivo, args.dry_run)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
