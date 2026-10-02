#!/usr/bin/env python3
"""Genera ejemplos mínimos y ficticios de ZipCrypto y PDF restringido."""

import argparse
from pathlib import Path
import shutil
import subprocess


CLAVE_ZIP_FICTICIA = "clave_sintetica_01!"
CLAVE_OWNER_FICTICIA = "propietario_ficticio_01!"


def pdf_minimo(texto):
    contenido = f"BT /F1 12 Tf 40 150 Td ({texto}) Tj ET\n".encode("ascii")
    objetos = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(contenido)).encode() + b" >>\nstream\n" + contenido + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    posiciones = [0]
    for numero, objeto in enumerate(objetos, 1):
        posiciones.append(len(pdf))
        pdf.extend(f"{numero} 0 obj\n".encode() + objeto + b"\nendobj\n")
    inicio_xref = len(pdf)
    pdf.extend(f"xref\n0 {len(posiciones)}\n0000000000 65535 f \n".encode())
    for posicion in posiciones[1:]:
        pdf.extend(f"{posicion:010d} 00000 n \n".encode())
    pdf.extend(f"trailer\n<< /Size {len(posiciones)} /Root 1 0 R >>\nstartxref\n{inicio_xref}\n%%EOF\n".encode())
    return bytes(pdf)


def generar(salida):
    salida = Path(salida)
    salida.mkdir(parents=True, exist_ok=True)
    plano = salida / "texto_conocido.txt"
    plano.write_text("Este contenido es ficticio y conocido para la demo.\n", encoding="utf-8")
    if shutil.which("7z"):
        subprocess.run(["7z", "a", "-y", "-tzip", "-mem=ZipCrypto", "-mx=0",
                        "-p" + CLAVE_ZIP_FICTICIA, str(salida / "zipcrypto_demo.zip"),
                        plano.name], cwd=salida, check=True, stdout=subprocess.DEVNULL)
    else:
        print("Falta 7z: sólo se generó el texto conocido")
    pdf = salida / "documento_demo.pdf"
    pdf.write_bytes(pdf_minimo("PDF ficticio de demostracion"))
    if shutil.which("qpdf"):
        subprocess.run(["qpdf", "--encrypt", "", CLAVE_OWNER_FICTICIA, "256",
                        "--print=none", "--modify=none", "--extract=n", "--",
                        str(pdf), str(salida / "pdf_restringido_demo.pdf")], check=True)
    else:
        print("Falta qpdf: sólo se generó el PDF abierto")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--salida", default=str(Path(__file__).with_name("extras")))
    args = parser.parse_args()
    generar(args.salida)


if __name__ == "__main__":
    main()
