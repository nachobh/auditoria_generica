#!/usr/bin/env python3
"""Genera un módulo WASM ficticio diminuto con un import y memoria exportada."""

from pathlib import Path


def seccion(numero, contenido):
    if len(contenido) >= 128:
        raise ValueError("ejemplo demasiado grande")
    return bytes((numero, len(contenido))) + contenido


def generar(salida):
    modulo = b"\0asm\x01\0\0\0"
    modulo += seccion(1, b"\x01\x60\x00\x00")
    modulo += seccion(2, b"\x01\x03env\x03log\x00\x00")
    modulo += seccion(5, b"\x01\x00\x01")
    modulo += seccion(7, b"\x01\x06memory\x02\x00")
    salida = Path(salida)
    salida.parent.mkdir(parents=True, exist_ok=True)
    salida.write_bytes(modulo)


if __name__ == "__main__":
    generar(Path(__file__).with_name("extras") / "modulo_ficticio.wasm")
