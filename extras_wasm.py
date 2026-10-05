#!/usr/bin/env python3
"""Inventario estático mínimo de imports, exports y memoria de un módulo WASM."""

import argparse
from pathlib import Path


def uleb(datos, posicion):
    numero = 0
    for vuelta in range(5):
        if posicion >= len(datos):
            raise ValueError("WASM truncado")
        byte = datos[posicion]
        posicion += 1
        if vuelta == 4 and byte & 0xf0:
            raise ValueError("LEB128 fuera del rango de 32 bits")
        numero |= (byte & 0x7f) << (7 * vuelta)
        if not byte & 0x80:
            return numero, posicion
    raise ValueError("LEB128 demasiado largo")


def nombre(datos, posicion):
    longitud, posicion = uleb(datos, posicion)
    if longitud > 1024 or posicion + longitud > len(datos):
        raise ValueError("nombre WASM inválido")
    return datos[posicion:posicion + longitud].decode("utf-8"), posicion + longitud


def leer_byte(datos, posicion):
    if posicion >= len(datos):
        raise ValueError("WASM truncado")
    return datos[posicion], posicion + 1


def limites(datos, posicion):
    flags, posicion = uleb(datos, posicion)
    _, posicion = uleb(datos, posicion)
    if flags & 1:
        _, posicion = uleb(datos, posicion)
    return posicion


def inventario(ruta):
    ruta = Path(ruta)
    if ruta.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("WASM demasiado grande para este inventario (máximo 8 MiB)")
    with ruta.open("rb") as entrada:
        datos = entrada.read(8 * 1024 * 1024 + 1)
    if len(datos) > 8 * 1024 * 1024:
        raise ValueError("WASM demasiado grande para este inventario (máximo 8 MiB)")
    if datos[:8] != b"\0asm\x01\0\0\0":
        raise ValueError("no es un módulo WASM binario v1")
    imports, exports = [], []
    vistas = set()
    posicion = 8
    while posicion < len(datos):
        seccion = datos[posicion]
        tamaño, posicion = uleb(datos, posicion + 1)
        fin = posicion + tamaño
        if fin > len(datos):
            raise ValueError("sección WASM truncada")
        if seccion in {2, 7}:
            if seccion in vistas:
                raise ValueError("sección de inventario WASM duplicada")
            vistas.add(seccion)
            # Cada lector sólo puede acceder al contenido de esta sección.
            contenido = datos[posicion:fin]
            cantidad, actual = uleb(contenido, 0)
            if cantidad > 10000:
                raise ValueError("demasiadas entradas WASM")
            for _ in range(cantidad):
                if seccion == 2:
                    modulo, actual = nombre(contenido, actual)
                    campo, actual = nombre(contenido, actual)
                    tipo, actual = leer_byte(contenido, actual)
                    if tipo == 0:
                        _, actual = uleb(contenido, actual)
                    elif tipo == 1:
                        _, actual = leer_byte(contenido, actual)
                        actual = limites(contenido, actual)
                    elif tipo == 2:
                        actual = limites(contenido, actual)
                    elif tipo == 3:
                        _, actual = leer_byte(contenido, actual)
                        _, actual = leer_byte(contenido, actual)
                    else:
                        raise ValueError("tipo de import WASM no admitido")
                    imports.append((modulo, campo, tipo))
                else:
                    campo, actual = nombre(contenido, actual)
                    tipo, actual = leer_byte(contenido, actual)
                    if tipo not in {0, 1, 2, 3}:
                        raise ValueError("tipo de export WASM no admitido")
                    _, actual = uleb(contenido, actual)
                    exports.append((campo, tipo))
            if actual != len(contenido):
                raise ValueError("sección WASM inválida")
        posicion = fin
    return imports, exports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archivo")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.dry_run:
            print(f"Plan: inventario estático de {Path(args.archivo).name}; no ejecuta WASM")
            return 0
        imports, exports = inventario(args.archivo)
    except (OSError, ValueError, IndexError) as exc:
        parser.error(str(exc))
    print(f"Imports: {len(imports)}; exports: {len(exports)}")
    for modulo, campo, tipo in imports[:16]:
        print(f"  import {modulo!r}.{campo!r} (tipo {tipo})")
    for campo, tipo in exports[:16]:
        print(f"  export {campo!r} (tipo {tipo})")
    print("Inventario de superficie: revisar permisos del host y código JS; no confirma vulnerabilidad")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
