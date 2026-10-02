#!/usr/bin/env python3
"""Inventario estático mínimo de imports, exports y memoria de un módulo WASM."""

import argparse
from pathlib import Path


def uleb(datos, posicion):
    numero = 0
    for vuelta in range(10):
        if posicion >= len(datos):
            raise ValueError("WASM truncado")
        byte = datos[posicion]
        posicion += 1
        numero |= (byte & 0x7f) << (7 * vuelta)
        if not byte & 0x80:
            return numero, posicion
    raise ValueError("LEB128 demasiado largo")


def nombre(datos, posicion):
    longitud, posicion = uleb(datos, posicion)
    if longitud > 1024 or posicion + longitud > len(datos):
        raise ValueError("nombre WASM inválido")
    return datos[posicion:posicion + longitud].decode("utf-8", errors="replace"), posicion + longitud


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
    datos = ruta.read_bytes()
    if datos[:8] != b"\0asm\x01\0\0\0":
        raise ValueError("no es un módulo WASM binario v1")
    imports, exports = [], []
    posicion = 8
    while posicion < len(datos):
        seccion = datos[posicion]
        tamaño, posicion = uleb(datos, posicion + 1)
        fin = posicion + tamaño
        if fin > len(datos):
            raise ValueError("sección WASM truncada")
        if seccion in {2, 7}:
            cantidad, actual = uleb(datos, posicion)
            if cantidad > 10000:
                raise ValueError("demasiadas entradas WASM")
            for _ in range(cantidad):
                if seccion == 2:
                    modulo, actual = nombre(datos, actual)
                    campo, actual = nombre(datos, actual)
                    tipo = datos[actual]
                    actual += 1
                    if tipo == 0:
                        _, actual = uleb(datos, actual)
                    elif tipo == 1:
                        actual += 1
                        actual = limites(datos, actual)
                    elif tipo == 2:
                        actual = limites(datos, actual)
                    elif tipo == 3:
                        actual += 2
                    else:
                        raise ValueError("tipo de import WASM no admitido")
                    imports.append((modulo, campo, tipo))
                else:
                    campo, actual = nombre(datos, actual)
                    tipo = datos[actual]
                    actual += 1
                    _, actual = uleb(datos, actual)
                    exports.append((campo, tipo))
            if actual > fin:
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
