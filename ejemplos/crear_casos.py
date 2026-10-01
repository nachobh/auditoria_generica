#!/usr/bin/env python3
"""Crea hashes MD5 de contraseñas inventadas para la demo offline."""

import argparse
from datetime import date
import hashlib
from pathlib import Path


def casos(anio=None):
    anio = date.today().year if anio is None else anio
    return {
        "01_directa": "FiccionCometa",
        "02_cambio_caso": "FICCIONNUBE",
        "03_anio_simbolo": f"FiccionCometa{anio}!",
        "04_sufijo_dos_cifras": "FiccionLago37",
        "05_prefijo_dos_cifras": "42FiccionBosque",
        "06_dos_palabras": "FiccionCometa-FiccionNube",
        "07_pin_cuatro": "0427",
        "08_pin_seis": "004271",
    }


def crear(salida, anio=None):
    salida.mkdir(parents=True, mode=0o700, exist_ok=True)
    ejemplos = casos(anio)
    existentes = [nombre for nombre in ejemplos if (salida / f"{nombre}.md5").exists()]
    if existentes:
        raise FileExistsError(f"ya existen ejemplos en {salida}; elige un directorio vacío")
    for nombre, ficticia in ejemplos.items():
        destino = salida / f"{nombre}.md5"
        with destino.open("x", encoding="ascii") as archivo:
            archivo.write(hashlib.md5(ficticia.encode()).hexdigest() + "\n")
    return len(ejemplos)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--salida", required=True, type=Path)
    args = parser.parse_args()
    cantidad = crear(args.salida)
    print(f"{cantidad} hashes ficticios creados en {args.salida}")
    print("No contienen contraseñas reales ni datos personales; cada archivo tiene un hash.")


if __name__ == "__main__":
    main()
