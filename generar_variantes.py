#!/usr/bin/env python3
"""Genera candidatos offline acotados a partir de semillas autorizadas."""

import argparse
from datetime import date
import os
from pathlib import Path
import tempfile


MAX_SEMILLAS = 24


def leer_semillas(rutas):
    semillas = []
    vistas = set()
    for ruta in rutas:
        with open(ruta, encoding="utf-8", errors="replace") as origen:
            for linea in origen:
                semilla = linea.rstrip("\r\n")
                if not 3 <= len(semilla) <= 40 or not semilla.isprintable():
                    continue
                if semilla in vistas:
                    continue
                vistas.add(semilla)
                semillas.append(semilla)
                if len(semillas) >= MAX_SEMILLAS:
                    return semillas
    return semillas


def variantes(semillas, anio=None):
    anio = date.today().year if anio is None else anio
    casos = set()
    anios = set()
    sufijos = set()
    prefijos = set()
    uniones = set()
    for semilla in semillas:
        casos.update((semilla.lower(), semilla.upper(), semilla.title(),
                      semilla.replace("a", "@").replace("o", "0")))
        for valor in (anio - 1, anio, anio + 1):
            anios.add(f"{semilla}{valor}!")
        for numero in range(100):
            sufijos.add(f"{semilla}{numero:02d}")
            prefijos.add(f"{numero:02d}{semilla}")
    for primera in semillas[:8]:
        for segunda in semillas[:8]:
            if primera != segunda:
                uniones.add(f"{primera}-{segunda}")
                uniones.add(f"{primera}_{segunda}")
    return {
        "casos": casos,
        "anios": anios,
        "sufijos_2d": sufijos,
        "prefijos_2d": prefijos,
        "uniones": uniones,
    }


def guardar(destino, candidatos):
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destino.parent,
                                     prefix=".variantes_", delete=False) as temporal:
        temporal.writelines(f"{candidato}\n" for candidato in sorted(candidatos))
        nombre_temporal = temporal.name
    os.replace(nombre_temporal, destino)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--salida", required=True, type=Path)
    parser.add_argument("semillas", nargs="+", type=Path)
    args = parser.parse_args()
    args.salida.mkdir(mode=0o700, parents=True, exist_ok=True)
    grupos = variantes(leer_semillas(args.semillas))
    for nombre, candidatos in grupos.items():
        if candidatos:
            guardar(args.salida / f"extra_{nombre}.txt", candidatos)
            print(f"{nombre}: {len(candidatos)} candidatos")


if __name__ == "__main__":
    main()
