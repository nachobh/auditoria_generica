#!/usr/bin/env python3
"""Identificación pasiva de fabricante a partir del OUI de una MAC.

Usa la base IEEE (paquete ieee-data) instalada en el sistema. Es sólo una
consulta local sin conexión a ningún servicio externo: la MAC del objetivo
no sale de la máquina. Un OUI identifica al fabricante del chip/tarjeta de
red, no un modelo de router concreto; varios fabricantes de ISP comparten
el mismo OUI base para distintos modelos, así que esto es una pista, no una
identificación exacta del equipo.
"""

import re
from pathlib import Path

MAC = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")

RUTAS_BD = (
    "/usr/share/ieee-data/oui.txt",
    "/var/lib/ieee-data/oui.txt",
)

_CACHE = None


def _cargar_bd():
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    tabla = {}
    for ruta in RUTAS_BD:
        p = Path(ruta)
        if not p.is_file():
            continue
        try:
            texto = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for linea in texto.splitlines():
            m = re.match(r"^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.+?)\s*$", linea)
            if m:
                tabla[m.group(1).upper()] = m.group(2).strip()
        if tabla:
            break
    _CACHE = tabla
    return _CACHE


def vendor_de_mac(mac):
    """Fabricante asociado al OUI (primeros 3 octetos) de una MAC, o None."""
    if not mac or not MAC.fullmatch(mac.strip()):
        return None
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    return _cargar_bd().get(oui)


# Fabricantes de hardware/chipset conocidos por figurar en el aviso público
# de WPSplinter (Quentin Kaiser, oct. 2026) sobre un desbordamiento en el
# reensamblado EAP de WPS del stack 802.11 de Broadcom. Sin CVE asignado.
# Esto es sólo informativo: identifica routers que podrían compartir el
# chipset afectado, no confirma vulnerabilidad ni la explota.
VENDORS_WPSPLINTER = (
    "broadcom",
    "askey",
    "sagemcom",
    "technicolor",
    "arcadyan",
    "mitrastar",
    "netgear",
    "zte",
    "arris",
    "huawei",
    "tp-link",
    "tenda",
    "zyxel",
)


def posible_wpsplinter(vendor):
    """True si el fabricante identificado coincide con la lista pública de
    marcas citadas en el aviso de WPSplinter. No es una prueba de que el
    equipo esté afectado (no hay CVE ni PoC público): es sólo una señal
    para decidir si conviene desactivar WPS y preguntar al operador por un
    parche."""
    if not vendor:
        return False
    v = vendor.lower()
    return any(marca in v for marca in VENDORS_WPSPLINTER)


def main():
    import sys
    if len(sys.argv) != 2:
        print("uso: oui_lookup.py AA:BB:CC:DD:EE:FF", file=sys.stderr)
        return 2
    vendor = vendor_de_mac(sys.argv[1])
    if vendor is None:
        print("fabricante desconocido (OUI no encontrado localmente)")
        return 1
    print(vendor)
    if posible_wpsplinter(vendor):
        print("aviso: este fabricante figura en el listado público de WPSplinter "
              "(sin CVE, sin confirmación de que este equipo esté afectado); "
              "si usas WPS, considera desactivarlo y preguntar al operador por firmware")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
