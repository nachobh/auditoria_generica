#!/usr/bin/env python3
"""Auditoría SSH acotada: intentos de contraseña con sshpass sobre objetivos autorizados."""

import argparse
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys

HOST = re.compile(r"^[A-Za-z0-9._-]+(:[0-9]{1,5})?\Z")
USUARIO = re.compile(r"^[A-Za-z0-9._-]{1,64}\Z")


def ruta_lista(ruta):
    ruta = str(ruta)
    if ruta.startswith("~/") and os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        try:
            return Path(pwd.getpwnam(os.environ["SUDO_USER"]).pw_dir) / ruta[2:]
        except KeyError as exc:
            raise ValueError("usuario original de sudo no encontrado") from exc
    return Path(ruta).expanduser()


def candidatos(ruta, maximo):
    with Path(ruta).open(encoding="utf-8", errors="replace") as archivo:
        for linea in archivo:
            candidato = linea.rstrip("\r\n")
            if candidato and not candidato.startswith("#") and len(candidato) <= 128:
                yield candidato
                maximo -= 1
                if maximo == 0:
                    return


def ssh_brute(host, usuario, lista, limite, seco=False):
    if not HOST.match(host):
        raise ValueError("destino inválido: usa host o host:puerto")
    if not USUARIO.match(usuario):
        raise ValueError("usuario inválido")
    if not 1 <= limite <= 200:
        raise ValueError("--limite-intentos debe estar entre 1 y 200")
    lista = ruta_lista(lista)
    if not lista.is_file():
        raise ValueError("lista de candidatos no encontrada")
    if seco:
        print(f"Plan: hasta {limite} candidatos de {lista.name} contra {usuario}@{host} "
              "con sshpass; sin guardar contraseñas")
        return 0
    sshpass, ssh = shutil.which("sshpass"), shutil.which("ssh")
    if not (sshpass and ssh):
        raise ValueError("faltan sshpass y/o ssh (sudo apt-get install -y sshpass openssh-client)")
    hechos = 0
    for candidato in candidatos(lista, limite):
        orden = [sshpass, "-e", ssh,
                 "-o", "BatchMode=no",
                 "-o", "PreferredAuthentications=password",
                 "-o", "PubkeyAuthentication=no",
                 "-o", "NumberOfPasswordPrompts=1",
                 "-o", "ConnectTimeout=10",
                 "-o", "StrictHostKeyChecking=accept-new",
                 "-p", (host.split(":")[1] if ":" in host else "22"),
                 f"{usuario}@{host.split(':')[0]}", "exit"]
        entorno = os.environ.copy()
        entorno["SSHPASS"] = candidato
        try:
            proceso = subprocess.run(orden, capture_output=True, timeout=30,
                                     check=False, env=entorno)
        except subprocess.TimeoutExpired:
            print(f"Tiempo agotado en el intento {hechos + 1}; estado desconocido")
            return 3
        hechos += 1
        salida = proceso.stderr.decode(errors="replace").lower()
        if proceso.returncode == 0:
            print(f"Acceso SSH confirmado tras {hechos} intentos; candidato oculto")
            return 0
        if "too many authentication failures" in salida or "connection closed" in salida:
            print(f"El servidor limita intentos tras {hechos}; prueba detenida por cortesía")
            return 0 if hechos else 3
        if "permission denied" not in salida and proceso.returncode not in {5, 255}:
            print(f"Respuesta inesperada de ssh (código {proceso.returncode}); se detiene la prueba")
            return 3
    unidad = "intento" if hechos == 1 else "intentos"
    print(f"Sin acceso en {hechos} {unidad}; no demuestra que la contraseña sea fuerte")
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="accion", required=True)
    br = sub.add_parser("ssh-brute")
    br.add_argument("--host", required=True)
    br.add_argument("--usuario", required=True)
    br.add_argument("--wl", default=str(Path(__file__).with_name("ejemplos") /
                                        "candidatos_web_ficticios.txt"))
    br.add_argument("--limite-intentos", type=int, default=3)
    br.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        return ssh_brute(args.host, args.usuario, args.wl, args.limite_intentos,
                         args.dry_run)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
