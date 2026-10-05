#!/usr/bin/env python3
"""Auditoría FTP acotada: intentos de contraseña en servidores FTP propios o autorizados."""

import argparse
import ftplib
import os
from pathlib import Path
import pwd
import re
import sys

HOST = re.compile(r"^[A-Za-z0-9._-]+(:[0-9]{1,5})?\Z")
USUARIO = re.compile(r"^[A-Za-z0-9._@-]{1,64}\Z")


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


def ftp_brute(host, usuario, lista, limite, seco=False):
    if not HOST.match(host):
        raise ValueError("destino inválido: usa host o host:puerto")
    if not USUARIO.match(usuario):
        raise ValueError("usuario inválido")
    if not 1 <= limite <= 200:
        raise ValueError("--limite-intentos debe estar entre 1 y 200")
    lista = ruta_lista(lista)
    if not lista.is_file():
        raise ValueError("lista de candidatos no encontrada")
    host_nombre = host.split(":")[0]
    puerto = int(host.split(":")[1]) if ":" in host else 21
    if seco:
        print(f"Plan: hasta {limite} candidatos de {lista.name} contra {usuario}@{host} "
              "por FTP; sin guardar contraseñas")
        return 0
    hechos = 0
    for candidato in candidatos(lista, limite):
        ftp = ftplib.FTP()
        try:
            ftp.connect(host_nombre, puerto, timeout=15)
            ftp.login(usuario, candidato)
            hechos += 1
            try:
                ftp.quit()
            except ftplib.Error:
                pass
            print(f"Acceso FTP confirmado tras {hechos} intentos; candidato oculto")
            return 0
        except ftplib.error_perm:
            hechos += 1
        except ftplib.error_temp as exc:
            print(f"Servidor limitó o cerró la conexión tras {hechos} intentos: "
                  f"{str(exc)[:80]}")
            return 3
        except (ftplib.Error, OSError) as exc:
            print(f"Error de conexión FTP en el intento {hechos + 1}: {str(exc)[:80]}")
            return 3
        finally:
            try:
                ftp.close()
            except Exception:
                pass
    unidad = "intento" if hechos == 1 else "intentos"
    print(f"Sin acceso en {hechos} {unidad}; no demuestra que la contraseña sea fuerte")
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="accion", required=True)
    br = sub.add_parser("ftp-brute")
    br.add_argument("--host", required=True)
    br.add_argument("--usuario", required=True)
    br.add_argument("--wl", default=str(Path(__file__).with_name("ejemplos") /
                                        "candidatos_web_ficticios.txt"))
    br.add_argument("--limite-intentos", type=int, default=3)
    br.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        return ftp_brute(args.host, args.usuario, args.wl, args.limite_intentos,
                         args.dry_run)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
