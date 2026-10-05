#!/usr/bin/env python3
"""Búsqueda de credenciales expuestas en ficheros: claves privadas, tokens,
parámetros password=, URLs con usuario:contraseña. Salida enmascarada."""

import argparse
import os
from pathlib import Path
import re
import sys
import stat
import tempfile

PATRONES = (
    ("clave-privada", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("token-genérico", re.compile(r"(?i)\b(?:api[_-]?token|auth[_-]?token|access[_-]?token|secret[_-]?key)\b\s*[:=]\s*[\"']?([^\s\"',;]{8,128})")),
    ("password-fichero", re.compile(r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*[\"']?([^\s\"',;]{1,128})")),
    ("url-credenciales", re.compile(r"\b[a-z][a-z0-9+.-]*://([^/\s:@]{1,64}):([^/\s@]{1,128})@")),
    ("token-formato", re.compile(
        r"\b(sk-[A-Za-z0-9]{16,64}"
        r"|ghp_[A-Za-z0-9]{20,}"
        r"|github_pat_[A-Za-z0-9_]{36,}"
        r"|glpat-[A-Za-z0-9_-]{20,}"
        r"|npm_[A-Za-z0-9]{36}"
        r"|dckr_pat_[A-Za-z0-9_-]{20,}"
        r"|xox[baprs]-[A-Za-z0-9-]{10,})\b"
    )),
)

EXCLUIDOS = {".git", "__pycache__", "node_modules", ".venv", "vendor"}
MAX_BYTES = 2 * 1024 * 1024
MAX_CANDIDATOS = 200


def enmascarar(valor):
    if len(valor) <= 4:
        return valor[0] + "*" * (len(valor) - 1)
    return valor[:2] + "*" * (len(valor) - 4) + valor[-2:]


def escanear_arbol(ruta, maximo=MAX_CANDIDATOS):
    raiz = Path(ruta)
    if raiz.is_symlink():
        raise ValueError("la ruta del escaneo no puede ser un enlace simbólico")
    if not raiz.exists():
        raise ValueError("la ruta no existe")
    objetivos = [raiz] if raiz.is_file() else []
    if raiz.is_dir():
        for carpeta, directorios, archivos in os.walk(raiz, followlinks=False):
            directorios[:] = sorted(d for d in directorios if d not in EXCLUIDOS
                                    and not (Path(carpeta) / d).is_symlink())
            objetivos.extend(Path(carpeta) / nombre for nombre in sorted(archivos))
    hallazgos = []
    candidatos = []
    for fichero in objetivos:
        try:
            fd = os.open(fichero, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as entrada:
                info = os.fstat(entrada.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                    continue
                datos = entrada.read(MAX_BYTES + 1)
            if len(datos) > MAX_BYTES:
                continue
            texto = datos.decode("utf-8", errors="ignore")
        except OSError:
            continue
        if "\0" in texto[:4096]:
            continue
        for numero, linea in enumerate(texto.splitlines(), 1):
            for nombre, patron in PATRONES:
                for m in patron.finditer(linea):
                    grupos = [g for g in m.groups() if g]
                    valor = grupos[-1] if grupos else m.group(0)
                    if valor.lower() in {"changeme", "password", "tu_clave", "example",
                                         "ejemplo", "your_api_key", "your_token",
                                         "replace_me", "insert_here", "todo",
                                         "<password>", "<token>", "<secret>"}:
                        continue
                    hallazgos.append((str(fichero), numero, nombre, enmascarar(valor)))
                    if nombre in {"password-fichero", "url-credenciales"} and valor not in candidatos:
                        candidatos.append(valor)
                    if len(hallazgos) >= maximo:
                        return hallazgos, candidatos
    return hallazgos, candidatos


def cred_scan(ruta, generar=None, maximo=MAX_CANDIDATOS, seco=False):
    if seco:
        print(f"Plan: escaneo de credenciales en {ruta} (máx {maximo} hallazgos, "
              f"ficheros de texto de hasta {MAX_BYTES // (1024*1024)} MB); salida enmascarada")
        return 0
    hallazgos, candidatos = escanear_arbol(ruta, maximo)
    if not hallazgos:
        print("Sin hallazgos; el escaneo no demuestra ausencia de credenciales")
        return 1
    for fichero, numero, nombre, valor in hallazgos:
        print(f"{fichero}:{numero} {nombre} {valor}")
    print(f"Total: {len(hallazgos)} hallazgos (valores enmascarados; el original sólo "
          "queda en la lista generada si la pides)")
    if generar:
        destino = Path(generar)
        if destino.is_symlink():
            raise ValueError(f"el destino {destino} es un enlace simbólico; se rechaza por seguridad")
        # temporal exclusivo 0600 en el mismo directorio: sin predicción de nombre,
        # sin seguir enlaces, y la lista final nunca queda legible por grupo/otros.
        fd, nombre_temporal = tempfile.mkstemp(dir=str(destino.parent or Path(".")),
                                               prefix=destino.name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as salida:
                for candidato in candidatos:
                    salida.write(candidato + "\n")
            os.replace(nombre_temporal, destino)
        except BaseException:
            Path(nombre_temporal).unlink(missing_ok=True)
            raise
        print(f"Lista de candidatos para otras auditorías: {destino} ({len(candidatos)} líneas, permisos 0600)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="accion", required=True)
    cs = sub.add_parser("cred-scan")
    cs.add_argument("ruta")
    cs.add_argument("--generar", help="escribe aquí las contraseñas candidatas encontradas")
    cs.add_argument("--maximo", type=int, default=MAX_CANDIDATOS)
    cs.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.maximo <= 50000:
            raise ValueError("--maximo debe estar entre 1 y 50000")
        return cred_scan(args.ruta, args.generar, args.maximo, args.dry_run)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
