#!/usr/bin/env python3
"""Pruebas web acotadas para cuentas y formularios autorizados."""

import argparse
import http.cookiejar
import os
from pathlib import Path
import pwd
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener


class SinRedireccion(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def validar_url(url):
    partes = urlsplit(url)
    if partes.username or partes.password or partes.fragment:
        raise ValueError("URL con credenciales o fragmento no admitida")
    if partes.scheme == "https" and partes.hostname:
        return url
    if partes.scheme == "http" and partes.hostname in {"127.0.0.1", "localhost", "::1"}:
        return url
    raise ValueError("usa HTTPS o HTTP en localhost")


def consultar(opener, url, datos=None):
    peticion = Request(url, data=datos, headers={"User-Agent": "kit-auditoria-claves/1.0"})
    try:
        respuesta = opener.open(peticion, timeout=20)
    except HTTPError as exc:
        respuesta = exc
    cuerpo = respuesta.read(65536)
    estado, cabeceras = respuesta.status, respuesta.headers
    respuesta.close()
    return estado, cabeceras, cuerpo


def candidatos(ruta, maximo):
    with Path(ruta).open(encoding="utf-8") as archivo:
        for linea in archivo:
            candidato = linea.rstrip("\r\n")
            if candidato and not candidato.startswith("#") and len(candidato) <= 128:
                yield candidato
                maximo -= 1
                if maximo == 0:
                    return


def ruta_lista(ruta):
    ruta = str(ruta)
    if ruta.startswith("~/") and os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        try:
            return Path(pwd.getpwnam(os.environ["SUDO_USER"]).pw_dir) / ruta[2:]
        except KeyError as exc:
            raise ValueError("usuario original de sudo no encontrado") from exc
    return Path(ruta).expanduser()


def login(url, usuario, lista, limite, seco=False, pausa=1):
    validar_url(url)
    lista = ruta_lista(lista)
    if not 1 <= limite <= 5:
        raise ValueError("--limite-intentos debe estar entre 1 y 5")
    if not usuario or len(usuario) > 64 or "\n" in usuario or "\r" in usuario:
        raise ValueError("indica un usuario válido")
    if not Path(lista).is_file():
        raise ValueError("lista de candidatos no encontrada")
    if seco:
        print(f"Plan: hasta {limite} primeros candidatos válidos de la lista en {url}; sin guardar candidatos")
        return 0
    cookies = http.cookiejar.CookieJar()
    opener = build_opener(HTTPCookieProcessor(cookies), SinRedireccion())
    try:
        estado, _, _ = consultar(opener, url)
    except (URLError, TimeoutError) as exc:
        print(f"No se pudo cargar el formulario: {exc}")
        return 3
    if estado != 200:
        print(f"La página de acceso respondió HTTP {estado}; no se enviaron intentos")
        return 3
    hechos = 0
    for candidato in candidatos(lista, limite):
        datos = urlencode({"log": usuario, "pwd": candidato, "wp-submit": "Log In",
                           "testcookie": "1", "redirect_to": "/wp-admin/"}).encode()
        try:
            estado, _, _ = consultar(opener, url, datos)
        except (URLError, TimeoutError) as exc:
            print(f"Error de conexión en el intento {hechos + 1}; estado desconocido: {exc}")
            return 3
        hechos += 1
        if any(cookie.name.startswith("wordpress_logged_in_") for cookie in cookies):
            print(f"Acceso confirmado tras {hechos} intentos; candidato oculto")
            return 0
        if estado in {403, 429}:
            print(f"Control o bloqueo observado: HTTP {estado} tras {hechos} intentos")
            return 0
        if estado not in {200, 301, 302, 303}:
            print(f"Respuesta inesperada HTTP {estado}; se detiene la prueba")
            return 3
        if hechos < limite:
            time.sleep(pausa)
    unidad = "intento" if hechos == 1 else "intentos"
    print(f"Sin acceso confirmado en {hechos} {unidad}; no demuestra ausencia de protección")
    return 1


def url_con_parametro(url, nombre, valor):
    partes = urlsplit(url)
    pares = [(k, v) for k, v in parse_qsl(partes.query, keep_blank_values=True) if k != nombre]
    pares.append((nombre, valor))
    return urlunsplit((partes.scheme, partes.netloc, partes.path, urlencode(pares), ""))


def sqli(url, parametro, valor, indicador, seco=False):
    validar_url(url)
    if not parametro or not indicador or len(parametro) > 64 or len(valor) > 128 or len(indicador) > 128:
        raise ValueError("indica --param y --indicador")
    if seco:
        print(f"Plan: tres consultas GET al formulario {url}; parámetro={parametro}; sin extraer datos")
        return 0
    opener = build_opener(SinRedireccion())
    pruebas = (valor, valor + "' AND '1'='1", valor + "' AND '1'='2")
    observaciones = []
    for prueba in pruebas:
        try:
            estado, _, cuerpo = consultar(opener, url_con_parametro(url, parametro, prueba))
        except (URLError, TimeoutError) as exc:
            print(f"Error de conexión: {exc}")
            return 3
        if estado != 200:
            print(f"Respuesta HTTP {estado}; resultado inconcluyente")
            return 3
        observaciones.append(indicador.encode() in cuerpo)
    if observaciones == [True, True, False]:
        print("Diferencia compatible con SQLi booleana; requiere confirmación manual")
        return 0
    print("No se observó el patrón de SQLi booleana; resultado inconcluyente")
    return 1


def basic(url, usuario, lista, limite, seco=False, pausa=1):
    """Fuerza bruta acotada contra autenticación HTTP Basic."""
    validar_url(url)
    lista = ruta_lista(lista)
    if not 1 <= limite <= 20:
        raise ValueError("--limite-intentos debe estar entre 1 y 20")
    if not usuario or len(usuario) > 64 or "\n" in usuario or "\r" in usuario:
        raise ValueError("indica un usuario válido")
    if not lista.is_file():
        raise ValueError("lista de candidatos no encontrada")
    if seco:
        print(f"Plan: hasta {limite} candidatos contra HTTP Basic de {url} como {usuario}; "
              "sin guardar candidatos")
        return 0
    import base64
    opener = build_opener(SinRedireccion())
    hechos = 0
    for candidato in candidatos(lista, limite):
        credencial = base64.b64encode(f"{usuario}:{candidato}".encode()).decode()
        peticion = Request(url, headers={"User-Agent": "kit-auditoria-claves/1.0",
                                         "Authorization": f"Basic {credencial}"})
        try:
            respuesta = opener.open(peticion, timeout=20)
            estado = respuesta.status
            respuesta.close()
        except HTTPError as exc:
            estado = exc.code
        except (URLError, TimeoutError) as exc:
            print(f"Error de conexión en el intento {hechos + 1}; estado desconocido: {exc}")
            return 3
        hechos += 1
        if estado not in {401, 403, 407}:
            print(f"Acceso HTTP Basic confirmado tras {hechos} intentos; candidato oculto")
            return 0
        if hechos < limite:
            time.sleep(pausa)
    unidad = "intento" if hechos == 1 else "intentos"
    print(f"Sin acceso en {hechos} {unidad}; no demuestra que la contraseña sea fuerte")
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="accion", required=True)
    wp = sub.add_parser("web-login")
    wp.add_argument("--url", required=True)
    wp.add_argument("--usuario", required=True)
    wp.add_argument("--wl", default=str(Path(__file__).with_name("ejemplos") /
                                         "candidatos_web_ficticios.txt"))
    wp.add_argument("--limite-intentos", type=int, default=3)
    wp.add_argument("--dry-run", action="store_true")
    sql = sub.add_parser("web-sqli")
    sql.add_argument("--url", required=True)
    sql.add_argument("--param", required=True)
    sql.add_argument("--valor", required=True)
    sql.add_argument("--indicador", required=True)
    sql.add_argument("--dry-run", action="store_true")
    bas = sub.add_parser("web-basic")
    bas.add_argument("--url", required=True)
    bas.add_argument("--usuario", required=True)
    bas.add_argument("--wl", default=str(Path(__file__).with_name("ejemplos") /
                                         "candidatos_web_ficticios.txt"))
    bas.add_argument("--limite-intentos", type=int, default=3)
    bas.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.accion == "web-login":
            return login(args.url, args.usuario, args.wl, args.limite_intentos, args.dry_run)
        if args.accion == "web-basic":
            return basic(args.url, args.usuario, args.wl, args.limite_intentos, args.dry_run)
        return sqli(args.url, args.param, args.valor, args.indicador, args.dry_run)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
