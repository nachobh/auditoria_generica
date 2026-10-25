#!/usr/bin/env python3
"""LiteLLM 1.107.0 — compromiso de cadena de suministro (Microsoft Security
Blog, 2026-10-23). El wheel publicado en PyPI el 2026-10-21 instalaba
cook.pth («import cook»), cook.py (recolector PRIVCOLLECT) y
sitecustomize.py (cargador remoto Unix) en el directorio lib del entorno
Python, FUERA del directorio de litellm: bastaba ARRANCAR PYTHON para
ejecutar la carga. Exfiltración POST http://www.litellm[.]dev/healthcheck
(octet-stream, cabecera X-SHA256); marcador /tmp/.pc_once_72129118c59f5636c0bb;
cargador con lock /tmp/remote_code_loader.lock y puntero domain.txt → /codepy.

Dos caminos de comprobación, ambos SIN ejecutar el Python sospechoso
(recomendación explícita de Microsoft):
  --url   huella del proxy remoto (LiteLLM responde /health/liveliness y
          /version; un 404 estilo Werkzeug/Flask NO es LiteLLM)
  --ruta  inspección a fichero limpio de un entorno Python (venv montado,
          imagen desempaquetada): busca los tres archivos y sus marcas
  --sistema  lo propio en esta máquina (site-packages conocidos + /tmp)
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

VERSION_COMPROMETIDA = "1.107.0"
MARCADORES = {
    "cook.pth": [re.compile(r"^\s*import\s+cook", re.I | re.M)],
    "cook.py": [re.compile(r"PRIVCOLLECT", re.I)],
    "sitecustomize.py": [re.compile(r"remote_code_loader|codepy|domain\.txt",
                                    re.I)],
}
MARCAS_TMP = ("/tmp/.pc_once_72129118c59f5636c0bb",
              "/tmp/remote_code_loader.lock")
MAX_WALK = 20000


def _get(url, timeout=10):
    peticion = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (kit-auditoria-claves)"})
    try:
        with urllib.request.urlopen(peticion, timeout=timeout) as r:
            return r.status, r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4096).decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)


def check_url(url, seco):
    if seco:
        print("Plan: 3 GETs de huella (/health/liveliness, /version, /) al "
              "proxy; veredicto de versión contra la release comprometida "
              f"{VERSION_COMPROMETIDA} (sin impacto)")
        return 0
    base = url.rstrip("/")
    estado, cuerpo = _get(base + "/health/liveliness")
    if estado is None:
        print(f"INCONCLUYENTE: {base} no responde ({cuerpo})")
        return 3
    es_litellm = False
    if estado == 200 and "alive" in cuerpo.lower():
        es_litellm = True
    version = None
    estado_v, cuerpo_v = _get(base + "/version")
    if estado_v == 200:
        try:
            version = json.loads(cuerpo_v).get("version")
            es_litellm = True
        except (json.JSONDecodeError, AttributeError):
            m = re.search(r"(\d+\.\d+\.\d+)", cuerpo_v)
            version = m.group(1) if m else None
    if not es_litellm:
        firma = ("Werkzeug/Flask" if "Not Found</title>" in cuerpo
                 else "respuesta no-LiteLLM")
        print(f"VEREDICTO: NO_ES_LITELLM — {base} no responde como proxy "
              f"LiteLLM ({firma}, HTTP {estado})")
        return 1
    if version == VERSION_COMPROMETIDA:
        print(f"VEREDICTO: RELEASE_COMPROMETIDA — proxy LiteLLM "
              f"{VERSION_COMPROMETIDA}: la release estuvo envenenada en "
              "PyPI e imágenes oficiales. Reconstruye el entorno desde "
              "artefacto verificado y ROTACIONA las credenciales al "
              "alcance del proceso (claves de proveedores, BD del proxy, "
              "variables de entorno). Borrar el paquete no basta: los "
              "arranques anteriores ya pudieron ejecutar la carga.")
        return 0
    print(f"VEREDICTO: PROXY_LITELLM version={version or '(oculta)'} — "
          f"no es la release {VERSION_COMPROMETIDA}. OJO: si 1.107.0 se "
          "llegó a instalar alguna vez en ESTE entorno, cook.pth/cook.py/"
          "sitecustomize.py sobreviven fuera del directorio de litellm; "
          "pásale --ruta sobre el entorno o --sistema en la máquina.")
    return 1


def _marcas_de(ruta, patron):
    try:
        texto = open(ruta, encoding="utf-8", errors="replace").read(200000)
    except OSError:
        return False
    return any(p.search(texto) for p in patron)


def check_ruta(ruta, seco):
    if seco:
        print(f"Plan: recorrido acotado de {ruta} buscando cook.pth/cook.py/"
              "sitecustomize.py con sus marcas y dist-info de litellm "
              f"{VERSION_COMPROMETIDA}; SIN ejecutar el python del entorno "
              "sospechoso")
        return 0
    if not os.path.isdir(ruta):
        print(f"Error: {ruta} no es un directorio", file=sys.stderr)
        return 2
    vistos = 0
    hallazgos = []
    dist_litellm = []
    for raiz, dirs, ficheros in os.walk(ruta):
        dirs[:] = [d for d in dirs if d not in ("proc", "sys", ".git")]
        for f in ficheros:
            vistos += 1
            if vistos > MAX_WALK:
                print("AVISO: recorrido truncado; el resultado puede ser "
                      "parcial")
                break
            completo = os.path.join(raiz, f)
            if f in MARCADORES and _marcas_de(completo, MARCADORES[f]):
                hallazgos.append(completo)
            elif f == "cook.pth":
                hallazgos.append(completo + " (sin marcar)")
            elif f.startswith("litellm") and ".dist-info" in raiz:
                dist_litellm.append(raiz)
        if vistos > MAX_WALK:
            break
    for marca in MARCAS_TMP:
        if os.path.exists(os.path.join(ruta, marca.lstrip("/"))):
            hallazgos.append(os.path.join(ruta, marca.lstrip("/")))
    if hallazgos:
        print("VEREDICTO: ARCHIVOS_INFECCADOS —")
        for h in hallazgos:
            print(f"  {h}")
        print("No arranques el python de este entorno. Reconstruye desde "
              "artefacto verificado y rota credenciales al alcance del "
              "proceso.")
        return 0
    if dist_litellm:
        print(f"VEREDICTO: ENTORNO_SIN_ARCHIVOS_MALICIOSOS — hay litellm "
              f"({dist_litellm[0]}) pero ni cook.*/sitecustomize marcado "
              "ni marcas de /tmp. Aun así, si 1.107.0 se instaló antes, "
              "los ficheros pueden estar en OTRO entorno que comparta el "
              "intérprete.")
        return 1
    print("VEREDICTO: SIN_LITELLM — ni paquete ni archivos de arranque "
          "maliciosos bajo esa ruta")
    return 1


def check_sistema(seco):
    if seco:
        print("Plan: comprobar site-packages de esta máquina y marcas de "
              "/tmp (sin importar nada)")
        return 0
    candidatos = []
    for base in (os.path.expanduser("~/.local/lib"), "/usr/lib",
                 "/usr/local/lib", "/opt"):
        for raiz, dirs, ficheros in os.walk(base):
            if raiz.count(os.sep) - base.count(os.sep) > 4:
                dirs[:] = []
                continue
            if raiz.endswith("site-packages") or raiz.endswith("dist-packages"):
                candidatos.append(raiz)
    hallazgos = []
    for d in candidatos:
        for f, patron in MARCADORES.items():
            completo = os.path.join(d, f)
            if os.path.exists(completo) and _marcas_de(completo, patron):
                hallazgos.append(completo)
    for marca in MARCAS_TMP:
        if os.path.exists(marca):
            hallazgos.append(marca)
    if hallazgos:
        print("VEREDICTO: ARCHIVOS_INFECCADOS —")
        for h in hallazgos:
            print(f"  {h}")
        return 0
    print("VEREDICTO: SISTEMA_LIMPIO — ni cook.pth/cook.py/sitecustomize "
          "marcados ni marcas de /tmp en los entornos de esta máquina")
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="extras_litellm.py")
    sub = ap.add_subparsers(dest="modo", required=True)
    c = sub.add_parser("litellm-check")
    c.add_argument("--url", help="proxy LiteLLM a huellar (http(s)://…)")
    c.add_argument("--ruta", help="entorno Python a inspeccionar a fichero "
                                  "limpio (venv, imagen desempaquetada)")
    c.add_argument("--sistema", action="store_true",
                   help="comprobar los site-packages y /tmp de esta máquina")
    c.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if not (a.url or a.ruta or a.sistema):
        print("Error: indica --url, --ruta o --sistema", file=sys.stderr)
        return 2
    if a.url and not a.url.startswith(("http://", "https://")):
        print("Error: --url debe empezar por http(s)://", file=sys.stderr)
        return 2
    resultados = []
    if a.url:
        resultados.append(check_url(a.url, a.dry_run))
    if a.ruta:
        resultados.append(check_ruta(a.ruta, a.dry_run))
    if a.sistema:
        resultados.append(check_sistema(a.dry_run))
    # cualquier hallazgo manda (0); si no, lo inconcluyente (3); si no, 1
    for prioridad in (0, 3):
        if prioridad in resultados:
            return prioridad
    return 1


if __name__ == "__main__":
    sys.exit(main())
