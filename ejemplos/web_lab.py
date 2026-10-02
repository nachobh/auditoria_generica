#!/usr/bin/env python3
"""Laboratorio web ficticio: login tipo WordPress y búsqueda SQL vulnerable/segura."""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import sqlite3
from urllib.parse import parse_qs, urlsplit


CLAVE_FICTICIA = "solo_ficticio_01!"


class Laboratorio(BaseHTTPRequestHandler):
    intentos = 0
    con_limite = False

    def log_message(self, *args):
        pass

    def enviar(self, codigo, cuerpo, extra=None):
        datos = cuerpo.encode()
        self.send_response(codigo)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(datos)))
        for nombre, valor in (extra or {}).items():
            self.send_header(nombre, valor)
        self.end_headers()
        self.wfile.write(datos)

    def do_GET(self):
        partes = urlsplit(self.path)
        if partes.path == "/wp-login.php":
            self.enviar(200, "Acceso de laboratorio")
            return
        if partes.path not in {"/buscar-vulnerable", "/buscar-seguro"}:
            self.enviar(404, "No encontrado")
            return
        termino = parse_qs(partes.query).get("q", [""])[0]
        bd = sqlite3.connect(":memory:")
        bd.execute("CREATE TABLE articulos (nombre TEXT)")
        bd.execute("INSERT INTO articulos VALUES (?)", ("libro_ficticio",))
        try:
            if partes.path == "/buscar-vulnerable":
                filas = bd.execute("SELECT nombre FROM articulos WHERE nombre='" + termino + "'")
            else:
                filas = bd.execute("SELECT nombre FROM articulos WHERE nombre=?", (termino,))
            encontrado = any(nombre == "libro_ficticio" for (nombre,) in filas)
        except sqlite3.Error:
            encontrado = False
        bd.close()
        self.enviar(200, "RESULTADO_FICTICIO" if encontrado else "sin resultados")

    def do_POST(self):
        if urlsplit(self.path).path != "/wp-login.php":
            self.enviar(404, "No encontrado")
            return
        longitud = min(int(self.headers.get("Content-Length", "0")), 4096)
        formulario = parse_qs(self.rfile.read(longitud).decode(errors="replace"))
        self.__class__.intentos += 1
        if self.con_limite and self.intentos > 3:
            self.enviar(429, "Demasiados intentos")
            return
        if formulario.get("log") == ["demo"] and formulario.get("pwd") == [CLAVE_FICTICIA]:
            self.enviar(302, "Acceso", {"Location": "/wp-admin/",
                                        "Set-Cookie": "wordpress_logged_in_demo=1; HttpOnly"})
        else:
            self.enviar(200, "Acceso denegado")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--puerto", type=int, default=8769)
    parser.add_argument("--con-limite", action="store_true")
    args = parser.parse_args()
    Laboratorio.con_limite = args.con_limite
    servidor = HTTPServer(("127.0.0.1", args.puerto), Laboratorio)
    print(f"Laboratorio ficticio: http://127.0.0.1:{servidor.server_port}", flush=True)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        servidor.server_close()


if __name__ == "__main__":
    main()
