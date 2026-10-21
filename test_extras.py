from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from extras_archivos import pdf_permisos, zip_conocido
from extras_wasm import inventario
from extras_web import ruta_lista


BASE = Path(__file__).with_name("ejemplos") / "extras"
AUDITOR = Path(__file__).with_name("auditor_generico.sh")
MENU = {1: (1, 1), 2: (1, 2), 4: (1, 3), 5: (1, 4), 8: (1, 5),
        9: (1, 6), 22: (1, 7), 3: (2, 1), 19: (2, 2), 14: (2, 3),
        20: (2, 4), 6: (2, 5), 7: (2, 6), 13: (2, 7), 21: (2, 8),
        10: (3, 1), 17: (3, 2), 11: (3, 3), 15: (4, 1), 24: (4, 2),
        16: (4, 3), 12: (4, 4), 18: (4, 5), 23: (4, 6)}


def entrada_menu(opcion, parametros):
    grupo, subopcion = MENU[opcion]
    return f"{grupo}\n{subopcion}\n{parametros}"


class ExtraTests(unittest.TestCase):
    def test_zipcrypto_sintetico(self):
        self.assertEqual(zip_conocido(BASE / "zipcrypto_demo.zip", "texto_conocido.txt",
                                      BASE / "texto_conocido.txt", seco=True), 0)
        with tempfile.TemporaryDirectory() as td:
            falso = Path(td) / "plano.txt"
            falso.write_text("corto")
            with self.assertRaisesRegex(ValueError, "12 bytes"):
                zip_conocido(BASE / "zipcrypto_demo.zip", "texto_conocido.txt", falso, seco=True)
    @unittest.skipUnless(shutil.which("qpdf"), "qpdf opcional no instalado")
    def test_pdf_restringido(self):
        salida = io.StringIO()
        with redirect_stdout(salida):
            self.assertEqual(pdf_permisos(BASE / "pdf_restringido_demo.pdf"), 0)
        self.assertIn("sin clave de apertura", salida.getvalue())

    def test_wasm_inventario_y_modulo_invalido(self):
        imports, exports = inventario(BASE / "modulo_ficticio.wasm")
        self.assertEqual(imports, [("env", "log", 0)])
        self.assertEqual(exports, [("memory", 2)])
        with tempfile.TemporaryDirectory() as td:
            invalido = Path(td) / "roto.wasm"
            invalido.write_bytes(b"no wasm")
            with self.assertRaisesRegex(ValueError, "no es un módulo"):
                inventario(invalido)

    def test_entrada_comun_para_wifi_sin_radio(self):
        for modo in ("wifi-wps-pin", "wifi-pmkid"):
            proceso = subprocess.run(
                ["bash", str(AUDITOR), "--tipo", modo, "--interfaz", "wlan0",
                 "--bssid", "02:11:22:33:44:55", "--canal", "6", "--dry-run"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(proceso.returncode, 0, proceso.stderr)
            self.assertIn("Plan:", proceso.stdout)

    def test_deauth_y_wps_scan_dry_run(self):
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--tipo", "wifi-deauth", "--interfaz", "wlan0mon",
             "--bssid", "02:11:22:33:44:55", "--cliente", "02:aa:bb:cc:dd:ee",
             "--golpes", "10", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proceso.returncode, 0, proceso.stderr)
        self.assertIn("aireplay-ng --deauth 10 -a 02:11:22:33:44:55 -c 02:AA:BB:CC:DD:EE",
                      proceso.stdout)
        self.assertIn("4-way handshake", proceso.stdout)
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--tipo", "wifi-wps-scan", "--interfaz", "wlan0mon",
             "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proceso.returncode, 0, proceso.stderr)
        self.assertIn("wash pasivo", proceso.stdout)

    def test_wifi_monitor_listar_y_guardas_dry_run(self):
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--tipo", "wifi-monitor", "--listar"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proceso.returncode, 0, proceso.stderr)
        self.assertIn("INTERFAZ", proceso.stdout)
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--modo", "monitor", "--interfaz", "noexiste0",
             "--accion", "activar", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(proceso.returncode, 0)
        self.assertIn("no aparece como interfaz WiFi", proceso.stderr)

    def test_deauth_rechaza_mac_invalida(self):
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--tipo", "wifi-deauth", "--interfaz", "wlan0mon",
             "--bssid", "02:11:22:33:44:55", "--cliente", "no-es-mac", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proceso.returncode, 2)
        self.assertIn("cliente inválida", proceso.stderr)

    def test_lista_wps_extrae_todos_los_aps(self):
        from wps_capture_utils import lista_wps
        muestra = [
            "BSSID Ch dBm WPS Lck Vendor ESSID\n",
            "02:11:22:33:44:55 6 -54 2.0 No Ficticio Red de prueba\n",
            "02:11:22:33:44:66 36 -50 1.0 Yes Ficticio Otra red\n",
            "basura que no es fila\n",
        ]
        self.assertEqual(lista_wps(muestra), [
            ("02:11:22:33:44:55", 6, "2.0", "No", "Red de prueba"),
            ("02:11:22:33:44:66", 36, "1.0", "Yes", "Otra red"),
        ])

    def test_ssh_brute_dry_run_y_validaciones(self):
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--tipo", "ssh-brute", "--host", "127.0.0.1:22",
             "--usuario", "demo", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proceso.returncode, 0, proceso.stderr)
        self.assertIn("contra demo@127.0.0.1:22", proceso.stdout)
        for host, error in (("host;mal", "destino inválido"),
                            ("127.0.0.1", "usuario inválido")):
            usuario = "demo" if host == "host;mal" else "us;er"
            proceso = subprocess.run(
                ["bash", str(AUDITOR), "--tipo", "ssh-brute", "--host", host,
                 "--usuario", usuario, "--dry-run"],
                capture_output=True, text=True, timeout=10,
            )
            with self.subTest(host=host):
                self.assertEqual(proceso.returncode, 2)
                self.assertIn(error, proceso.stderr)

    @unittest.skipUnless(shutil.which("sshpass") and shutil.which("ssh"),
                         "sshpass/ssh no instalados")
    def test_ssh_brute_puerto_cerrado_sin_acceso(self):
        from extras_ssh import ssh_brute
        lista = Path(__file__).with_name("ejemplos") / "candidatos_web_ficticios.txt"
        # puerto 1/22 cerrado local: sin acceso, sin cuelgue, código 1 o 3
        self.assertIn(ssh_brute("127.0.0.1:1", "demo", lista, 1), {1, 3})

    def test_cred_scan_detecta_enmascara_y_genera(self):
        from extras_credenciales import cred_scan, enmascarar
        self.assertEqual(enmascarar("secreto12"), "se*****12")
        self.assertEqual(enmascarar("ab"), "**")
        with tempfile.TemporaryDirectory() as td:
            origen = Path(td) / "f"
            origen.write_text('password = "S3cr3to:Prueba!"\n'
                              'url: postgres://admin:CoNtr4s3na@db.local/app\n'
                              'password = changeme\n', encoding="utf-8")
            salida = io.StringIO()
            lista = Path(td) / "candidatos.txt"
            with redirect_stdout(salida):
                self.assertEqual(cred_scan(origen, str(lista)), 0)
            texto = salida.getvalue()
            self.assertIn("password-fichero S3***********a!", texto)
            self.assertIn("url-credenciales Co******na", texto)
            self.assertNotIn("S3cr3to:Prueba!", texto)
            self.assertNotIn("changeme", texto)
            self.assertEqual(lista.read_text().splitlines(),
                             ["S3cr3to:Prueba!", "CoNtr4s3na"])
            vacio = Path(td) / "vacio"
            vacio.write_text("nada aqui\n")
            salida = io.StringIO()
            with redirect_stdout(salida):
                self.assertEqual(cred_scan(vacio), 1)

    def test_limites_superiores_x10_aceptados_y_rechazados(self):
        casos_ok = (
            (["--tipo", "wifi-wps-pin", "--interfaz", "w", "--bssid",
              "02:11:22:33:44:55", "--canal", "6", "--limite-intentos", "50"], "Plan:"),
            (["--tipo", "wifi-pmkid", "--interfaz", "w", "--bssid",
              "02:11:22:33:44:55", "--canal", "6", "--segundos", "600"], "Plan:"),
            (["--tipo", "wifi-wps-scan", "--interfaz", "w", "--segundos", "1200"], "Plan:"),
            (["--tipo", "wifi-deauth", "--interfaz", "w", "--bssid",
              "02:11:22:33:44:55", "--golpes", "200"], "Plan:"),
            (["--tipo", "ssh-brute", "--host", "127.0.0.1", "--usuario",
              "demo", "--limite-intentos", "200"], "Plan:"),
            (["--tipo", "web-login", "--url", "https://e.invalid/wp", "--usuario",
              "demo", "--limite-intentos", "50"], "Plan:"),
        )
        for argumentos, esperado in casos_ok:
            proceso = subprocess.run(["bash", str(AUDITOR), *argumentos, "--dry-run"],
                                     capture_output=True, text=True, timeout=10)
            with self.subTest(argumentos=argumentos[-2:]):
                self.assertEqual(proceso.returncode, 0, proceso.stderr)
                self.assertIn(esperado, proceso.stdout)
        for argumentos in (
            ["--tipo", "wifi-wps-pin", "--interfaz", "w", "--bssid",
             "02:11:22:33:44:55", "--canal", "6", "--limite-intentos", "51"],
            ["--tipo", "wifi-pmkid", "--interfaz", "w", "--bssid",
             "02:11:22:33:44:55", "--canal", "6", "--segundos", "601"],
            ["--tipo", "wifi-deauth", "--interfaz", "w", "--bssid",
             "02:11:22:33:44:55", "--golpes", "201"],
            ["--tipo", "ssh-brute", "--host", "127.0.0.1", "--usuario",
             "demo", "--limite-intentos", "201"],
        ):
            proceso = subprocess.run(["bash", str(AUDITOR), *argumentos, "--dry-run"],
                                     capture_output=True, text=True, timeout=10)
            with self.subTest(argumentos=argumentos[-2:]):
                self.assertEqual(proceso.returncode, 2)

    def test_modo_alias_y_tiempo_atajo(self):
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--modo", "pmkid", "--interfaz", "wlan0",
             "--bssid", "02:11:22:33:44:55", "--canal", "6", "--tiempo", "600",
             "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proceso.returncode, 0, proceso.stderr)
        self.assertIn("600s", proceso.stdout)
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--modo", "ssh", "--host", "127.0.0.1",
             "--usuario", "demo", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proceso.returncode, 0, proceso.stderr)
        self.assertIn("sshpass", proceso.stdout)
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--modo", "ftp", "--host", "127.0.0.1",
             "--usuario", "demo", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proceso.returncode, 0, proceso.stderr)
        self.assertIn("FTP", proceso.stdout)
        # --modo numérico sigue siendo el modo de hashcat
        with tempfile.TemporaryDirectory() as td:
            hash_file = Path(td) / "md5.txt"
            hash_file.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n")
            proceso = subprocess.run(
                ["bash", str(AUDITOR), "--tipo", "hash", "--modo", "0",
                 "--dry-run", str(hash_file)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(proceso.returncode, 0, proceso.stderr)
            self.assertIn("raw", proceso.stdout)
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--modo", "inexistente", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proceso.returncode, 2)
        self.assertIn("--tipo desconocido", proceso.stderr)

    def test_mitm_arp_dry_run_y_validaciones(self):
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--modo", "mitm", "--interfaz", "wlan0",
             "--objetivo", "192.168.1.10", "--gateway", "192.168.1.1",
             "--tiempo", "60", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proceso.returncode, 0, proceso.stderr)
        self.assertIn("bettercap arp-spoof wlan0", proceso.stdout)
        self.assertIn("192.168.1.10", proceso.stdout)
        self.assertIn("60s", proceso.stdout)
        for mal in ("no-es-ip", "999.1.1.1", "1.2.3"):
            proceso = subprocess.run(
                ["bash", str(AUDITOR), "--modo", "mitm", "--interfaz", "wlan0",
                 "--objetivo", mal, "--dry-run"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(proceso.returncode, 2, mal)
            self.assertIn("IPv4", proceso.stderr)
        # sin permisos y sin dry-run debe exigir sudo
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--modo", "mitm", "--interfaz", "wlan0",
             "--objetivo", "192.168.1.10", "--gateway", "192.168.1.1"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(proceso.returncode, 0)
        self.assertIn("sudo", proceso.stderr + proceso.stdout)

    def test_menu_muestra_comando_equivalente(self):
        # modo extra (opción 13)
        proceso = subprocess.run(
            ["bash", str(AUDITOR)],
            input=entrada_menu(13, "wlan0mon\n02:11:22:33:44:55\n\n\nplan\n"),
            capture_output=True, text=True, timeout=10)
        self.assertEqual(proceso.returncode, 0, proceso.stderr)
        self.assertIn("Comando equivalente para repetir sin el menú:", proceso.stdout)
        self.assertIn("--tipo wifi-deauth --interfaz wlan0mon "
                      "--bssid 02:11:22:33:44:55 --golpes 10 --dry-run", proceso.stdout)
        # flujo offline (opción 1)
        with tempfile.TemporaryDirectory() as td:
            objetivo = Path(td) / "f.zip"
            objetivo.write_bytes(b"PK\x03\x04")
            proceso = subprocess.run(
                ["bash", str(AUDITOR), "--dry-run"],
                input=entrada_menu(1, f"{objetivo}\n1-2\nauto\n"),
                capture_output=True, text=True, timeout=10)
            self.assertEqual(proceso.returncode, 0, proceso.stderr)
            self.assertIn("Comando equivalente para repetir sin el menú:", proceso.stdout)
            self.assertIn(f"--tipo archivo --nivel 1-2 --motor auto --dry-run {objetivo}",
                          proceso.stdout)

    def test_menu_guiado_presenta_y_prepara_todos_los_modos_extra(self):
        for opcion in range(6, 25):
            with self.subTest(opcion=opcion):
                if opcion in (6, 7):
                    entradas = f"{opcion}\n\n02:11:22:33:44:55\n6\n\n\n"
                elif opcion == 13:
                    entradas = f"{opcion}\nwlan0mon\n02:11:22:33:44:55\n\n\nplan\n"
                elif opcion == 14:
                    entradas = f"{opcion}\nwlan0mon\n\n\nplan\n"
                elif opcion == 15:
                    entradas = f"{opcion}\n127.0.0.1\ndemo\n\n3\nplan\n"
                elif opcion == 24:
                    entradas = f"{opcion}\n127.0.0.1\nanonymous\n\n3\nplan\n"
                elif opcion == 16:
                    entradas = f"{opcion}\n{Path(__file__).with_name('ejemplos')}\n\nplan\n"
                elif opcion == 17:
                    entradas = f"{opcion}\nhttp://127.0.0.1:9/wp\ndemo\n\n3\nplan\n"
                elif opcion == 18:
                    entradas = f"{opcion}\nwlan0\n192.168.1.10\n192.168.1.1\n60\nplan\n"
                elif opcion == 19:
                    entradas = f"{opcion}\nwlan0\nRed Ficticia\n5\nplan\n"
                elif opcion == 20:
                    entradas = f"{opcion}\nwlan0\n02:11:22:33:44:55\n6\nplan\n"
                elif opcion == 21:
                    entradas = f"{opcion}\nwlan0mon\n02:11:22:33:44:55\n6\n5\n15\nplan\n"
                elif opcion == 22:
                    entradas = (f"{opcion}\n"
                                f"{Path(__file__).with_name('README.md')}\n22000\nplan\n")
                elif opcion == 23:
                    entradas = f"{opcion}\ndemo\nplan\n"
                else:
                    entradas = f"{opcion}\n" + "\n" * 6
                entradas = entrada_menu(opcion, entradas.split("\n", 1)[1])
                proceso = subprocess.run(["bash", str(AUDITOR)], input=entradas,
                                         capture_output=True, text=True, timeout=10)
                self.assertEqual(proceso.returncode, 0, proceso.stderr)
                self.assertIn("4) Otros", proceso.stdout)
                self.assertIn("Plan:", proceso.stdout)

    def test_ftp_brute_dry_run_y_validaciones(self):
        proceso = subprocess.run(
            ["bash", str(AUDITOR), "--tipo", "ftp-brute", "--host", "127.0.0.1:21",
             "--usuario", "demo", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proceso.returncode, 0, proceso.stderr)
        self.assertIn("contra demo@127.0.0.1:21", proceso.stdout)
        for host, error in (("host;mal", "destino inválido"),
                            ("127.0.0.1", "usuario inválido")):
            usuario = "demo" if host == "host;mal" else "us;er"
            proceso = subprocess.run(
                ["bash", str(AUDITOR), "--tipo", "ftp-brute", "--host", host,
                 "--usuario", usuario, "--dry-run"],
                capture_output=True, text=True, timeout=10,
            )
            with self.subTest(host=host):
                self.assertEqual(proceso.returncode, 2)
                self.assertIn(error, proceso.stderr)

    def test_ftp_brute_puerto_cerrado_sin_acceso(self):
        from extras_ftp import ftp_brute
        lista = Path(__file__).with_name("ejemplos") / "candidatos_web_ficticios.txt"
        resultado = ftp_brute("127.0.0.1:1", "demo", lista, 1)
        self.assertIn(resultado, {1, 3})

    def test_cred_scan_detecta_tokens_modernos(self):
        from extras_credenciales import escanear_arbol
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            origen = Path(td) / "tokens.env"
            origen.write_text(
                'GH_TOKEN=github_pat_11ABCDEFG1234567890abcdefghijklmnopqrstu\n'
                'GITLAB_TOKEN=glpat-AbCdEfGhIjKlMnOpQrSt\n'
                'NPM_TOKEN=npm_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890\n',
                encoding="utf-8"
            )
            hallazgos, _ = escanear_arbol(origen)
            nombres = {h[2] for h in hallazgos}
            self.assertIn("token-formato", nombres)

    def test_menu_web_resuelve_tilde_y_admite_lista_grande_acotada(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporal:
            lista = Path(temporal) / "candidatos_ficticios.txt"
            with lista.open("wb") as archivo:
                archivo.write(b"ficticia_01\nficticia_02\n")
                archivo.truncate(2 * 1024 * 1024)
            nombre_usuario = pwd.getpwuid(os.getuid()).pw_name
            ruta_con_tilde = "~/" + str(lista.relative_to(Path.home()))
            entorno = os.environ.copy()
            entorno["SUDO_USER"] = nombre_usuario
            entradas = entrada_menu(10, "https://ejemplo.invalid/wp-login.php\ndemo\n"
                                    f"{ruta_con_tilde}\n5\nplan\n")
            proceso = subprocess.run(["bash", str(AUDITOR)], input=entradas,
                                     env=entorno, capture_output=True, text=True, timeout=10)
            self.assertEqual(proceso.returncode, 0, proceso.stderr)
            self.assertIn("hasta 5 primeros candidatos", proceso.stdout)
            self.assertEqual(ruta_lista(ruta_con_tilde), lista)
            with patch("extras_web.os.geteuid", return_value=0), \
                    patch.dict(os.environ, {"SUDO_USER": nombre_usuario}):
                self.assertEqual(ruta_lista(ruta_con_tilde), lista)


if __name__ == "__main__":
    unittest.main()
