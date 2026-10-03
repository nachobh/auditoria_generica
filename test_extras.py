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

    def test_menu_guiado_presenta_y_prepara_todos_los_modos_extra(self):
        for opcion in range(6, 15):
            with self.subTest(opcion=opcion):
                if opcion in (6, 7):
                    entradas = f"{opcion}\n\n02:11:22:33:44:55\n6\n\n\n"
                elif opcion == 13:
                    entradas = f"{opcion}\nwlan0mon\n02:11:22:33:44:55\n\n\nplan\n"
                elif opcion == 14:
                    entradas = f"{opcion}\nwlan0mon\n\n\nplan\n"
                else:
                    entradas = f"{opcion}\n" + "\n" * 6
                proceso = subprocess.run(["bash", str(AUDITOR)], input=entradas,
                                         capture_output=True, text=True, timeout=10)
                self.assertEqual(proceso.returncode, 0, proceso.stderr)
                self.assertIn("12) WASM: inventario estático", proceso.stdout)
                self.assertIn("Plan:", proceso.stdout)

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
            entradas = ("10\nhttps://ejemplo.invalid/wp-login.php\ndemo\n"
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
