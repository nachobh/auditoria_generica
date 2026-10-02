from contextlib import redirect_stdout
import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from extras_archivos import pdf_permisos, zip_conocido
from extras_wasm import inventario


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


if __name__ == "__main__":
    unittest.main()
