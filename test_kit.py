import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import hashlib

from demo_controles import resumen


SCRIPT = Path(__file__).with_name("auditor_generico.sh")
DOWNLOADER = Path(__file__).with_name("wordlists") / "descargar_wordlists.sh"


class KitTests(unittest.TestCase):
    def test_demo_usa_datos_sinteticos_y_controles(self):
        datos = resumen()
        self.assertEqual(datos["candidatos_ficticios"], 8)
        self.assertTrue(datos["tabla_reutilizable_sin_sal"])
        self.assertTrue(datos["tabla_falla_con_sal"])
        self.assertTrue(datos["sal_unica_cambia_verificador"])
        self.assertTrue(datos["login_bloqueado_tras_tres_fallos"])
        self.assertFalse(datos["clave_sin_segundo_factor_autentica"])
        self.assertTrue(datos["clave_con_segundo_factor_autentica"])

    def test_dry_run_no_crea_archivos_ni_ejecuta_verificador(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            objetivo = base / "ficticio.xdf"
            objetivo.write_text("FORMATO FICTICIO\n")
            marcador = base / "invocado"
            verificador = base / "verificador.py"
            verificador.write_text(
                "from pathlib import Path\n"
                f"Path({str(marcador)!r}).touch()\n"
            )
            salida = base / "salida"
            env = {**os.environ, "AUDITORIA_DIR": str(salida)}
            proceso = subprocess.run(
                ["bash", str(SCRIPT), "--tipo", "externo", "--nivel", "1",
                 "--dry-run", "--externo-cmd", f"{sys.executable} {verificador} %P",
                 str(objetivo)], env=env, capture_output=True, text=True, timeout=10
            )
            self.assertEqual(proceso.returncode, 0, proceso.stderr)
            self.assertFalse(marcador.exists())
            self.assertFalse(salida.exists())

    def test_verificador_recibe_candidato_literal_y_reporte_oculto(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            secreto = "solo_demo_ficticio_03!"
            objetivo = base / "ficticio.xdf"
            objetivo.write_text("FORMATO FICTICIO\n")
            lista = base / "lista con espacios.txt"
            lista.write_text(secreto + "\n")
            verificador = base / "verificador.py"
            verificador.write_text(
                "import sys\n"
                f"sys.exit(0 if sys.argv[1] == {str(objetivo)!r} "
                f"and sys.argv[2] == {secreto!r} else 1)\n"
            )
            salida = base / "salida"
            env = {**os.environ, "AUDITORIA_DIR": str(salida)}
            proceso = subprocess.run(
                ["bash", str(SCRIPT), "--tipo", "externo", "--nivel", "1",
                 "--yes", "--wl", str(lista), "--sin-calibrar",
                 "--externo-cmd", f"{sys.executable} {verificador} %F %P",
                 str(objetivo)], env=env, capture_output=True, text=True, timeout=10
            )
            self.assertEqual(proceso.returncode, 0, proceso.stderr)
            self.assertNotIn(secreto, proceso.stdout)
            trabajos = list(salida.iterdir())
            self.assertEqual(len(trabajos), 1)
            self.assertEqual([x.name for x in trabajos[0].iterdir()], ["resultado.txt"])
            resultado = (trabajos[0] / "resultado.txt").read_text()
            self.assertIn("contrasena=omitida", resultado)
            self.assertIn("verificacion=ok", resultado)
            self.assertNotIn(secreto, resultado)

    def test_argumentos_invalidos_no_crean_salida(self):
        with tempfile.TemporaryDirectory() as td:
            objetivo = Path(td) / "ficticio.xdf"
            objetivo.write_text("FORMATO FICTICIO\n")
            env = {**os.environ, "AUDITORIA_DIR": str(Path(td) / "salida")}
            for extra in (["--max-min", "abc"], ["--nivel"], ["--modo", "0;true"]):
                proceso = subprocess.run(
                    ["bash", str(SCRIPT), *extra, str(objetivo)] if len(extra) > 1
                    else ["bash", str(SCRIPT), *extra],
                    env=env, capture_output=True, text=True, timeout=10
                )
                self.assertEqual(proceso.returncode, 2, proceso.stderr)
            self.assertFalse((Path(td) / "salida").exists())

    def test_cancelar_no_crea_resultados(self):
        with tempfile.TemporaryDirectory() as td:
            objetivo = Path(td) / "ficticio.xdf"
            objetivo.write_text("FORMATO FICTICIO\n")
            salida = Path(td) / "salida"
            env = {**os.environ, "AUDITORIA_DIR": str(salida)}
            proceso = subprocess.run(
                ["bash", str(SCRIPT), "--tipo", "externo", "--externo-cmd",
                 "python3 verificador.py %P", str(objetivo)], input="n\n",
                env=env, capture_output=True, text=True, timeout=10
            )
            self.assertEqual(proceso.returncode, 0, proceso.stderr)
            self.assertFalse(salida.exists())

    def test_comprobar_listas_no_crea_directorio(self):
        with tempfile.TemporaryDirectory() as td:
            destino = Path(td) / "sin_descargas"
            proceso = subprocess.run(
                ["bash", str(DOWNLOADER), "--comprobar", "--destino",
                 str(destino), "stupid-ones-in-production.txt"],
                capture_output=True, text=True, timeout=10
            )
            self.assertEqual(proceso.returncode, 1)
            self.assertFalse(destino.exists())

    def test_motor_recibe_ruta_con_metacaracteres_como_argumento(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            secreto = "solo_demo_ficticio_03!"
            objetivo = base / "hash_ficticio.txt"
            objetivo.write_text(hashlib.md5(secreto.encode()).hexdigest() + "\n")
            lista = base / "lista;touch PWNED.txt"
            lista.write_text(secreto + "\n")
            motor = base / "hashcat_ficticio"
            motor.write_text(
                f"#!{sys.executable}\n"
                "from pathlib import Path\nimport sys\n"
                "a = sys.argv[1:]\n"
                f"if '--show' in a:\n    print({secreto!r})\n"
                "elif '--potfile-path' in a:\n"
                "    Path(a[a.index('--potfile-path') + 1]).write_text('ficticio:ficticio\\n')\n"
            )
            motor.chmod(0o700)
            salida = base / "salida"
            env = {**os.environ, "AUDITORIA_DIR": str(salida),
                   "AUDITOR_HASHCAT": str(motor)}
            proceso = subprocess.run(
                ["bash", str(SCRIPT), "--tipo", "hash", "--modo", "0",
                 "--nivel", "1", "--wl", str(lista), "--sin-calibrar",
                 "--yes", str(objetivo)], cwd=base, env=env,
                capture_output=True, text=True, timeout=10
            )
            self.assertEqual(proceso.returncode, 0, proceso.stderr)
            self.assertFalse((base / "PWNED.txt").exists())
            self.assertNotIn(secreto, proceso.stdout)
            trabajo = next(salida.iterdir())
            self.assertIn("verificacion=ok", (trabajo / "resultado.txt").read_text())

    def test_rainbow_exige_que_el_candidato_coincida_con_el_hash(self):
        for correcto in (False, True):
            with self.subTest(correcto=correcto), tempfile.TemporaryDirectory() as td:
                base = Path(td)
                secreto = "solo_demo_ficticio_03!"
                objetivo = base / "hash_ficticio.txt"
                digest = hashlib.md5(secreto.encode()).hexdigest()
                objetivo.write_text(digest + "\n")
                motor = base / "hashcat_ficticio"
                motor.write_text(f"#!{sys.executable}\nimport sys\nsys.exit(1)\n")
                motor.chmod(0o700)
                binario = base / "bin"
                binario.mkdir()
                tabla = base / "tablas"
                tabla.mkdir()
                (tabla / "demo.rt").write_bytes(b"tabla ficticia")
                rcrack = binario / "rcrack"
                candidato = secreto if correcto else "solo_demo_ficticio_99!"
                rcrack.write_text(
                    f"#!{sys.executable}\n"
                    f"print('plaintext of {digest} is {candidato}')\n"
                )
                rcrack.chmod(0o700)
                salida = base / "salida"
                env = {**os.environ, "AUDITORIA_DIR": str(salida),
                       "AUDITOR_HASHCAT": str(motor),
                       "AUDITOR_RAINBOW": str(binario),
                       "AUDITOR_RAINBOW_TABLES": str(tabla)}
                proceso = subprocess.run(
                    ["bash", str(SCRIPT), "--tipo", "hash", "--modo", "0",
                     "--nivel", "5", "--sin-calibrar", "--yes", str(objetivo)],
                    env=env, capture_output=True, text=True, timeout=10
                )
                self.assertEqual(proceso.returncode, 0 if correcto else 1,
                                 proceso.stdout + proceso.stderr)
                trabajo = next(salida.iterdir())
                informe = trabajo / "resultado.txt"
                if correcto:
                    self.assertIn("motor=rainbow", informe.read_text())
                    self.assertIn("verificacion=ok", informe.read_text())
                else:
                    self.assertFalse(informe.exists())


if __name__ == "__main__":
    unittest.main()
