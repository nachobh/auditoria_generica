"""Regresiones con archivos ficticios y motores simulados; sin radio ni sitios reales."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

from extras_credenciales import cred_scan, escanear_arbol
from test_extras import entrada_menu

BASE = Path(__file__).resolve().parent
AUDITOR = BASE / "auditor_generico.sh"


class Regresiones(unittest.TestCase):
    def test_variantes_desde_menu_ejecuta_con_salida(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            semillas = base / "semillas con espacios.txt"
            semillas.write_text("demo_ficticia\n")
            salida = base / "variantes"
            entradas = entrada_menu(23, f"variantes\n{salida}\n{semillas}\nprueba\n")
            p = subprocess.run(["bash", str(AUDITOR)], input=entradas, cwd=base,
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue((salida / "extra_casos.txt").is_file())
            self.assertEqual((salida / "extra_casos.txt").stat().st_mode & 0o777, 0o600)

    def test_lanzador_test_fija_directorio_del_kit(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            python = base / "python3"
            python.write_text(f"#!{sys.executable}\nimport os,sys\nprint(os.getcwd())\nprint(sys.argv[1:])\n")
            python.chmod(0o700)
            env = {**os.environ, "PATH": str(base) + ":" + os.environ["PATH"]}
            p = subprocess.run(["bash", str(AUDITOR), "--modo", "test"], cwd=base,
                               env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.splitlines()[0], str(BASE))
            self.assertIn("unittest", p.stdout)

    def test_volver_y_salir_y_eof_del_menu(self):
        for entrada in ("1\n0\n3\n0\n0\n", "", "9\n0\n"):
            p = subprocess.run(["bash", str(AUDITOR)], input=entrada,
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 0, p.stderr)

    def test_escaneo_no_sigue_enlaces_y_exporta_privado(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            scope = base / "scope"
            scope.mkdir()
            fuera = base / "fuera.txt"
            fuera.write_text("password=ficticia_fuera\n")
            (scope / "enlace.txt").symlink_to(fuera)
            (scope / "directorio_enlace").symlink_to(base, target_is_directory=True)
            self.assertEqual(escanear_arbol(scope), ([], []))
            with self.assertRaises(ValueError):
                escanear_arbol(scope / "enlace.txt")
            origen = scope / "demo.txt"
            origen.write_text("password=ficticia_dentro\n")
            destino = base / "lista.txt"
            (base / "lista.txt.tmp").symlink_to(fuera)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cred_scan(scope, destino), 0)
            self.assertEqual(destino.stat().st_mode & 0o777, 0o600)
            self.assertEqual(fuera.read_text(), "password=ficticia_fuera\n")
            self.assertEqual(destino.read_text(), "ficticia_dentro\n")

    @unittest.skipUnless(shutil.which("taskset"), "taskset no disponible")
    def test_cpu_limita_benchmark_y_trabajos_y_acepta_ceros_iniciales(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            objetivo = base / "demo.md5"
            objetivo.write_text(hashlib.md5(b"ficticia").hexdigest() + "\n")
            lista = base / "lista.txt"
            lista.write_text("ficticia\n")
            registro = base / "llamadas.jsonl"
            motor = base / "hashcat"
            motor.write_text(f"#!{sys.executable}\nimport json,os,sys\n"
                             f"with open({str(registro)!r},'a') as f: f.write(json.dumps([sys.argv[1:],len(os.sched_getaffinity(0))])+'\\n')\n"
                             "if '-b' in sys.argv: print('Speed.#1: 100 H/s');sys.exit(0)\n"
                             "sys.exit(1)\n")
            motor.chmod(0o700)
            env = {**os.environ, "AUDITOR_HASHCAT": str(motor),
                   "AUDITORIA_DIR": str(base / "resultados")}
            p = subprocess.run(["bash", str(AUDITOR), "--tipo", "hash", "--modo", "0",
                                "--cpu", "01", "--nivel", "1", "--wl", str(lista),
                                "--yes", str(objetivo)], env=env,
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 1, p.stderr)
            llamadas = [json.loads(l) for l in registro.read_text().splitlines()]
            relevantes = [(a, n) for a, n in llamadas if '-b' in a or '-a' in a]
            self.assertTrue(any('-b' in a for a, _ in relevantes))
            self.assertTrue(any('-a' in a for a, _ in relevantes))
            self.assertTrue(all(n == 1 for _, n in relevantes), relevantes)
            p = subprocess.run(["bash", str(AUDITOR), "--cpu", "08", "--dry-run",
                                "--tipo", "hash", "--modo", "0", str(objetivo)],
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 0 if len(os.sched_getaffinity(0)) >= 8 else 2)
            self.assertNotIn("value too great for base", p.stderr)

    def test_mascara_separa_objetivos_y_configuraciones_y_reanuda(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            motor = base / "hashcat"
            motor.write_text(f"#!{sys.executable}\n"
                             "import json,sys\nfrom pathlib import Path\na=sys.argv[1:]\n"
                             "r=Path(a[a.index('--restore-file-path')+1])\n"
                             "if '--restore' in a: print('OBJETIVO_REANUDADO='+r.read_text());sys.exit(0)\n"
                             "h=a[a.index('-m')+2];r.write_text(h);sys.exit(2)\n")
            motor.chmod(0o700)
            pgrep = base / "pgrep"
            pgrep.write_text("#!/bin/sh\nexit 1\n")
            pgrep.chmod(0o700)
            env = {**os.environ, "AUDITOR_HASHCAT": str(motor),
                   "PATH": str(base) + ":" + os.environ["PATH"]}
            for nombre in ("A", "B"):
                (base / nombre).write_text(f"hash_ficticio_{nombre}\n")

            def ejecutar(nombre, *extras):
                return subprocess.run(["bash", str(BASE / 'run_mascara_larga.sh'),
                                       "--hash", nombre, "--dir", str(base / 'estado'),
                                       "--longitudes", "10", *extras], cwd=base, env=env,
                                      capture_output=True, text=True, timeout=10)

            self.assertEqual(ejecutar('A').returncode, 2)
            estado = ejecutar('A', '--estado')
            self.assertEqual(estado.returncode, 0, estado.stderr)
            self.assertIn('hay .restore', estado.stdout)
            self.assertEqual(ejecutar('B').returncode, 2)
            a = ejecutar('A')
            self.assertEqual(a.returncode, 0, a.stderr)
            self.assertIn('OBJETIVO_REANUDADO=' + str(base / 'A'), a.stdout)
            self.assertEqual(ejecutar('A', '--charset', '?d').returncode, 2)
            self.assertEqual(len(list((base / 'estado').glob('*.restore'))), 3)
            for log in (base / 'estado').glob('*.log'):
                self.assertEqual(log.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
