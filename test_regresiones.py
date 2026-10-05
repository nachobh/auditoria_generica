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
from unittest.mock import patch

from extras_credenciales import cred_scan, enmascarar, escanear_arbol
from extras_wasm import inventario, uleb
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


class RobustezInventario(unittest.TestCase):
    def test_corte_o_limite_ssh_no_se_informa_como_acceso(self):
        from extras_ssh import ssh_brute
        with tempfile.TemporaryDirectory() as td:
            lista = Path(td) / "ficticia.txt"
            lista.write_text("demo_ficticia_1\ndemo_ficticia_2\n")
            for detalle in (b"Too many authentication failures", b"Connection closed"):
                respuesta = subprocess.CompletedProcess([], 255, b"", detalle)
                with self.subTest(detalle=detalle), \
                        patch("extras_ssh.shutil.which", return_value="simulado"), \
                        patch("extras_ssh.subprocess.run", return_value=respuesta) as ejecutar, \
                        redirect_stdout(io.StringIO()):
                    self.assertEqual(ssh_brute("127.0.0.1", "demo", lista, 2), 3)
                    self.assertEqual(ejecutar.call_count, 1)

    def test_wasm_rechaza_secciones_malformadas(self):
        # El contador no puede tomarse del encabezado de la sección siguiente.
        secciones = (
            b"\x02\x00\x00\x00",
            b"\x07\x00\x00\x00",
            b"\x02\x02\x00\x00",  # contenido sobrante
            b"\x07\x03\x01\x00\x00",  # export sin índice
            b"\x07\x04\x01\x00\x04\x00",  # tipo desconocido
            b"\x02\x01\x00\x02\x01\x00",  # sección repetida
            b"\x07\x05\x01\x01\xff\x00\x00",  # UTF-8 inválido
            b"\x02\x05\x01\x00\x00\x03\x7f",  # global truncado
        )
        with tempfile.TemporaryDirectory() as td:
            archivo = Path(td) / "ficticio.wasm"
            for seccion in secciones:
                with self.subTest(seccion=seccion):
                    archivo.write_bytes(b"\0asm\x01\0\0\0" + seccion)
                    with self.assertRaises(ValueError):
                        inventario(archivo)

    def test_leb128_limita_enteros_y_detecta_truncamiento(self):
        self.assertEqual(uleb(b"\xff\xff\xff\xff\x0f", 0), (2**32 - 1, 5))
        for dato in (b"\x80", b"\xff\xff\xff\xff\x10",
                     b"\x80\x80\x80\x80\x80\x00"):
            with self.subTest(dato=dato), self.assertRaises(ValueError):
                uleb(dato, 0)

    def test_escaneo_se_detiene_sin_recorrer_todo_el_arbol(self):
        with tempfile.TemporaryDirectory() as td:
            fichero = Path(td) / "ficticio.txt"
            fichero.write_text("password=demo_ficticia\n")

            def rutas():
                yield fichero
                self.fail("se recorrió el árbol después de alcanzar el límite")

            with patch("extras_credenciales.iterar_ficheros", return_value=rutas()):
                hallazgos, _ = escanear_arbol(td, maximo=1)
            self.assertEqual(len(hallazgos), 1)
            for limite in (0, -1, 50001):
                with self.assertRaises(ValueError):
                    escanear_arbol(td, maximo=limite)

    def test_escaneo_oculta_claves_cortas_y_controles(self):
        for valor in ("", "a", "ab", "abc", "abcd"):
            self.assertEqual(enmascarar(valor), "*" * len(valor))
        with tempfile.TemporaryDirectory() as td:
            fichero = Path(td) / "demo\x1b[31m.txt"
            fichero.write_text("password=z\n")
            salida = io.StringIO()
            with redirect_stdout(salida):
                self.assertEqual(cred_scan(fichero), 0)
            self.assertNotIn("\x1b", salida.getvalue())
            self.assertIn("password-fichero *", salida.getvalue())


class RobustezDescargas(unittest.TestCase):
    def setUp(self):
        self.temporal = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporal.cleanup)
        self.base = Path(self.temporal.name)
        self.script = self.base / "descargar.sh"
        shutil.copyfile(BASE / "wordlists/descargar_wordlists.sh", self.script)
        datos = b"lista_ficticia\n"
        (self.base / "manifest.tsv").write_text(
            f"demo.txt\t1\t{hashlib.sha256(datos).hexdigest()}\ttxt\tdemo.txt\n")
        self.binarios = self.base / "bin"
        self.binarios.mkdir()
        curl = self.binarios / "curl"
        curl.write_text(f"#!{sys.executable}\nimport sys\nfrom pathlib import Path\n"
                        f"Path(sys.argv[sys.argv.index('-o')+1]).write_bytes({datos!r})\n")
        curl.chmod(0o700)
        self.destino = self.base / "salida"

    def ejecutar(self, *args):
        return subprocess.run(["bash", str(self.script), "--destino", str(self.destino), *args],
                              env={**os.environ, "PATH": str(self.binarios) + ":" + os.environ["PATH"]},
                              capture_output=True, text=True, timeout=10)

    def test_nombre_desconocido_aborta_tambien_en_seleccion_mixta(self):
        p = self.ejecutar("demo.txt", "desconocido.txt")
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertFalse(self.destino.exists())

    def test_descarga_simulada_y_verificacion(self):
        p = self.ejecutar("demo.txt")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual((self.destino / "demo.txt").read_text(), "lista_ficticia\n")
        self.assertEqual(self.ejecutar("--comprobar", "demo.txt").returncode, 0)
        (self.destino / "demo.txt").write_text("alterada\n")
        self.assertEqual(self.ejecutar("--comprobar", "demo.txt").returncode, 1)

    def test_fallo_al_guardar_no_anuncia_exito_y_limpia_temporales(self):
        mv = self.binarios / "mv"
        mv.write_text("#!/bin/sh\nexit 1\n")
        mv.chmod(0o700)
        p = self.ejecutar("demo.txt")
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("no se pudo guardar", p.stderr)
        self.assertNotIn("ok (", p.stdout)
        self.assertEqual(list(self.destino.iterdir()), [])

    def test_rechaza_destino_directorio_o_enlace(self):
        self.destino.mkdir()
        objetivo = self.destino / "demo.txt"
        objetivo.mkdir()
        self.assertEqual(self.ejecutar("demo.txt").returncode, 1)
        objetivo.rmdir()
        fuera = self.base / "fuera.txt"
        fuera.write_text("conservar\n")
        objetivo.symlink_to(fuera)
        self.assertEqual(self.ejecutar("demo.txt").returncode, 1)
        self.assertEqual(fuera.read_text(), "conservar\n")


if __name__ == "__main__":
    unittest.main()
