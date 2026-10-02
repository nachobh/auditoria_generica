from contextlib import redirect_stdout
from http.server import HTTPServer
import io
from pathlib import Path
import threading
import unittest

from ejemplos.web_lab import Laboratorio
from extras_web import login, sqli


class WebExtraTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Laboratorio.intentos = 0
        Laboratorio.con_limite = False
        cls.server = HTTPServer(("127.0.0.1", 0), Laboratorio)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_login_ficticio_oculta_candidato(self):
        salida = io.StringIO()
        lista = Path(__file__).with_name("ejemplos") / "candidatos_web_ficticios.txt"
        with redirect_stdout(salida):
            estado = login(self.base + "/wp-login.php", "demo", lista, 3, pausa=0)
        self.assertEqual(estado, 0)
        self.assertIn("Acceso confirmado", salida.getvalue())
        self.assertNotIn("solo_ficticio_01!", salida.getvalue())

    def test_sqli_distingue_consulta_insegura_y_parametrizada(self):
        salida = io.StringIO()
        with redirect_stdout(salida):
            vulnerable = sqli(self.base + "/buscar-vulnerable", "q", "libro_ficticio",
                              "RESULTADO_FICTICIO")
            seguro = sqli(self.base + "/buscar-seguro", "q", "libro_ficticio",
                          "RESULTADO_FICTICIO")
        self.assertEqual(vulnerable, 0)
        self.assertEqual(seguro, 1)


if __name__ == "__main__":
    unittest.main()
