from pathlib import Path
import subprocess
import tempfile
import unittest

from wps_capture_utils import estado_wps, etiqueta_modelo, parse_wash_json


SCRIPT = Path(__file__).with_name("run_captura_wifi_wps.sh")


class WpsCaptureTests(unittest.TestCase):
    def test_detecta_solo_bssid_y_canal_elegidos(self):
        muestra = [
            "BSSID Ch dBm WPS Lck Vendor ESSID\n",
            "02:11:22:33:44:55 6 -54 2.0 No Ficticio Red de prueba\n",
            "02:11:22:33:44:55 36 -50 2.0 Yes Ficticio Red de prueba\n",
            "02:11:22:33:44:66 6 -55 1.0 No Ficticio Otra red\n",
        ]
        self.assertEqual(estado_wps(muestra, "02:11:22:33:44:55", 6), ("2.0", "No"))
        self.assertEqual(estado_wps(muestra, "02:11:22:33:44:55", 36), ("2.0", "Yes"))
        self.assertIsNone(estado_wps(muestra, "02:11:22:33:44:55", 100))
        self.assertIsNone(estado_wps(muestra, "02:11:22:33:44:77", 6))

    def test_parse_wash_json_extrae_fabricante_y_modelo(self):
        # Formato real del volcado -j de wash (comas finales, repetido por AP).
        volcado = (
            '{"bssid" : "F0:86:20:84:B1:66", "essid" : "MiFibra-7330", '
            '"channel" : 6, "wps_version" : 2, "wps_locked" : 0, '
            '"wps_manufacturer" : "Broadcom", "wps_model_name" : "HGU", '
            '"wps_model_number" : "FAST5656", "wps_device_name" : "", }\n'
            '{"bssid" : "02:11:22:33:44:66", "essid" : "Otra", '
            '"channel" : 36, "wps_version" : 1, "wps_locked" : 1, '
            '"wps_manufacturer" : "", "wps_model_name" : "", '
            '"wps_model_number" : "", "wps_device_name" : "", }\n'
        )
        filas = parse_wash_json(volcado)
        self.assertEqual(len(filas), 2)
        primera = filas[0]
        self.assertEqual(primera["bssid"], "F0:86:20:84:B1:66")
        self.assertEqual(primera["canal"], 6)
        self.assertEqual(primera["locked"], "No")
        self.assertEqual(primera["manufacturer"], "Broadcom")
        self.assertEqual(primera["model_name"], "HGU")
        segunda = filas[1]
        self.assertEqual(segunda["locked"], "Yes")
        self.assertEqual(segunda["manufacturer"], "")

    def test_parse_wash_json_vacio_sin_bssid(self):
        self.assertEqual(parse_wash_json("sin json aqui"), [])
        self.assertEqual(parse_wash_json(""), [])

    def test_etiqueta_modelo_prioriza_wps_sobre_oui(self):
        fila = {"manufacturer": "Broadcom", "model_name": "HGU", "model_number": "FAST5656"}
        self.assertEqual(etiqueta_modelo(fila, "Arcadyan Corporation"),
                         "Broadcom HGU FAST5656")
        fila_vacia = {"manufacturer": "", "model_name": "", "model_number": ""}
        self.assertEqual(etiqueta_modelo(fila_vacia, "Arcadyan Corporation"),
                         "Arcadyan Corporation (estimado por MAC, no es el modelo exacto)")
        self.assertEqual(etiqueta_modelo(fila_vacia, None), "")

    def test_dry_run_no_crea_archivos(self):
        with tempfile.TemporaryDirectory() as td:
            salida = Path(td) / "salida"
            proceso = subprocess.run(
                ["bash", str(SCRIPT), "--interfaz", "wlan0", "--bssid",
                 "02:11:22:33:44:55", "--canal", "36", "--observar-seg", "12",
                 "--captura-seg", "8", "--salida", str(salida), "--dry-run"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(proceso.returncode, 0, proceso.stderr)
            self.assertIn("observación pasiva=12s", proceso.stdout)
            self.assertIn("captura de evidencia=8s", proceso.stdout)
            self.assertFalse(salida.exists())


if __name__ == "__main__":
    unittest.main()
