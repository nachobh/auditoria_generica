from pathlib import Path
import subprocess
import tempfile
import unittest

from wps_capture_utils import estado_wps


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
