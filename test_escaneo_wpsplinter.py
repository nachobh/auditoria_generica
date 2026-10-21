from contextlib import redirect_stdout
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import extras_wifi


CSV_REAL = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
02:11:22:33:44:55, 2026-10-21 11:09:45, 2026-10-21 11:10:03, 10, 270, WPA2, CCMP, PSK, -61,       17,        0,   0.  0.  0.  0,  12, RED_FICTICIA_5G, 
02:AA:BB:CC:DD:EE, 2026-10-21 11:09:45, 2026-10-21 11:10:01,  1, 130, WPA2, CCMP, PSK, -61,       19,        0,   0.  0.  0.  0,  12, RED_FICTICIA, 
02:AA:BB:CC:DD:EE, 2026-10-21 11:09:45, 2026-10-21 11:10:02,  1, 130, WPA2, CCMP, PSK, -55,       20,        0,   0.  0.  0.  0,  12, RED_FICTICIA, 
AA:BB:CC, malformada
Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
"""


class EscaneoTests(unittest.TestCase):
    def test_ap_del_csv_lee_campos_reales_de_airodump(self):
        with tempfile.TemporaryDirectory() as td:
            csv = Path(td) / "scan-01.csv"
            csv.write_text(CSV_REAL, encoding="utf-8")
            aps = extras_wifi._ap_del_csv(csv)
        # deduplicado por BSSID conservando la mejor señal, ordenado por potencia
        self.assertEqual([(a[0], a[1], a[2], a[3]) for a in aps],
                         [("02:AA:BB:CC:DD:EE", 1, "RED_FICTICIA", -55),
                          ("02:11:22:33:44:55", 10, "RED_FICTICIA_5G", -61)])

    def test_wifi_escanear_valida_rangos(self):
        with self.assertRaisesRegex(ValueError, "segundos fuera"):
            extras_wifi.wifi_escanear("wlan0", segundos=3)
        with self.assertRaisesRegex(ValueError, "banda"):
            extras_wifi.wifi_escanear("wlan0", banda="6g")

    def test_wifi_escanear_dry_run(self):
        salida = io.StringIO()
        with redirect_stdout(salida):
            rc = extras_wifi.wifi_escanear("wlan0", segundos=30, seco=True)
        self.assertEqual(rc, 0)
        self.assertIn("dejarlo activo", salida.getvalue())


class WpsplinterTests(unittest.TestCase):
    def test_exige_script_vendor(self):
        with patch.object(Path, "is_file", return_value=False):
            with self.assertRaisesRegex(ValueError, "falta"):
                extras_wifi.wifi_wpsplinter("wlan0mon", "Red")

    def test_rechaza_ssid_largo(self):
        with self.assertRaisesRegex(ValueError, "SSID"):
            extras_wifi.wifi_wpsplinter("wlan0mon", "x" * 40)

    def test_dry_run_no_toca_hardware(self):
        salida = io.StringIO()
        with redirect_stdout(salida):
            rc = extras_wifi.wifi_wpsplinter("wlan0mon", "Red Ficticia", seco=True)
        self.assertEqual(rc, 0)
        self.assertIn("WPSplinter", salida.getvalue())

    def test_cli_alias_y_dry_run(self):
        auditor = Path(__file__).with_name("auditor_generico.sh")
        casos = {"wpsplinter": ["--ssid", "Red Ficticia"], "escanear": ["--segundos", "30"]}
        for modo, extra in casos.items():
            proceso = subprocess.run(
                ["bash", str(auditor), "--modo", modo, "--interfaz", "wlan0mon",
                 *extra, "--dry-run"],
                capture_output=True, text=True, timeout=15)
            self.assertEqual(proceso.returncode, 0, proceso.stderr)
            self.assertIn("Plan:", proceso.stdout)


if __name__ == "__main__":
    unittest.main()
