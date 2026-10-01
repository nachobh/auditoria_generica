import csv
from pathlib import Path
import subprocess
import tempfile
import unittest

from wifi_capture_utils import filtrar_hashes, seleccionar_ap


SCRIPT = Path(__file__).with_name("run_captura_wifi.sh")


def csv_escaneo(ruta):
    with ruta.open("w", newline="", encoding="utf-8") as archivo:
        writer = csv.writer(archivo)
        writer.writerow(["BSSID", "First time seen", "Last time seen", "channel",
                         "Speed", "Privacy", "Cipher", "Authentication", "Power",
                         "# beacons", "# IV", "LAN IP", "ID-length", "ESSID", "Key"])
        for mac, canal, nombre in (
            ("00:11:22:33:44:55", "6", "Red de prueba"),
            ("AA:BB:CC:DD:EE:FF", "36", "Red de prueba"),
            ("12:34:56:78:9A:BC", "11", "Otra red"),
        ):
            writer.writerow([mac, "", "", canal, "", "WPA2", "CCMP", "PSK",
                             "", "", "", "", "", nombre, ""])
        writer.writerow([])
        writer.writerow(["Station MAC", "First time seen", "Last time seen",
                         "Power", "# packets", "BSSID", "Probed ESSIDs"])
        writer.writerow(["DE:AD:BE:EF:00:01", "", "", "", "", "", "Red de prueba"])


class WifiCaptureTests(unittest.TestCase):
    def test_seleccion_exacta_y_duplicados(self):
        with tempfile.TemporaryDirectory() as td:
            ruta = Path(td) / "scan.csv"
            csv_escaneo(ruta)
            self.assertEqual(seleccionar_ap(ruta, "Otra red"),
                             ("12:34:56:78:9A:BC", 11))
            self.assertEqual(seleccionar_ap(ruta, "Red de prueba", "aa:bb:cc:dd:ee:ff"),
                             ("AA:BB:CC:DD:EE:FF", 36))
            with self.assertRaisesRegex(ValueError, "ambiguo"):
                seleccionar_ap(ruta, "Red de prueba")
            with self.assertRaisesRegex(ValueError, "no se encontró"):
                seleccionar_ap(ruta, "Red")

    def test_filtra_hashes_por_bssid_y_ssid(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            origen = base / "todos.22000"
            destino = base / "objetivo.22000"
            nombre = "Red de prueba"
            hex_ssid = nombre.encode().hex()
            esperado = f"WPA*02*mic*001122334455*66778899aabb*{hex_ssid}*resto\n"
            origen.write_text(
                esperado
                + f"WPA*01*pmkid*aabbccddeeff*66778899aabb*{hex_ssid}*resto\n"
                + "WPA*02*mic*001122334455*66778899aabb*4f74726120726564*resto\n"
            )
            self.assertEqual(filtrar_hashes(origen, destino, "00:11:22:33:44:55", nombre),
                             {"01": 0, "02": 1})
            self.assertEqual(destino.read_text(), esperado)
            sin_hash = base / "ausente.22000"
            self.assertEqual(filtrar_hashes(origen, sin_hash, "DE:AD:BE:EF:00:01"),
                             {"01": 0, "02": 0})
            self.assertFalse(sin_hash.exists())

    def test_dry_run_no_necesita_root_ni_herramientas(self):
        with tempfile.TemporaryDirectory() as td:
            salida = Path(td) / "salida"
            proc = subprocess.run(
                ["bash", str(SCRIPT), "--interfaz", "wlan0", "--ssid",
                 "Red de prueba", "--banda", "abg", "--salida", str(salida),
                 "--dry-run"], capture_output=True, text=True, timeout=10
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("se hará un escaneo pasivo", proc.stdout)
            self.assertFalse(salida.exists())

            directo = subprocess.run(
                ["bash", str(SCRIPT), "--interfaz", "wlan0mon", "--bssid",
                 "00:11:22:33:44:55", "--canal", "6", "--dry-run"],
                capture_output=True, text=True, timeout=10
            )
            self.assertEqual(directo.returncode, 0, directo.stderr)
            self.assertNotIn("se hará un escaneo pasivo", directo.stdout)

    def test_deauth_requiere_bssid_explicito(self):
        proc = subprocess.run(
            ["bash", str(SCRIPT), "--interfaz", "wlan0", "--ssid",
             "Red de prueba", "--deauth", "2", "--dry-run"],
            capture_output=True, text=True, timeout=10
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("requiere --bssid", proc.stderr)


if __name__ == "__main__":
    unittest.main()
