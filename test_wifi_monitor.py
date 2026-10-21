from contextlib import redirect_stdout
import io
import unittest
from unittest.mock import patch

import extras_wifi


class WifiMonitorTests(unittest.TestCase):
    def test_rechaza_interfaz_desconocida(self):
        with patch.object(extras_wifi, "_interfaces_wifi", return_value=["wlan0"]):
            with self.assertRaisesRegex(ValueError, "no aparece como interfaz WiFi"):
                extras_wifi.wifi_monitor("wlan1", "activar", seco=True)

    def test_rechaza_accion_invalida(self):
        with self.assertRaisesRegex(ValueError, "--accion"):
            extras_wifi.wifi_monitor("wlan0", "freir-huevos")

    def test_niega_activar_sobre_ruta_por_defecto_sin_forzar(self):
        with patch.object(extras_wifi, "_interfaces_wifi", return_value=["wlan0"]), \
             patch.object(extras_wifi, "_interfaz_predeterminada", return_value="wlan0"):
            with self.assertRaisesRegex(ValueError, "ruta por defecto"):
                extras_wifi.wifi_monitor("wlan0", "activar", forzar=False, seco=True)
            # con --forzar sí deja pasar hasta el plan (dry-run no toca nada)
            salida = io.StringIO()
            with redirect_stdout(salida):
                rc = extras_wifi.wifi_monitor("wlan0", "activar", forzar=True, seco=True)
            self.assertEqual(rc, 0)
            self.assertIn("desconectará", salida.getvalue())

    def test_desactivar_sobre_ruta_por_defecto_no_requiere_forzar(self):
        # sólo "activar" sobre la interfaz de la ruta por defecto es arriesgado
        with patch.object(extras_wifi, "_interfaces_wifi", return_value=["wlan0"]), \
             patch.object(extras_wifi, "_interfaz_predeterminada", return_value="wlan0"):
            salida = io.StringIO()
            with redirect_stdout(salida):
                rc = extras_wifi.wifi_monitor("wlan0", "desactivar", seco=True)
            self.assertEqual(rc, 0)

    def test_listar_sin_interfaces(self):
        with patch.object(extras_wifi, "_interfaces_wifi", return_value=[]):
            salida = io.StringIO()
            with redirect_stdout(salida):
                rc = extras_wifi.listar_interfaces_wifi()
            self.assertEqual(rc, 1)
            self.assertIn("No se detectaron", salida.getvalue())

    def test_listar_marca_la_interfaz_predeterminada(self):
        with patch.object(extras_wifi, "_interfaces_wifi", return_value=["wlan0", "wlan1"]), \
             patch.object(extras_wifi, "_interfaz_predeterminada", return_value="wlan0"), \
             patch.object(extras_wifi, "_modo_interfaz", return_value="managed"):
            salida = io.StringIO()
            with redirect_stdout(salida):
                rc = extras_wifi.listar_interfaces_wifi()
            self.assertEqual(rc, 0)
            lineas = salida.getvalue().splitlines()
            fila_wlan0 = next(l for l in lineas if l.startswith("wlan0"))
            fila_wlan1 = next(l for l in lineas if l.startswith("wlan1"))
            self.assertIn("cuidado", fila_wlan0)
            self.assertNotIn("cuidado", fila_wlan1)


if __name__ == "__main__":
    unittest.main()
