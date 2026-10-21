import unittest

import oui_lookup


class OuiLookupTests(unittest.TestCase):
    def setUp(self):
        self._cache_previo = oui_lookup._CACHE
        oui_lookup._CACHE = {"F08620": "Arcadyan Corporation", "0017C2": "Broadcom"}

    def tearDown(self):
        oui_lookup._CACHE = self._cache_previo

    def test_vendor_de_mac_encuentra_por_oui(self):
        self.assertEqual(oui_lookup.vendor_de_mac("F0:86:20:84:B1:66"), "Arcadyan Corporation")
        self.assertEqual(oui_lookup.vendor_de_mac("f0:86:20:11:22:33"), "Arcadyan Corporation")

    def test_vendor_de_mac_desconocido_o_invalido(self):
        self.assertIsNone(oui_lookup.vendor_de_mac("AA:BB:CC:11:22:33"))
        self.assertIsNone(oui_lookup.vendor_de_mac("no-es-mac"))
        self.assertIsNone(oui_lookup.vendor_de_mac(""))

    def test_posible_wpsplinter_por_coincidencia_de_marca(self):
        self.assertTrue(oui_lookup.posible_wpsplinter("Broadcom"))
        self.assertTrue(oui_lookup.posible_wpsplinter("Sagemcom Broadband SAS"))
        self.assertFalse(oui_lookup.posible_wpsplinter("Apple, Inc."))
        self.assertFalse(oui_lookup.posible_wpsplinter(None))
        self.assertFalse(oui_lookup.posible_wpsplinter(""))


if __name__ == "__main__":
    unittest.main()
