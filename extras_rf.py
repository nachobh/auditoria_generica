#!/usr/bin/env python3
"""Pruebas acotadas de radio no-WiFi: recon Bluetooth/BLE y comprobación SDR.

El kit audita claves de acceso; estas dos familias cubren el resto del
espectro que un pentester inalámbrico encuentra en casa/oficina:

  ble-recon  descubrimiento BLE pasivo/activo acotado con bluetoothctl
             (los dispositivos que responden dicen mucho de quién vive en
             la casa: wearables, cerraduras, sensores emparejables).
  sdr-check  comprobación de hardware y herramientas RTL-SDR; sin dongle
             no hay ataque que lanzar, y el kit no instala drivers.
"""

import argparse
import os
import re
import shutil
import subprocess
import time

USB_RADIO = re.compile(r"rtl2832|rtl-sdr|realtek.*radio|rtl2832u", re.I)


def _binario(nombre):
    return shutil.which(nombre) or shutil.which(
        nombre, path=os.environ.get("PATH", "") + ":/usr/sbin")


def ble_recon(segundos=30, seco=False):
    """Barrido BLE acotado; lista dispositivos vistos (direcciones completas:
    una MAC BLE no es un secreto, igual que el BSSID)."""
    if not 5 <= segundos <= 300:
        raise ValueError("--segundos debe estar entre 5 y 300")
    if seco:
        print(f"Plan: {segundos}s de escaneo BLE con bluetoothctl y lista de "
              "dispositivos visibles")
        return 0
    control = _binario("bluetoothctl")
    if not control:
        raise ValueError("falta bluetoothctl (paquete bluez)")
    if not list(__import__("pathlib").Path("/sys/class/bluetooth").glob("hci*")):
        print("Sin adaptador Bluetooth (hci0) visible: ¿apagado por rfkill?")
        return 3
    encendido = subprocess.run([control, "power", "on"], capture_output=True,
                               text=True, timeout=15, check=False)
    if "Failed" in encendido.stdout + encendido.stderr:
        print("El adaptador no se puede encender (rfkill duro o bloqueado)")
        return 3
    try:
        with open(os.devnull, "wb") as nada:
            subprocess.run([control, "--timeout", str(segundos), "scan", "on"],
                           stdout=nada, stderr=nada, timeout=segundos + 20,
                           check=False)
        tiempo = subprocess.run([control, "devices"], capture_output=True,
                                text=True, timeout=15, check=False)
        vistos = [linea for linea in tiempo.stdout.splitlines()
                  if linea.startswith("Device ")]
        for linea in vistos[:40]:
            print(linea)
        print(f"Dispositivos BLE/BR-EDR visibles: {len(vistos)}")
        return 0 if vistos else 1
    finally:
        subprocess.run([control, "scan", "off"], capture_output=True,
                       timeout=10, check=False)


def sdr_check(seco=False):
    """Comprueba dongle RTL-SDR y utilidades; sin ambas cosas no hay ataque SDR."""
    if seco:
        print("Plan: lsusb en busca de RTL2832U y comprobación de rtl_test")
        return 0
    lsusb = _binario("lsusb")
    hardware = False
    if lsusb:
        usb = subprocess.run([lsusb], capture_output=True, text=True,
                             timeout=15, check=False)
        hardware = bool(USB_RADIO.search(usb.stdout))
    herramientas = bool(_binario("rtl_test") and _binario("rtl_sdr"))
    if not hardware:
        print("Sin dongle RTL-SDR (RTL2832U) en el bus USB: la familia de "
              "ataques SDR (ISMA, TPMS, 433 MHz, ADS-B) no aplica a este "
              "equipo; el kit no la automatiza")
        return 1
    if not herramientas:
        print("Dongle RTL-SDR detectado pero faltan utilidades: "
              "sudo apt-get install -y rtl-sdr")
        return 2
    prueba_bin = _binario("rtl_test")
    prueba = subprocess.run(["timeout", "6", prueba_bin or "rtl_test", "-t"],
                            capture_output=True, text=True, timeout=20,
                            check=False)
    ok = "Test succeeded" in prueba.stdout or "successful" in prueba.stdout
    print(f"Dongle RTL-SDR + rtl_test: {'OK, listo para capturas' if ok else 'presente pero rtl_test falló (ver dmesg/permisos plugdev)'}")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="accion", required=True)
    ble = sub.add_parser("ble-recon")
    ble.add_argument("--segundos", type=int, default=30)
    ble.add_argument("--dry-run", action="store_true")
    sdr = sub.add_parser("sdr-check")
    sdr.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.accion == "ble-recon":
            return ble_recon(args.segundos, args.dry_run)
        return sdr_check(args.dry_run)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
