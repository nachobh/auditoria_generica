# Changelog

Formato [Keep a Changelog](https://keepachangelog.com/es/1.1.0/),
versionado según [SemVer](https://semver.org/lang/es/).

## [1.1.0] — 2026-10-05

### Añadido
- Wordlists en español (Pwdb común, lang-spanish, Moby, RAE y usuarios/contraseñas
  de SecLists) en el manifiesto y en los niveles 1 y 3 del auditor.
- `ftp-brute`: intentos de contraseña FTP acotados con `ftplib` (hasta 200,
  un intento por candidato, se detiene ante 421 o error de conexión).
- `mitm-arp`: envenenamiento ARP acotado con bettercap (10–3600 s),
  autodetección de gateway, `--sin-gateway` y restauración garantizada de
  `ip_forward`.
- `run_mascara_larga.sh`: máscaras alfanuméricas largas (10–12) con pausa
  (`--parar`), reanudación automática por `.restore` y estado (`--estado`).
- `cred-scan` reconoce tokens `github_pat_`, `glpat-`, `npm_`, `dckr_pat_` y
  descarta marcadores de plantilla (`changeme`, `<token>`, …).
- `--version` en `auditor_generico.sh`, `LICENSE` MIT y este changelog.

### Cambiado
- Prioridad del motor GPU: hashcat HIP 7.1.2 en `~/.local/share` antes que el
  paquete apt (OpenCL/CPU); `-w 4` en ataques y calibración con la misma
  workload para que la estimación sea justa.
- `wash` en vivo deja de ser el método único: con chips que no entregan
  beacons en monitor (mt7925) se captura con `airodump-ng` y se analiza
  offline con `wash -f`.
- `aireplay-ng` se invoca con `--ignore-negative-one` (drivers que reportan
  canal -1).

### Corregido
- `.hccapx`: conversión con `hccap2john` (hashcat 7 eliminó el modo 2500).
- Contraseñas del pot de john que contienen `:` sin truncar (corte sólo en el
  primer dos puntos).
- Propiedad del directorio de salida al ejecutar bajo sudo.
- Regresiones de menús y aliases de `--modo` (números vs nombres).

## [1.0.0] — 2026-10-02

### Añadido
- `auditor_generico.sh` con niveles 1–5, calibración de velocidad,
  verificación externa y salida enmascarada por defecto.
- Captura WiFi dirigida (`run_captura_wifi.sh`), observación WPS y evidencia.
- Auditorías acotadas: WiFi (WPS PIN, PMKID, deauth, escaneo WPS), archivos
  (ZipCrypto, permisos PDF), web (login WordPress, HTTP Basic, SQLi booleana),
  SSH con sshpass, credenciales en ficheros e inventario WASM.
- Menú guiado con comando equivalente impreso antes de ejecutar.
