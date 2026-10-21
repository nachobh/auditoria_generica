# Changelog

Formato [Keep a Changelog](https://keepachangelog.com/es/1.1.0/),
versionado según [SemVer](https://semver.org/lang/es/).

## [Unreleased]

## [1.2.0] — 2026-10-21

### Añadido
- Menú WiFi reorganizado en cuatro bloques (Tarjeta de red, Escaneo de
  objetivos, Ataque WPA, Ataque WPS) y navegación anidada: cada operación
  devuelve al submenú desde el que se lanzó, no al menú principal.
- Objetivo en memoria: `wifi-escanear` (alias `--modo escanear`) barre el
  entorno y deja elegido ESSID/BSSID/canal; los prompts de BSSID/SSID/canal
  reutilizan el objetivo con Enter y aceptan `escanear` para elegirlo en el
  momento. El objetivo persiste en `~/.local/state/kit-auditoria-claves/`.
- El modo monitor ya no se desactiva solo tras escaneos ni capturas
  (`--mantener-monitor` en run_captura_wifi.sh); sólo la opción del menú
  "Desactivar modo monitor" lo quita, y ahora también resucita
  NetworkManager y reconecta la interfaz base tras el `airmon-ng check kill`.
- Nuevo modo `wifi-wpsplinter` (alias `--modo wpsplinter`): huella activa del
  desbordamiento del monitor WPS de Broadcom (Quentin Kaiser, oct-2026)
  usando el fingerprinter oficial (third_party/broadcom-wps, MIT, scapy).
  Veredicto LIKELY_VULNERABLE/NOT/INCONCLUSIVE con evidencias pcap+JSON.
- El menú guiado (sin argumentos) ya no termina el script al acabar una
  auditoría: vuelve a mostrar el menú principal tras cada ronda (fichero o
  modo extra) y sólo sale de verdad cuando se elige "0) Salir" en el menú
  de grupos. Cada ronda corre en un subshell para que un fallo o una
  cancelación tampoco cierren la sesión. La invocación directa por CLI
  (`--tipo ...`) no cambia: sigue ejecutando una sola vez y terminando.
- Nuevo modo `wifi-monitor` (alias `--modo monitor`): activa o desactiva modo
  monitor en una interfaz WiFi propia (equivalente a `airmon-ng start/stop`
  usando `ip`/`iw`), con `--listar` para ver las interfaces WiFi detectadas,
  su modo actual y si alguna es la de la ruta por defecto. Se niega a poner
  en modo monitor la interfaz de la ruta por defecto salvo `--forzar`, para
  no cortar por accidente la propia conexión a internet o la sesión SSH.
  Disponible también en el menú guiado (grupo "Auditoría WiFi").
- `wifi-wps-scan` ahora usa `wash -j` para leer, cuando el AP lo anuncia, el
  fabricante y modelo del elemento de información WPS (`wps_manufacturer`,
  `wps_model_name`, `wps_model_number`); si no está disponible, estima el
  fabricante por el OUI de la MAC con la base local `ieee-data` (nuevo
  módulo `oui_lookup.py`, sin consultas externas). Si el fabricante
  coincide con la lista pública de marcas citadas en el aviso de
  WPSplinter, añade un aviso puramente informativo (sin comprobar ni
  explotar el fallo).

### Corregido
- El inventario WASM restringe cada lectura a su sección y rechaza enteros
  de más de 32 bits, UTF-8 inválido, secciones de inventario repetidas y
  contenido sobrante. La lectura del archivo también queda limitada a 8 MiB.
- `cred-scan` recorre los archivos de forma incremental y termina al alcanzar
  el límite; oculta completamente secretos de hasta cuatro caracteres y
  escapa controles de terminal en los hallazgos.
- El descargador rechaza nombres desconocidos antes de procesar una selección,
  enlaces y destinos no regulares; informa fallos al guardar y acota la espera
  de las descargas.
- Los cortes y límites de autenticación SSH devuelven estado inconcluyente
  (código 3), en lugar de éxito.
- Pruebas de regresión con módulos, listas y motores ficticios para estos casos.

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
- `--version` en `auditor_generico.sh` y este changelog.
- Licencia Apache-2.0 (`LICENSE`) con `NOTICE` de atribuciones: RainbowCrack 1.2
  incluido en el repo (términos del autor en `rainbowcrack/disclaimer.txt`) y
  terceros externos documentados (SecLists MIT, john/aircrack-ng/reaver GPL,
  bettercap GPLv3, hashcat y bkcrack MIT).

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
