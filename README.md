# kit-auditoria-claves

Licencia Apache-2.0 (ver `LICENSE` y `NOTICE`) · `auditor_generico.sh --version` ·
registro de cambios en [CHANGELOG.md](CHANGELOG.md)

Base común para auditorías de contraseñas: un único script guiado (`auditor_generico.sh`)
que va de lo simple a lo complejo, con los wordlists, las reglas de ataque y (opcional)
RainbowCrack compilable desde la fuente incluida.

> **Uso autorizado.** Este material sirve para auditar sistemas y ficheros propios o
> para los que tengas autorización expresa por escrito. Por defecto los candidatos
> hallados se ocultan y los potfiles y logs se borran al terminar.

Para presentar el proyecto sin credenciales ajenas ni descargas, ejecuta
`python3 demo_controles.py`. Usa ocho cadenas ficticias definidas en el código;
no lee archivos privados ni accede a la red. Compara SHA-256 sin sal, SHA-256
con sal única y PBKDF2-HMAC-SHA256 con 100 000 iteraciones. Si está instalado
`argon2-cffi`, mide también Argon2id con 19 MiB y dos iteraciones. Incluye una
tabla precalculada pequeña y un simulador local de límite de intentos y segundo
factor. Sus tiempos son ilustrativos de esta máquina.
Para una auditoría pequeña de varios patrones, consulta
[los ocho casos ficticios](ejemplos/README.md).

## Estructura

```text
kit-auditoria-claves/
├── auditor_generico.sh          script principal (menú guiado o CLI)
├── LICENSE                      Apache-2.0
├── NOTICE                       atribuciones (Apache 4d) y terceros
├── CHANGELOG.md                 registro de cambios (Keep a Changelog)
├── demo_controles.py            demo pequeña con datos ficticios
├── generar_variantes.py         variantes acotadas de semillas autorizadas
├── run_captura_wifi.sh          captura WiFi dirigida y configurable
├── run_captura_wifi_wps.sh      observación WPS y captura breve de evidencia
├── run_reaver_largo.sh          ataque WPS PIN prolongado con reintentos
├── run_mascara_larga.sh         máscaras largas (10-12) reanudables con hashcat
├── third_party/broadcom-wps/    fingerprinter WPSplinter (Quentin Kaiser, MIT)
├── extras_wifi.py               WPS PIN, PMKID, inyección deauth y escaneo WPS acotados
├── extras_mitm.py               envenenamiento ARP acotado con bettercap (red propia)
├── extras_archivos.py           ZipCrypto y permisos PDF
├── extras_web.py                login WordPress, HTTP Basic y SQLi booleana acotados
├── extras_ssh.py                intentos SSH acotados con sshpass
├── extras_ftp.py                intentos FTP acotados con ftplib
├── extras_credenciales.py       búsqueda de secretos expuestos en ficheros
├── extras_wasm.py               inventario estático de módulos WASM
├── wifi_capture_utils.py        selección de AP y filtrado WPA 22000
├── wps_capture_utils.py         extrae sólo el estado WPS del AP elegido
├── test_wifi_capture.py         pruebas con redes y hashes ficticios
├── test_wps_capture.py          pruebas de la observación WPS
├── test_extras.py               pruebas de modos extra sin radio
├── test_extras_web.py           pruebas del laboratorio web local
├── test_regresiones.py          guarda los arreglos de regresiones pasadas
├── test_kit.py                  pruebas sin credenciales reales
├── PRESENTACION.md              guion breve para el equipo
├── README.md                    este archivo
├── .gitignore                   wordlists descargadas y resultados no se versionan
├── wordlists/
│   ├── manifest.tsv             nombre, líneas, sha256, origen SecLists
│   ├── descargar_wordlists.sh   trae las listas y verifica sha256
│   └── (tus listas propias: .gitignore las excluye del repo)
├── ejemplos/                  ocho hashes MD5 y semillas ficticias generables
└── rainbowcrack/
    ├── build.sh                 compila la fuente a rainbowcrack/bin/
    ├── src/                     RainbowCrack 1.2 parcheado (g++ y openssl actuales)
    ├── disclaimer.txt           términos del autor original (Zhu Shuanglei)
    └── readme_src.txt           instrucciones de build originales
```

## Requisitos

```bash
sudo apt-get update
sudo apt-get install -y p7zip-full python3 curl tar john hashcat \
  python3-olefile libcompress-raw-lzma-perl poppler-utils \
  hcxtools aircrack-ng iw reaver sshpass build-essential libssl-dev \
  yara squashfs-tools
```

- **Motor de crackeo:** `hashcat` (GPU) y/o `john`. El script prefiere hashcat y cae a
  john automáticamente. Comprueba que tu john es la variante *jumbo* con
  `command -v zip2john`; si no lo es, instala la jumbo desde <https://www.openwall.com/john/>.
- **GPU en AMD/ROCm:** el `hashcat` de apt sólo ve el backend OpenCL de CPU
  (pocl); la GPU necesita el binario HIP 7.1.2 de <https://hashcat.net/hashcat/>
  (`.7z` → `hashcat.bin` renombrado a `hashcat`) y `LD_LIBRARY_PATH=/opt/rocm/lib`,
  que el script exporta solo. El script busca el binario GPU en
  `AUDITOR_HASHCAT` → `~/.local/share/hashcat-7.1.2/hashcat` → scratch → apt.
  Instalación única:

  ```bash
  mkdir -p ~/.local/share && cd /tmp
  curl -LO https://hashcat.net/files/hashcat-7.1.2.7z
  7z x -y hashcat-7.1.2.7z && cp hashcat-7.1.2/hashcat.bin hashcat-7.1.2/hashcat
  chmod +x hashcat-7.1.2/hashcat && mv hashcat-7.1.2 ~/.local/share/
  LD_LIBRARY_PATH=/opt/rocm/lib ~/.local/share/hashcat-7.1.2/hashcat -I | grep -i hip
  ```

  Con la GPU activa, `hashcat -b -m 0` marca `Device #01: AMD Radeon 8060S…`
  a ~9000 MH/s frente a ~2000 MH/s del CPU. El script usa `-w 4` (workload
  alto) en ataques y calibración; la calibración mide con el mismo `-w 4`
  que los trabajos, así que priorizar GPU es automático: el motor más rápido
  gana la calibración.
- **`p7zip-full`** permite verificar candidatos contra rar/zip/7z.
- **Office:** `python3-olefile` para `office2john.py`.
- **PDF 7z/LZMA:** `libcompress-raw-lzma-perl` para `7z2john.pl`.
- **WiFi:** `hcxtools` convierte `.cap/.pcap` al formato `22000` de hashcat; sin él,
  el script avisa y usa john (más lento).
- **Captura WiFi:** `aircrack-ng`, `iw`, `hcxtools` y un adaptador compatible con
  modo monitor; la captura requiere `sudo`. `--dry-run` sólo necesita Bash.
- **Otros ataques:** `wifi-evil-twin` necesita `hostapd` y `dnsmasq`
  (`sudo apt-get install -y hostapd dnsmasq`) y usa la interfaz en modo
  gestionado (corta el WiFi durante la prueba); `ble-recon` necesita `bluez`
  y un adaptador sin rfkill; `sdr-check` recomienda `rtl-sdr` sólo si detecta
  dongle; `wifi-enterprise` documenta la instalación de eaphammer sin
  automatizarla.
  instalada **para root**: `sudo python3 -m pip install --break-system-packages
  scapy` (el `--user` del usuario normal no lo ve root). La provocación
  (`wpsplinter-probar`) usa la misma dependencia. El triage de firmware
  (`firmware-yara`) necesita `yara` (`sudo apt-get install -y yara`) y, para
  imágenes squashfs, `squashfs-tools`.
- **Observación WPS:** `reaver` aporta `wash`, que lee los anuncios WPS sin probar
  PIN. El script WPS requiere además `aircrack-ng`, `iw` y modo monitor. Si `wash`
  está instalado en `~/.local/bin/wash`, el script lo encuentra también al usar
  `sudo`, aunque esa carpeta no figure en el `PATH` de root.
- **ZipCrypto:** `bkcrack` es opcional; [fuente e instalación](https://github.com/kimci86/bkcrack).
- **PDF con permisos:** `qpdf` es opcional (`sudo apt-get install qpdf`).
- **PMKID dirigido:** `hcxdumptool` y `hcxpcapngtool`; necesita una interfaz WiFi
  dedicada, ya que `hcxdumptool` cambia su modo, MAC y canal durante la captura.
- **Web y WASM:** usan Python estándar y no precisan instalar paquetes nuevos.
- **Rainbow (nivel 5):** sólo si compilas `rainbowcrack/build.sh`.

## Puesta en marcha

```bash
git clone <la-url-del-repo> kit-auditoria-claves
cd kit-auditoria-claves

wordlists/descargar_wordlists.sh          # 17 listas, con sha256
rainbowcrack/build.sh                     # opcional: tablas del nivel 5
```

Para la demo no hace falta descargar nada: `python3 demo_controles.py`.
La descarga de listas y la compilación de RainbowCrack son opcionales.
`descargar_wordlists.sh` sólo baja lo que falte; `--comprobar` revalida sha256,
`--fuerza` repite la descarga y `wordlists/descargar_wordlists.sh rockyou.txt`
baja una lista concreta. Las descargas están en `.gitignore`: cada compañero
las trae con ese comando en su copia.
Un nombre desconocido aborta toda la selección antes de descargar. El
descargador rechaza enlaces simbólicos o directorios como archivos de destino
y devuelve error si no puede guardar una lista verificada.

## Uso

Modo guiado (menú de tipo de objetivo, ruta y niveles):

```bash
./auditor_generico.sh
```

El menú padre agrupa todas las opciones en **1) Auditoría de ficheros**,
**2) Auditoría WiFi**, **3) Auditoría Web** y **4) Otros**. Cada submenú
permite volver con `0`; en el menú padre, `0` termina la sesión. Ficheros incluye
Office, hashes, ZipCrypto, permisos PDF y máscaras; Otros incluye SSH,
credenciales, WASM, MITM y utilidades (demo, variantes y tests).

Dentro de **Auditoría WiFi** hay cuatro bloques: **Tarjeta de red** (listar
interfaces, activar/desactivar modo monitor), **Escaneo de objetivos**,
**Ataque WPA** (analizar captura, captura dirigida, PMKID, desautenticación) y
**Ataque WPS** (escaneo pasivo, evidencia, PIN acotado —admite Pixie Dust—,
PIN prolongado, huella WPSplinter, provocación acotada y triage YARA de
firmware) y **Otros ataques** (WEP, WPA3-SAE, evil twin con conteo de
asociaciones, detección 802.1X, comprobación KRACK/FragAttacks del cliente,
PINes por defecto de fabricante, descubrimiento BLE y comprobación SDR; y
desde v1.5.0, **evil twin capturamanos** (`wifi-evil-capture`): clona el
ESSID *y el BSSID* del objetivo con WPA2-PSK dummy, desautentica a sus
clientes y cosecha los handshakes de reintento en un VIF monitor abierto en
el mismo phy mientras el clon emite.

**Captura → crack en el sitio:** en el menú, cuando una captura produce un
artefacto crackable (PMKID, WPA3/SAE o handshakes del evil twin capturamanos)
el auditor ofrece crackearlo al instante con el motor offline; ya no hace
falta volver a navegar hasta «Analizar captura». Por CLI el flujo sigue
siendo `--tipo wifi <archivo>` con el nivel que quieras.

El bloque **Otros ataques** cubre las familias del espectro inalámbrico que
un pentester encuentra además del WPA2/WPS doméstico. Cada una es acotada y
honesta sobre su alcance: `wifi-enterprise` y `wifi-krack` **detectan y
guían** (el ataque activo real —eaphammer, client-attack— ataca a clientes o
empieza por montar un AP propio y queda fuera del ámbito del kit);
`wifi-evil-twin` sí ejecuta: levanta un clon abierto del SSID con
hostapd+dnsmasq durante N segundos y cuenta cuántos dispositivos se asocian
sin que nadie los invite (la métrica que predice el éxito de un evil twin
KARMA). `ble-recon` y `sdr-check` cubren Bluetooth y radio definida por
software: el primero descubre dispositivos visibles; el segundo comprueba si
el hardware RTL-SDR existe antes de prometer nada. Tras cada operación se vuelve al submenú anterior, no al
menú principal.

**Objetivo en memoria.** `Escaneo de objetivos → Escanear y elegir` barre el
entorno, numera las redes por señal y deja elegido un objetivo (ESSID, BSSID,
canal) que se recuerda durante toda la sesión (y a través del fichero
`~/.local/state/kit-auditoria-claves/objetivo.env`). Cualquier prompt de
BSSID/SSID/canal acepta ese objetivo con sólo pulsar Enter, y la palabra
`escanear` en cualquier prompt de BSSID/SSID lanza el escaneo en ese momento y
devuelve al mismo punto. **El modo monitor ya no se desactiva solo** tras los
escaneos ni tras las capturas dirigidas (`--mantener-monitor`): sólo la
opción `Tarjeta de red → Desactivar modo monitor` lo quita y reconecta WiFi.
Los modos adicionales solicitan sus parámetros y proponen **plan** como acción
predeterminada, sin enviar
intentos ni capturar tráfico. Elige **prueba** para ejecutarlo con los límites
indicados. Los ejemplos de archivos y web aparecen como valores iniciales;
puedes sustituirlos por objetivos autorizados.

Por línea de comandos:

```bash
./auditor_generico.sh documento.zip                        # autodetecta
./auditor_generico.sh --nivel 1-5 --max-min 120 respaldo.7z
./auditor_generico.sh --tipo office --nivel 1-3 informe.xlsx
./auditor_generico.sh --tipo hash --modo 0 --nivel 5 hash_md5_ficticio.txt
./auditor_generico.sh --tipo wifi captura.cap
./auditor_generico.sh --motor john --dry-run objetivo.rar   # sólo plan
./auditor_generico.sh --tipo externo --externo-cmd './verificador.sh %F %P' fichero.xdf
```

**Tipos (`--tipo`):** `archivo` (rar/zip/7z/pdf/keepass, autodetecta), `office`,
`wifi`, `hash`, `externo` (formato no reconocido) y `auto` (por defecto).

**Modos cortos (`--modo`):** alias de `--tipo` para los modos de ataque:
`wps`, `wps-scan`, `pmkid`, `deauth`, `wpsplinter`, `probe`, `firmware`,
`escanear`, `ssh`, `cred`, además de los nombres largos completos. `--modo` con número sigue siendo el modo de hashcat
(`--modo 0` = MD5). `--tiempo N` es un atajo según el modo: segundos para
`pmkid` y `wps-scan`, segundos de bkcrack para `zip-conocido` y minutos
(equivalente a `--max-min`) para objetivos offline.

```bash
./auditor_generico.sh --modo pmkid --interfaz wlan0 \
  --bssid 02:11:22:33:44:55 --canal 6 --tiempo 600
./auditor_generico.sh --modo ssh --host 192.168.1.50 --usuario ana --limite-intentos 200
```

Al terminar el menú guiado, justo antes de lanzar la prueba, se imprime el
**comando equivalente con flags** para repetir la misma ejecución sin volver
a pasar por el menú.

El menú guiado no termina el script al acabar una auditoría (ni al
cancelarla ni si falla): vuelve a mostrar `=== Auditoría guiada ===` para
que elijas otra. Sólo sale de verdad al elegir **"0) Salir"** en ese menú
principal.

**Niveles (`--nivel` 1..5 o rango, por defecto `1-3`):**

| Nivel | Qué hace |
|-------|----------|
| 1 | intentos inmediatos: `stupid-ones`, `unkown-azul` y `custom.txt` si existe |
| 2 | listas comunes con reglas: `days`, `months`, `Most-Popular`, `JWT` (+best66) |
| 3 | listas grandes con reglas: Merriam-Webster SCRABBLE, SCRABBLE-large, darkc0de |
| 4 | masivas y combinaciones: Pwdb 10M, rockyou (solo y con best66), azul×días, híbrido lista propia+6 dígitos (si hay lista propia) |
| 5 | máscaras (`?d?d?d?d?d?d?d?d`, …) y rainbow tables (MD5/SHA1 sin sal) |

`--ampliar` añade métodos **offline** y acotados: PIN de 4 cifras (nivel 1),
PIN de 6 cifras, cambios de mayúsculas, año más símbolo, prefijos y sufijos de
dos cifras y unión de dos semillas (nivel 2). Usa `--wl` o `wordlists/custom.txt`
para las variantes; lee como máximo 24 semillas de 3–40 caracteres y genera
menos de 6 000 candidatos por lote. Los PIN de 6 cifras suponen hasta un millón
de intentos: revisa el plan y usa `--max-min` en formatos lentos. No se añaden
estos métodos al verificador externo.
Las variantes de texto se preparan como listas temporales privadas y se borran
al acabar, salvo con `--guardar-secretos`.

Los trabajos se ejecutan **en secuencia**. Al aparecer un candidato, se distingue
entre verificación independiente (`ok`), rechazo (`rechazado`) y coincidencia
según el motor sin verificación independiente (`motor`). Los hashes hexadecimales
MD5, SHA-1 y SHA-256 se recalculan para comprobar el candidato; para Office,
otros hashes y Wi-Fi no se afirma una verificación independiente. `7z t`
puede comprobar un documento Office normal sin comprobar ninguna clave.

Otras opciones: `--dry-run` (plan orientativo sin ejecutar motores ni crear
archivos), `--ampliar`, `--yes` (sin preguntar), `--guardar-secretos` (conserva salida sensible),
`--max-min N` (omite trabajos estimados sobre N minutos), `--sin-calibrar`
(estimaciones sin medir), `--wl lista1,lista2` (sustituye niveles 1-2),
`--formato NOMBRE` (formato john si hay duda), `--rainbow-dir DIR`.

Elección de motor y límite de recursos: `--motor auto|hashcat|john` fuerza el
motor (por defecto `auto`; `--tool` es su alias) y en el menú guiado se pregunta
igual. `--cpu N` limita los motores y su calibración a N núcleos disponibles
en la afinidad del proceso con `taskset` (por defecto
`auto` = sin límite; útil para no saturar la máquina mientras trabaja otra
cosa). `--carga 1-4` fija el nivel de carga de hashcat `-w` (por defecto 4;
bájalo a 1-2 si el escritorio se queda sin respuesta). John no tiene opción
equivalente a `-w`: para acotarlo usa `--cpu`.

Lanzadores integrados: `--modo` también lanza los scripts del kit con sus
propios argumentos: `captura`/`captura-wifi` (run_captura_wifi.sh),
`captura-wps`, `reaver-largo`, `mascara-larga`, `variantes`
(generar_variantes.py), `demo` (demo_controles.py) y `test` (los seis
módulos de unittest). Con `--dry-run` muestran el comando sin ejecutarlo.
Las capturas y WPS prolongado están en WiFi; máscaras en Ficheros; las
utilidades están en Otros. Variantes solicita semilla y directorio de salida.
El lanzador de tests funciona desde cualquier directorio.

`run_mascara_larga.sh` se distribuye con el kit. Separa las sesiones por ruta
y contenido del hash, modo, charset, carga y directorio de trabajo; los logs
y potfiles quedan privados fuera del repositorio. Repite los mismos parámetros
para reanudar. Los estados antiguos con nombres `m22000_l10` no se reutilizan
automáticamente: conserva esos archivos si necesitas recuperar un trabajo previo.

`--help` imprime toda la ayuda.
Un hash hexadecimal sin metadatos es ambiguo: para hashcat, indica siempre
`--modo` en lugar de asumir MD5 por su longitud.

### Captura WiFi dirigida

`run_captura_wifi.sh` prepara una captura de una red propia o expresamente
autorizada. También se conserva `/home/ignacia/run_captura_wifi.sh` como lanzador
de compatibilidad en esta máquina; para compartir el proyecto, usa el script del
kit. No hay SSID, BSSID, contraseña ni interfaz reales incorporados al repositorio.

```bash
# Comprueba el plan sin root, hardware ni archivos de salida.
./run_captura_wifi.sh --interfaz wlan0 --ssid 'Red de laboratorio' --dry-run

# Red elegida por SSID: escaneo pasivo, selección exacta y captura de 2 minutos.
sudo ./run_captura_wifi.sh --interfaz wlan0 --ssid 'Red de laboratorio' \
  --escaneo-seg 20 --minutos 2

# AP y canal conocidos: evita el escaneo. Acepta una interfaz ya en modo monitor.
sudo ./run_captura_wifi.sh --interfaz wlan0mon \
  --bssid 02:11:22:33:44:55 --canal 6 --minutos 2

# El mismo SSID en 2,4 y 5 GHz: el canal resuelve cuál de los AP capturar.
sudo ./run_captura_wifi.sh --interfaz wlan0 --ssid 'Red de laboratorio' \
  --canal 36 --escaneo-seg 45 --minutos 3

# Conserva sólo la captura original, sin convertirla todavía a 22000.
sudo ./run_captura_wifi.sh --interfaz wlan0 --ssid 'Red de laboratorio' \
  --canal 6 --minutos 2 --solo-captura
```

El escaneo busca la coincidencia exacta del SSID. Si varios AP anuncian el mismo
nombre (por ejemplo, en 2,4 y 5 GHz), usa `--canal` o `--bssid` para escoger uno;
no se capturan ambos canales a la vez con una sola interfaz. `--banda bg` limita
el escaneo a 2,4 GHz, `--banda a` a 5 GHz y `--banda abg` busca ambas (valor
predeterminado). Con `--canal`, el escaneo escucha sólo ese canal y `--banda` no
se utiliza. Para un BSSID y canal conocidos, se omite el escaneo. También
admite `--salida DIR`; `--help` muestra todas las opciones. Si sólo se indica
un BSSID, añade `--canal`.
La captura es pasiva por defecto: puede terminar sin un PMKID o handshake útil.
`--deauth 1` a `--deauth 3` habilita expresamente la desconexión y exige un
`--bssid` indicado por quien ejecuta el script; puede interrumpir clientes, así
que úsalo sólo cuando esa prueba esté autorizada.

Las salidas se guardan con permisos privados en
`~/capturas_wifi/<fecha>_wifi.<id>/` (o en `AUDITOR_CAPTURAS_DIR`). Si hay material
WPA del AP seleccionado, quedan `captura-01.cap` y `objetivo.22000`; el script
imprime la orden para analizar este último con `auditor_generico.sh`. La captura
predeterminada dura 10 minutos; `--minutos N` acepta de 1 a 60. `22000` es el
formato WPA de hashcat, no un tipo ni una duración de ataque. Con `--solo-captura`
se guarda únicamente el `.cap` y se pospone la conversión; al analizar ese `.cap`,
el auditor puede convertirlo a `22000` si `hcxtools` está instalado. En el auditor
elige métodos con `--nivel`, listas con `--wl` y un límite estimado por trabajo
con `--max-min`, por ejemplo:

```bash
./auditor_generico.sh --tipo wifi --motor hashcat --nivel 1-2 --max-min 5 \
  /ruta/a/objetivo.22000
```

La captura puede contener identificadores de dispositivos y tráfico de terceros: revisa y
elimina esos archivos antes de compartir el proyecto o la presentación.
La pantalla dinámica de `airodump-ng` se descarta: no se crean `scan.log` ni
`captura.log`, que podían crecer sin límite. El archivo `.cap` sí puede ocupar
espacio según el tráfico observado; comprueba el espacio libre antes de capturar.
`.gitignore` excluye capturas y hashes. El script sólo detiene la interfaz monitor
que crea, sin reiniciar NetworkManager.

### WPS PIN: exposición y evidencia

El PIN de **Wi-Fi Protected Setup (WPS)** es un mecanismo de registro distinto de
la contraseña WPA/WPA2 y de los hashes `22000`. [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755/)
documentó que la comprobación del PIN por mitades reduce el espacio efectivo de
búsqueda a unas 11 000 pruebas y que la ausencia de bloqueo tras fallos en
algunos routers hizo viable el abuso. Un AP que anuncia WPS no demuestra por sí
solo que su método PIN esté habilitado ni que permita intentos sin límite.

`run_captura_wifi_wps.sh` observa pasivamente, mediante
**Pixie Dust (`--pixie`)**: en lugar de probar PINs, Reaver captura los nonces
del enrollee y los crackea offline — es instantáneo si el AP es vulnerable a
Pixie y no gasta cuota de intentos. Se activa con `--pixie` en `wifi-wps-pin`
o desde el menú WPS (opción 3, pregunta `s/N`).

[`wash`](https://github.com/t6x/reaver-wps-fork-t6x/blob/master/docs/README.WASH), **un BSSID y canal
concretos**. Si se observa WPS, guarda una captura corta de ese AP con
`airodump-ng`; el resultado incluye la versión y el estado de bloqueo anunciados
por el AP y comprueba si el anuncio también aparece en el `.cap`. No envía PIN,
no intenta registrarse, no recupera la clave WPA y no
declara el AP vulnerable a partir del anuncio. Si no se observa WPS en la ventana,
el resultado es inconcluyente. Consulta además la configuración del router para
confirmar si WPS PIN está activo; desactivar WPS es la mitigación indicada por
[CERT/CC](https://www.kb.cert.org/vuls/id/723755/).

```bash
# Usa el BSSID y canal de un AP propio o autorizado; no incorpores datos reales al repo.
./run_captura_wifi_wps.sh --interfaz wlan0 --bssid 02:11:22:33:44:55 \
  --canal 6 --dry-run
sudo ./run_captura_wifi_wps.sh --interfaz wlan0 --bssid 02:11:22:33:44:55 \
  --canal 6 --observar-seg 20 --captura-seg 15
```

Con un SSID presente en 2,4 y 5 GHz, ejecuta cada BSSID/canal por separado. El
script crea una carpeta privada en `~/capturas_wifi/` y conserva el estado
del AP elegido y, si hay WPS anunciado, `wps_evidencia-01.cap`; si tuvo que
activar el modo monitor, también puede quedar `monitor.log`. La captura puede
incluir tramas de otros dispositivos: revísala antes de compartirla. La salida
de pantalla de `wash` y `airodump-ng` no se guarda en logs crecientes.

### Formatos no reconocidos (`.xdf`, firmas propias…)

El tipo `externo` necesita un verificador: una orden que reciba el candidato
por `%P` y opcionalmente el fichero por `%F`, como **argumentos independientes**,
y termine con código 0 sólo si es
correcto. La orden admite comillas, pero no tuberías, variables, redirecciones
ni expansión de comandos. El tiempo del plan usa una estimación aproximada;
no se hacen llamadas de calibración al verificador.

```bash
./auditor_generico.sh --tipo externo --externo-cmd '/ruta/verificar.sh %F %P' fichero.xdf
```

Si no existe verificador, ese objetivo no se puede auditar con el kit.

## Resultados

Cada ejecución crea `~/auditoria_logs/<fecha>_objetivo_<id>.XXXXXX/`. Por
defecto queda únicamente `resultado.txt`, con ID aleatorio, tipo,
fase general y estado de verificación. No guarda la ruta ni el candidato.
El directorio se crea privado (`umask 077`).

Con `--guardar-secretos` se conservan, sólo localmente:

- `password.txt` — la contraseña encontrada
- `resultado.txt` — fecha, objetivo, tipo, motor, modo, fase, candidato y verificación
- `hashcat.pot` / `john.pot` — potfiles de los motores
- `*.log` — log de cada trabajo del plan
- `extra_*.txt` — variantes generadas, si se usó `--ampliar`

Queda fuera del repositorio (ver `.gitignore`): **no subas nunca** esos directorios.
Incluso en el modo predeterminado, el proceso maneja candidatos y potfiles
temporalmente. Revisa los metadatos antes de compartir un informe.

## Variables de entorno

| Variable | Efecto |
|----------|--------|
| `AUDITOR_WORDLISTS` | directorio de wordlists (por defecto `./wordlists`) |
| `AUDITOR_HASHCAT` / `AUDITOR_JOHN` | rutas a los motores |
| `AUDITOR_RULES` | directorio de reglas hashcat |
| `AUDITOR_RAINBOW` / `AUDITOR_RAINBOW_TABLES` | binarios `rcrack` y tablas `.rt` |
| `AUDITORIA_DIR` | dónde se guardan los resultados |
| `AUDITOR_PERL5LIB` | ruta extra por si falta `Compress::Raw::Lzma` |
| `SECLISTS_RAW` | base raw alternativa para `descargar_wordlists.sh` |

También se acepta el nombre antiguo `RC_TABLAS` para las tablas.

## Auditorías adicionales

Todos los modos siguientes se invocan desde `auditor_generico.sh`. La ruta
`/home/ignacia/auditor_generico.sh` es un enlace al mismo archivo. Cada prueba
recibe su objetivo por parámetro: el repositorio no contiene URL, cuentas,
BSSID ni contraseñas reales. `--dry-run` valida el plan sin conectarse al objetivo.

| Modo | Prueba | Alcance del resultado |
|------|--------|-----------------------|
| `wifi-wps-pin` | `wash` pasivo y hasta 50 intentos con Reaver | Detecta bloqueo o registro WPS; pocos intentos inconclusos no prueban seguridad |
| `wifi-pmkid` | captura dirigida con `hcxdumptool` y filtro PMKID | sólo algunos AP entregan PMKID; el análisis posterior usa formato `22000` |
| `wifi-deauth` | `aireplay-ng -0` dirigido al BSSID (y cliente opcional) | desconecta a los clientes para forzar el 4-way handshake; interrumpe el servicio unos segundos |
| `wifi-wps-scan` | `wash -a -j` pasivo 10–1200 s | lista APs con WPS, si anuncian bloqueo y fabricante/modelo (vía WPS o MAC); pasivo, no envía paquetes |
| `wifi-monitor` | `airmon-ng` (o `ip`/`iw` si no está) sobre una interfaz propia | activa/desactiva modo monitor; `--listar` muestra interfaces y cuál es la de la ruta por defecto; niega activar sobre ésta salvo `--forzar`; al desactivar resucita NetworkManager y reconecta |
| `wifi-escanear` | `airodump-ng` 5–1200 s y lista numerada por señal | deja el modo monitor activo y el objetivo (ESSID/BSSID/canal) en memoria; el menú lo reutiliza en todos los prompts |
| `wifi-wpsplinter` | fingerprinter EAP de `third_party/broadcom-wps` (scapy) | clasifica el reensamblador WPS del AP (LIKELY_VULNERABLE/NOT/INCONCLUSIVE) sin explotarlo; requiere root, monitor y scapy |
| `wpsplinter-probar` | fragmentos de continuación que desbordan el reensamblador (1-5 golpes) | provocación genérica con riesgo real de DoS; clasifica HEALTHY/WPS_SILENT/SIN_BALIZAS tras cada golpe |
| `firmware-yara` | reglas Kaiser sobre el firmware del router (extrae zip/7z/squashfs) | triage estático por modelo/proveedor; la regla VULN_ apunta a la ruta vulnerable; no prueba ausencia |
| `wifi-wep` | captura de IVs (airodump) + crack (aircrack-ng -a 1) | red legada WEP; informe completo en el directorio de capturas |
| `wifi-wpa3` | hcxdumptool captura SAE/EAPOL + hcxpcapngtool | produce `.22000` listo para el flujo `--tipo wifi`; informa si vio SAE |
| `wifi-evil-twin` | clon abierto con hostapd+dnsmasq en la interfaz gestionada | cuenta qué dispositivos se asocian solos (exposición KARMA/evil twin); corta el WiFi de la máquina durante la prueba |
| `wifi-evil-capture` | clona ESSID+**BSSID** con WPA2-PSK dummy, deauth con aireplay y captura en un VIF monitor simultáneo | cosecha los handshakes de reintento de los clientes → `.22000`; al terminar ofrece crackear en el sitio |
| `wifi-enterprise` | barrido airodump filtrando AUTH=MGT | detecta APs 802.1X y guía el ataque eaphammer (hashcat -m 5500); no lo automatiza |
| `wifi-krack` | versiones locales de wpa_supplicant/hostapd vs 2.7 | comprobación pasiva lado cliente de KRACK/FragAttacks; la prueba activa ataca clientes y es fuera de ámbito |
| `wps-pins` | diccionario `wordlists/wps_pins_fabricante.txt` con Reaver | PINes por defecto de fabricante, acotado por `--limite-intentos` |
| `ble-recon` | bluetoothctl scan acotado | descubrimiento BLE/BR-EDR (wearables, cerraduras, sensores) |
| `sdr-check` | lsusb RTL2832U + rtl_test | comprueba hardware/herramientas SDR; sin dongle la familia no aplica |
| `mitm-arp` | envenenamiento ARP con `bettercap` (10–3600 s) | redirige el tráfico del objetivo por esta máquina; interrumpe la LAN y es visible para sus usuarios |
| `ssh-brute` | hasta 200 intentos de contraseña SSH con `sshpass` | un intento por candidato, `NumberOfPasswordPrompts=1`; se detiene si el servidor limita |
| `ftp-brute` | hasta 200 intentos de contraseña FTP con `ftplib` | un intento por candidato; para ante 421 o error de conexión |
| `cred-scan` | patrones de secretos en ficheros de texto | salida enmascarada; `--generar` guarda candidatos para otras auditorías; detecta `github_pat_`, `glpat-`, `npm_`, `dckr_pat_` |
| `zip-conocido` | texto conocido contra ZipCrypto | no afecta a ZIP con AES |
| `pdf-permisos` | apertura de PDF con restricciones de copia | no elude una contraseña necesaria para abrir el PDF |
| `web-login` | hasta 50 intentos de login tipo WordPress | no guarda ni imprime candidatos; se detiene ante HTTP 403/429 |
| `web-basic` | hasta 200 intentos contra HTTP Basic | 401/403/407 cuentan como fallo; cualquier otro estado se confirma como acceso |
| `web-sqli` | tres consultas booleanas a un parámetro GET | evidencia diferencial, sujeta a revisión manual; no extrae datos |
| `wasm` | imports y exports de un módulo binario | inventario estático, no prueba explotación |

### Cuatro pruebas WiFi

```bash
./auditor_generico.sh --tipo wifi-wps-pin --interfaz wlan0mon \
  --bssid 02:11:22:33:44:55 --canal 6 --limite-intentos 3 --dry-run
sudo ./auditor_generico.sh --tipo wifi-wps-pin --interfaz wlan0mon \
  --bssid 02:11:22:33:44:55 --canal 6 --limite-intentos 3

./auditor_generico.sh --tipo wifi-pmkid --interfaz wlan0 \
  --bssid 02:11:22:33:44:55 --canal 6 --segundos 20 --dry-run
sudo ./auditor_generico.sh --tipo wifi-pmkid --interfaz wlan0 \
  --bssid 02:11:22:33:44:55 --canal 6 --segundos 20

./auditor_generico.sh --tipo wifi-deauth --interfaz wlan0mon \
  --bssid 02:11:22:33:44:55 --golpes 10 --dry-run
sudo ./auditor_generico.sh --tipo wifi-deauth --interfaz wlan0mon \
  --bssid 02:11:22:33:44:55 --cliente 02:AA:BB:CC:DD:EE --golpes 10

./auditor_generico.sh --tipo wifi-wps-scan --interfaz wlan0mon --dry-run
sudo ./auditor_generico.sh --tipo wifi-wps-scan --interfaz wlan0mon --canal 6 --segundos 30

./auditor_generico.sh --tipo wifi-monitor --listar
sudo ./auditor_generico.sh --tipo wifi-monitor --interfaz wlan0 --accion activar --dry-run
sudo ./auditor_generico.sh --tipo wifi-monitor --interfaz wlan0 --accion activar
sudo ./auditor_generico.sh --tipo wifi-monitor --interfaz wlan0 --accion desactivar
```

`wifi-monitor` activa o desactiva modo monitor en una interfaz WiFi propia
(`ip link set ... down`, `iw dev ... set type monitor|managed`, `ip link set
... up`); requiere los paquetes `iw` e `iproute2`. `--listar` muestra todas
las interfaces WiFi detectadas, su modo (si `iw` está instalado) y marca cuál
es la interfaz de la ruta por defecto. Activar modo monitor sobre esa
interfaz desconecta la máquina de la red (y de una sesión SSH que pase por
ahí), así que el modo se niega a hacerlo salvo que añadas `--forzar`;
desactivarla no requiere esa confirmación. Al desactivar, intenta reconectar
con `nmcli device connect` si NetworkManager está disponible; si no, puede
que tengas que reconectar manualmente.

`wifi-deauth` envía de 1 a 200 desautenticaciones (`aireplay-ng -0 N -a BSSID
[-c CLIENTE]`) a un único AP autorizado: desconecta temporalmente a los
clientes legítimos y los obliga a rehacer el 4-way handshake, que capturas
mientras con `airodump-ng` o `hcxdumptool`. Si el kernel rechaza los paquetes
("send failed"), la interfaz no está realmente en modo monitor con inyección.
`wifi-wps-scan` es pasivo: marca cada AP como `sin bloqueo anunciado` (WPS sin bloqueo
anunciado) o `bloqueado`, y sugiere el comando `wifi-wps-pin` para los
candidatos. Además añade, cuando está disponible, el fabricante y modelo que
el propio router difunde en el elemento de información WPS (campos
`wps_manufacturer`/`wps_model_name`/`wps_model_number` del volcado `-j` de
`wash`); si el AP no los anuncia, estima el fabricante del chip de red por el
OUI de la MAC (vía la base local `ieee-data`, sin salir a internet) y lo
marca como estimado, no como modelo exacto. Si ese fabricante coincide con la
lista pública de marcas citadas en el aviso de
["WPSplinter"](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/)
(un desbordamiento en el reensamblado EAP de WPS del stack Broadcom, sin CVE
asignado y sin PoC público), el escaneo lo señala como aviso informativo:
no comprueba ni explota ese fallo, sólo recomienda desactivar WPS si no lo
usas y preguntar al operador por firmware corregido.

El primer modo exige una interfaz **ya en modo monitor**; observa WPS antes de
probar el PIN y no ignora un bloqueo anunciado. La prueba es online y puede
afectar al AP. El segundo usa la interfaz WiFi directamente, aplica un filtro
por BSSID, guarda un `.pcapng` privado y entrega sólo PMKID de ese AP en
`pmkid_objetivo.22000`; indica `--banda 2g|5g` si el canal lo requiere.
El proceso limita la captura a 32 MiB y suprime la salida de pantalla para
evitar logs grandes; si alcanza el límite, puede terminar sin PMKID.
No uses ambos modos sobre la interfaz que sostiene tu conexión de trabajo.
La vulnerabilidad de WPS PIN y la importancia del bloqueo están descritas por
[CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755/).

### Si wash no ve ningún AP: fixes según la tarjeta

Síntoma: `wash` (en vivo o vía `wps-scan`) responde "Sin APs con WPS
observados" mientras `airodump-ng` lista perfectamente las redes. No es que
no haya WPS: es que wash no recibe los beacons. Compruébalo siempre antes de
concluir:

```bash
sudo airodump-ng wlp195s0mon   # si ve APs y wash no, el problema es de wash
```

Fixes en orden, del más genérico al específico:

1. **Análisis offline (método que usa ya `wps-scan` por defecto).** Captura
   con airodump-ng y analiza el pcap con wash:
   ```bash
   sudo timeout 60 airodump-ng --band bg -w /tmp/wps --output-format pcap wlan0mon
   sudo wash -f /tmp/wps-01.cap -a
   ```
   Funciona con cualquier chip cuya interfaz monitor capture beacons, porque
   wash lee el fichero en vez del driver.
2. **Desactivar el filtrado de hardware de beacons/probes.** Algunos drivers
   entregan a los sockets raw sólo los frames "completos" que ellos mismos
   procesan. Prueba a recargar el módulo con opciones de monitor:
   ```bash
   sudo modprobe -r <modulo> && sudo modprobe <modulo>    # reset limpio
   ```
   y en ath9k/ath10k: `echo 1 | sudo tee /sys/kernel/debug/ieee80211/phy0/ath/...`
   según la documentación del driver.
3. **Interferencia del gestor de red.** `airmon-ng check kill` antes de crear
   el monitor; un NetworkManager activo puede "comerse" frames de gestión.
4. **Canal fijo.** Si el barrido no funciona, fija el canal del AP objetivo
   (`wash -c N`, `airodump-ng -c N`); algunos chips fallan sólo al saltar
   canales.
5. **Wash demasiado viejo para el chip.** Wash 1.6 (2011) usa libpcap sobre
   inyección clásica; para chips WiFi 6/7 (mt7925, BE200…) puede no haber
   soporte directo. Alternativas: `bully` (lee pcap igual que wash) o el
   análisis offline del punto 1.

**Caso concreto probado (MediaTek MT7925 / interfaz `wlp195s0`, kernel 6.x,
driver `mt7925e`):** wash en vivo no ve ningún beacon ni en modo survey ni en
scan, con o sin NetworkManager, con o sin canal fijo — el driver mt76 no
entrega los beacons al socket de wash. El análisis offline (punto 1) sí
funciona: la captura de airodump-ng analizada con `wash -f` detectó los 7 APs
con WPS de la zona. Por eso `wps-scan` captura con airodump-ng y analiza con
`wash -f` cuando `airodump-ng` está disponible, y sólo usa wash en vivo como
último recurso.

**Otros dos fallos confirmados del mismo driver (mt7925), con su workaround:**

- `aireplay-ng --deauth` aborta con «Couldn't determine current channel …
  channel -1». El driver reporta el canal como -1 en el ioctl; hay que pasar
  `--ignore-negative-one` (ya incorporado en `run_captura_wifi.sh` y
  `wifi-deauth`). Sin ese flag la inyección no se lanza y la captura queda
  pasiva.
- `bully` no funciona en absoluto: aborta con «ioctl(SIOCSIWFREQ) failed
  with '-1' … Unable to set channel» incluso fijando el canal antes con
  `iw dev <iface> set channel N`. No hay flag que evite ese ioctl. En este
  chip, para WPS PIN sólo queda Reaver (que sí funciona, aunque el beacon
  tarde minutos en aparecer) o wash offline para el escaneo.

Para crackear el material capturado: `hashcat` no está instalado en esta
máquina y este build de John (jumbo bleeding) no carga los hashes `.22000`
de hcxtools («No password hashes loaded»). `aircrack-ng -w lista.cap` sí
funciona y rinde ~65 000 contraseñas/s con el handshake completo.

### Cuántos intentos PIN hacen falta (Reaver)

El PIN WPS son 8 dígitos, pero el protocolo lo divide en dos mitades con
checksum: el espacio efectivo de búsqueda es 10⁴ + 10³ = **11 000 pruebas** (10 000 de la primera
mitad + 1 000 de la segunda por cada mitad acertada). De ahí:

| Escenario | Cálculo | Tiempo |
|-----------|---------|--------|
| Mejor caso | 1 PIN | segundos |
| Media (50%) | ~5 500 PINs | con 1 s de retardo ≈ 1,5 h |
| Peor caso | 11 000 PINs | con 1 s de retardo ≈ 3 h |
| Con retardo 15 s (común en routers con limitación) | media ~5 500 | **≈ 23 h** |
| Con bloqueo cada N intentos (lock-delay 5-10 min) | — | días |

Por eso `--limite-intentos` con 3, 5 o incluso 50 intentos casi nunca saca el
PIN completo: sirve para comprobar que el AP responde a WPS, no para crackear.
Un ataque real necesita miles de intentos encadenados, y ahí entra el
script prolongado:

```bash
sudo ./run_reaver_largo.sh --interfaz wlan0mon \
  --bssid AA:BB:CC:DD:EE:FF --canal 1 \
  --intentos-ronda 10 --retardo 15 --espera-bloqueo 900 --rondas-max 24
```

Encadena rondas de `--intentos-ronda` PINs; si el AP anuncia bloqueo espera
`--espera-bloqueo` segundos y reintenta; si la ronda termina sin nada,
encadena otra. Guarda el progreso como `<BSSID>.wps` en el directorio de
salida (0700) y lo reanuda solo, así que Ctrl-C o un apagón no pierden lo
ya probado. Para al encontrar el PIN, al alcanzar `--rondas-max`, o con
Ctrl-C. El PIN y la PSK quedan en los logs: trátalos como secretos.

**Comportamiento observado en routers Movistar (Broadcom).** Algunos APs no
anuncian el bloqueo en los beacons pero lo aplican en la práctica: Reaver
asocia, envía EAPOL-START e identidad WPS, y el router responde con un
deauth repetido (`[+] Received deauth request` en bucle) sin dejar avanzar
la transacción PIN. El `wash` del escaneo pasivo marca esos APs como
`sin bloqueo anunciado` porque el beacon no dice lo contrario: el bloqueo real sólo se
descubre al intentar el PIN. El script prolongado lo tolera (reintenta tras
la espera), pero si el bucle de deauth persiste ronda tras ronda, el AP está
efectivamente cerrado al método PIN y conviene pasar a PMKID/handshake.


### WPSplinter: huella del monitor WPS de Broadcom (wifi-wpsplinter)

Aviso publicado por Quentin Kaiser el 16-10-2026
(*one parser, two bugs*): el reensamblador de fragmentos EAP del **WPS
Monitor del firmware Broadcom** tiene un desbordamiento alcanzable por un
atacante **sin clave** (ni siquiera hace falta WPS activado con PIN: basta
que el AP anuncie WPS en las balizas). Afecta a un buen puñado de routers de
operador —entre ellos los **Huawei Wi-Fi 6 de Movistar/MiFibra** con chip
Broadcom— y puede acabar en ejecución remota de código en el AP. No hay CVE
asignada todavía y el parche depende del fabricante.

El kit integra el *fingerprinter* oficial del autor (`third_party/broadcom-wps`,
MIT): envía EAP fragmentados benignos y clasifica el reensamblador del AP.
**No explota nada ni tumba el router**: es una prueba de exposición acotada.

```bash
# plan sin permisos
./auditor_generico.sh --modo wpsplinter --interfaz wlan0mon --ssid MiRed --dry-run
# huella real (root, interfaz en modo monitor, librería scapy)
sudo ./auditor_generico.sh --modo wpsplinter --interfaz wlan0mon --ssid MiRed
```

Requisitos: `scapy` instalada **para root** (`sudo python3 -m pip install
--break-system-packages scapy`; ojo: el `--user` de tu usuario no lo ve
root) y la interfaz en modo monitor. Las evidencias (pcap completo +
`result.json`) se guardan en `~/capturas_wifi/wpsplinter/`. Veredictos:
`LIKELY_VULNERABLE` (reensamblador tipo Broadcom), `LIKELY_NOT_VULNERABLE`
(comportamiento hostapd) o `INCONCLUSIVE`. El escaneo pasivo `wifi-wps-scan`
ya avisaba por OUI cuando el fabricante figuraba en la lista pública; esta
prueba es la comprobación activa.

#### Provocación acotada (`wpsplinter-probar`, alias `--modo probe`)

El fingerprinter se detiene en el primer fragmento: por eso es inofensivo. El
paso siguiente, genérico para cualquier AP `LIKELY_VULNERABLE` de la familia,
es **continuar** los fragmentos EAP: el reensamblador vulnerable copia más
allá de su búfer (la primitiva "arbitrary write by controlling
`total_received`" de las diapositivas de Hexacon 2026 del propio Kaiser). Sin
calibrar por firmware, el resultado esperable es **DoS del WPS Monitor o
reinicio del AP**, no RCE: la ejecución arbitraria necesita offsets por
modelo (en ARM Linux, `system@PLT` fijo → `send_data` → `system($a0)`; en
eCos, leak previo + hijack de `send_data`).

```bash
# plan sin permisos
./auditor_generico.sh --modo probe --interfaz wlan0mon --ssid MiRed --dry-run
# 2 golpes × 12 fragmentos, salud del AP comprobada tras 25 s (RIESGO DoS)
sudo ./auditor_generico.sh --modo probe --interfaz wlan0mon --ssid MiRed
```

Cada golpe termina solo y clasifica al AP: `HEALTHY` (sobrevive),
`WPS_SILENT` (balizas OK pero dejó de anunciar WPS: el monitor WPS cayó) o
`SIN_BALIZAS` (reinicio/caída; espera 1-2 min). Evidencias pcap+JSON junto al
fingerprinter. Asume el riesgo: en red propia está justificado; en ajena, no.

Prueba real (oct-2026, MiFibra-casa): los 12 fragmentos de continuación del
primer golpe fueron **aceptados** por el reensamblador y el AP quedó
`HEALTHY`; en el segundo golpe la entrada WPS agotó el tiempo de espera
(el monitor WPS aún se recuperaba del golpe 1) y volvió a anunciar WPS poco
después. Conclusión honesta: la secuencia genérica llega al parser vulnerable
pero tumbarlo o ejecutar código exige la calibración por firmware que Kaiser
no ha publicado; el pcap del probe queda como evidencia para afinar offsets.

#### Triage YARA de firmware (`firmware-yara`, alias `--modo firmware`)

Genérico por modelo y proveedor: descarga el firmware del sitio de soporte de
tu operadora (Orange, Movistar, Vodafone, Proximus…) y aplica las reglas
`third_party/broadcom-wps/broadcom_wps_monitor.yar` (Kaiser, MIT) buscando el
WPS Monitor de Broadcom en ELF32 ARM/MIPS; `VULN_BRCM_WPS_EAP_Fragment_Reassembly_ELF`
apunta a la ruta de reensamblado vulnerable.

```bash
./auditor_generico.sh --modo firmware ./firmware_router.bin --extraer --dry-run
./auditor_generico.sh --modo firmware ./firmware.zip --url https://… --extraer
```

Desenvuelve zip/7z/tar/gz/squashfs (necesita `yara` y, para squashfs,
`squashfs-tools`) y escanea también en crudo si no hay contenedores. Son
reglas de triage: un firmware parcheado puede conservar las cuerdas; la
confirmación en aire es `wifi-wpsplinter`.

Resultado en redes propias (oct-2026): **MiFibra-casa (Arcadyan, canal 1) →
`LIKELY_VULNERABLE`**, con `implementation: BROADCOM_WPS_MONITOR` y evidencia
`broadcom_proprietary_ie` en el `result.json`; el router quedó `HEALTHY` (la
prueba no lo tumbó). En **MiFibra-7330 (Sagemcom Fast5656)** el AP rechazó la
asociación del fingerprinter (status 802.11 19, "medium access capabilities")
en los tres intentos → `INCONCLUSIVE`: algunos firmwares no aceptan la
asociación mínima que usa la herramienta; no significa que el AP esté
parcheado, sólo que no se le pudo interrogar. El `claim_boundary` del propio
informe lo deja claro: es una huella de familia de implementación, no una
verificación de explotación.

### Man in the middle (mitm-arp)

```bash
# plan sin permisos ni paquetes
./auditor_generico.sh --modo mitm --interfaz wlan0 --objetivo 192.168.1.10 --dry-run
# prueba real en red propia (30 s de envenenamiento)
sudo ./auditor_generico.sh --modo mitm --interfaz wlan0 \
  --objetivo 192.168.1.10 --gateway 192.168.1.1 --tiempo 30
```

El modo usa `bettercap` (arp-spoofing bidireccional, `arp.spoof.fullduplex`)
durante un tiempo acotado (10–3600 s) y restaura `ip_forward` al terminar,
pase lo que pase. Sin `--objetivo` envenena a toda la LAN; con
`--sin-gateway` (`arp.spoof.only`) sólo enreda entre objetivos sin tocar la
salida a Internet. El gateway se autodetecta desde la tabla de enrutado si no
se indica.

Qué demuestra y qué no: el tráfico del objetivo pasa por esta máquina, lo que
habilita el sniff de protocolos en claro (HTTP, DNS, ARP) y ataques de
proxy/sslstrip en la misma sesión de bettercap. Con HTTPS bien configurado
sólo se ven metadatos (SNI, dominios); un certificado desconocido lo detecta
cualquier navegador moderno. Es una prueba de exposición, no de compromiso.

Legalidad: el envenenamiento ARP envía ARP replies falsos a equipos de tu
LAN. En red propia está claro; en redes ajenas interceptar tráfico ajeno sin
autorización toca el art. 197 CP (secreto de las comunicaciones) además de la
LSSI. Bettercap 2.x usa `-iface`/`-silent` (no `-I`/`--no-ui` de la 1.x).

### SSH, FTP y credenciales

```bash
./auditor_generico.sh --tipo ssh-brute --host 192.168.1.50 --usuario ana \
  --wl ejemplos/candidatos_web_ficticios.txt --limite-intentos 3 --dry-run
./auditor_generico.sh --tipo ftp-brute --host 192.168.1.50 --usuario ftp \
  --wl ejemplos/candidatos_web_ficticios.txt --limite-intentos 3 --dry-run
./auditor_generico.sh --tipo cred-scan ~/proyecto --generar /tmp/candidatos.txt
```

`ssh-brute` usa `sshpass` con una sola pregunta de contraseña por candidato
(`NumberOfPasswordPrompts=1`), acepta la host key la primera vez y se detiene
si el servidor empieza a limitar. Requiere autorización sobre el destino: los
intentos quedan en el `auth.log` del servidor. `ftp-brute` hace lo propio con
`ftplib` (sin dependencias externas): un intento por candidato, sin imprimir
ni guardar contraseñas, y para ante una respuesta 421 o un corte de conexión
para no castigar al servidor. Anónimos: `anonymous` es el usuario por defecto
del menú. `cred-scan` busca claves
privadas, tokens y parámetros `password=` en ficheros de texto de hasta 2 MB
(excluye `.git`, `node_modules`…); imprime los valores enmascarados y
`--generar` escribe las contraseñas candidatas para reutilizarlas con
`ssh-brute`, `web-login` o el crackeo offline.
El escaneo omite enlaces simbólicos y rechaza un enlace como objetivo principal.
La lista exportada usa un temporal exclusivo y permisos `0600`.
El recorrido se detiene al alcanzar el máximo de hallazgos sin acumular todas
las rutas en memoria. Los secretos de hasta cuatro caracteres se ocultan
completamente; los controles de terminal se muestran escapados.
En SSH, un corte de conexión o límite de autenticación devuelve código 3
(inconcluyente), incluso después de haber enviado algún intento.

### Dos pruebas de archivos

`python3 ejemplos/crear_extras.py` regenera un ZIP ZipCrypto de unos cientos de
bytes y un PDF restringido de unos 1,4 KB. Todos los contenidos y las claves de
generación son ficticios. Requiere `7z` y `qpdf` para crear ambos; `--salida DIR`
permite crear otros ejemplos fuera del repositorio.

```bash
./auditor_generico.sh --tipo zip-conocido ejemplos/extras/zipcrypto_demo.zip \
  --entrada texto_conocido.txt --plano ejemplos/extras/texto_conocido.txt --max-seg 120
./auditor_generico.sh --tipo pdf-permisos ejemplos/extras/pdf_restringido_demo.pdf
```

El primer caso usa [bkcrack](https://github.com/kimci86/bkcrack) y muestra que
un ZIP con cifrado heredado puede ceder ante texto conocido sin adivinar la
contraseña. El segundo ilustra que las restricciones del propietario de un PDF
dependen del lector y no equivalen a una contraseña de apertura; consulta la
[documentación de qpdf](https://github.com/qpdf/qpdf/blob/main/manual/encryption.rst).

### Tres pruebas web

Para mostrar ambos casos sin cuentas ni sitios ajenos, arranca el laboratorio
ficticio en una terminal: `python3 ejemplos/web_lab.py`. Sólo escucha en
`127.0.0.1:8769`. En otra terminal:

```bash
./auditor_generico.sh --tipo web-login \
  --url http://127.0.0.1:8769/wp-login.php --usuario demo \
  --wl ejemplos/candidatos_web_ficticios.txt --limite-intentos 3
./auditor_generico.sh --tipo web-sqli \
  --url http://127.0.0.1:8769/buscar-vulnerable --param q \
  --valor libro_ficticio --indicador RESULTADO_FICTICIO
./auditor_generico.sh --tipo web-sqli \
  --url http://127.0.0.1:8769/buscar-seguro --param q \
  --valor libro_ficticio --indicador RESULTADO_FICTICIO
./auditor_generico.sh --tipo web-basic \
  --url https://tu-sitio-autorizado/admin --usuario admin \
  --wl ejemplos/candidatos_web_ficticios.txt --limite-intentos 3
```

Para un WordPress propio, sustituye URL, usuario y `--wl` por los autorizados.
El modo web exige HTTPS fuera de localhost, no sigue redirecciones y limita los
intentos a 1–50 (1–200 en `web-basic`), con una pausa entre ellos. Aunque la lista sea grande, sólo
prueba sus primeros candidatos válidos hasta alcanzar ese límite. En el menú
se acepta `~/` en rutas de archivos y, al usar `sudo`, se resuelve al directorio
del usuario que lo invocó. Las pruebas web no necesitan `sudo`.
El listado incluido sólo tiene tres
candidatos ficticios; no contiene credenciales filtradas ni puede garantizar
encontrar una contraseña real. Un HTTP 200 tras varios fallos tampoco prueba
que el sitio carezca de protección. Consulta las guías de
[WordPress sobre fuerza bruta](https://developer.wordpress.org/advanced-administration/security/brute-force/)
y [OWASP sobre SQLi](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection/).

### Chequeo WASM

```bash
./auditor_generico.sh --tipo wasm ejemplos/extras/modulo_ficticio.wasm
```

`python3 ejemplos/crear_wasm.py` regenera el módulo ficticio de 44 bytes. El
chequeo no lo ejecuta: enumera funciones importadas y memoria exportada para
revisar los permisos que el entorno le concede. El aislamiento y la interacción
con el host se explican en la [guía de seguridad de WebAssembly](https://webassembly.org/docs/security/).
El inventario limita el archivo a 8 MiB y las lecturas al contenido de cada
sección. Rechaza datos de inventario truncados o malformados; no sustituye
la validación completa de un módulo por un motor WebAssembly.

## Wordlists

No se versiona ninguna lista `.txt`: las diecisiete de abajo se traen con
`descargar_wordlists.sh` y quedan bajo `wordlists/` (excluidas por `.gitignore`).
Si tenéis listas propias del equipo, seleccionadlas con `--wl`. El nombre
`custom.txt` se usa automáticamente en el nivel 1 si existe. No copies ni
compartas listas que contengan credenciales reales. Origen y `sha256` de las
descargas en `manifest.tsv`, desde
[SecLists](https://github.com/danielmiessler/SecLists):

| archivo | líneas | origen |
|---------|-------:|--------|
| stupid-ones-in-production.txt | 4 | `Passwords/` |
| unkown-azul.txt | 3.629 | `Passwords/` |
| days.txt | 6.240 | `Passwords/` |
| months.txt | 13.431 | `Passwords/` |
| Most-Popular-Letter-Passes.txt | 47.603 | `Passwords/` |
| scraped-JWT-secrets.txt | 103.979 | `Passwords/` |
| Merriam-Webster-SCRABBLE-4thEdition.txt | 45.949 | `Passwords/SCRABBLE-hackerhouse.tgz` |
| SCRABBLE-large.txt | 589.940 | `Passwords/SCRABBLE-hackerhouse.tgz` |
| SCRABBLE-munged-large.txt | 597.337 | `Passwords/SCRABBLE-hackerhouse.tgz` |
| darkc0de.txt | 1.471.056 | `Passwords/` |
| Pwdb_top-10000000.txt | 10.000.000 | `Passwords/Common-Credentials/` |
| rockyou.txt | 14.344.391 | `Passwords/Leaked-Databases/rockyou.txt.tar.gz` |
| Spanish_Pwdb_top-150.txt | 150 | `Passwords/Common-Credentials/Language-Specific/` |
| lang-spanish.txt | 441 | `Miscellaneous/` |
| moby-spanish.txt | 86.058 | `Miscellaneous/Words/Moby-Project/Moby-Language-II/` |
| RAE_spanish_105582_words.txt | 105.582 | `Miscellaneous/Words/` |
| Spanish_common-usernames-and-passwords.txt | 525.958 | `Passwords/Common-Credentials/Language-Specific/` |

La presentación no necesita estas listas: suman cientos de MB y algunas
proceden de filtraciones. `rockyou` llega como `tar.gz` y el script lo extrae a texto plano: si tienes un
fichero `rockyou.txt` que empieza por `rockyou.txt` seguido de bytes nulos, es
el tarball sin extraer.

## RainbowCrack (nivel 5)

```bash
rainbowcrack/build.sh
```

Genera `rainbowcrack/bin/{rtgen,rtsort,rtdump,rcrack}` y necesita `build-essential`
y `libssl-dev`. La fuente es RainbowCrack 1.2 de Zhu Shuanglei, con dos parches
para g++ y OpenSSL modernos (`#include <cstring>`, API DES actualizada,
`-lcrypto`). Tablas de ejemplo (MD5 minúsculas, 1-5, cubre ~200M contraseñas en
~1 GB y 10-20 min de precomputo):

```bash
cd rainbowcrack/bin
./rtgen md5 loweralpha 1 5 0 4000 20000 tables
./rtsort tables/*.rt
```

Sólo el hash `md5`, `sha1` y `lm` están soportados por esta versión. El plan del
auditor añade el trabajo `n5_rainbow_tablas` sólo si hay tablas `.rt` y el hash es
MD5/SHA1 crudo.

### Navaja suiza PHP/OWASP (v1.9.0)

- **`--modo cve` (PHP → 3)**: ejecuta el script de investigación
  Masriyan/php2shell (vendorizado, MIT) contra el objetivo: verifica la
  primitiva `session.upload_progress` de CVE-2026-109618/109619 (sonda
  inerte; `--activo` añade evasión de filtros + carrera; `--sink-scan`
  busca el include/LFI que cerraría la cadena RCE). El exploit RCE
  weaponizado sigue sin ser público; los repos de 9bie, ikow y syrex1013
  (documentados en CHANGELOG) son investigación y reglas de detección.
- **`--modo estatico` (PHP → 4)**: auditoría estática de TU código PHP
  (16 reglas, severidades, `fichero:línea`), al estilo de
  Vulny-Code-Static-Analysis / vuln-scan / Cobra pero sin dependencias.
- **`--modo owasp` (Web → 5)**: ~20 peticiones de reconocimiento OWASP
  (cabeceras, cookies, `.git`/`.env`, XSS reflejado, SQLi por error,
  open redirect, CRLF, TRACE, datos sensibles, XXE opcional). Ideas del
  top-10 de frohrer.com; cada hallazgo es pista a confirmar.
- **`--modo node2shell` (Web → 6)**: Node2Shell
  ([CVE-2026-111497](https://github.com/advisories/GHSA-9v8h-qqgm-4m35)),
  la escritura fuera de límites del decodificador Brotli de Node.js
  (<22.23.4/24.22.1/26.12.1) que llega por cuerpos de petición con
  `Content-Encoding: br`. Dos fases: **0) Comprobación** (¿el endpoint
  decodifica br?) y **1) Ataque** (5 mutaciones deterministas de un
  stream brotli real, entregadas en trozos de 1 byte para forzar el
  decodificador en streaming — el camino del bug — con monitor de
  reinicio que distingue crash de proceso de error de aplicación).
  Requiere `pip install brotli`. El RCE no se afirma sin PoC público:
  un crash confirmado afirma primitiva de corrupción de memoria.
- **`--modo litellm` (Web → 7)**: LiteLLM 1.107.0, el compromiso de
  cadena de suministro del 2026-10-21 (cook.pth / PRIVCOLLECT /
  sitecustomize.py en el lib del entorno; exfil a
  `hxxp://www.litellm.dev/healthcheck`). Comprueba el proxy remoto
  (`--url`), un entorno Python desempaquetado (`--ruta`) o esta máquina
  (`--sistema`) — siempre sin ejecutar el Python sospechoso. Si tu
  entorno llegó a tener 1.107.0: reconstruir y rotar credenciales;
  borrar el paquete no limpia los ficheros de arranque.

### Pruebas reales y comodidad (v1.8.0)

- **PHP**: `--modo php` ya no se esconde tras un checklist si la versión
  está oculta: ejecuta sondas activas — descargas indiscretas
  (`index.php~/.bak/.old`, `composer.json`, `.env`), phpinfo, LFI
  `php://filter`, **sonda de fuga entre peticiones** (CVE-2026-109619:
  petición marcada + 20 en la misma conexión; si la marca reaparece,
  hay estado rancio) y **sonda OOM** (CVE-2026-109618: POST de 16 MB +
  GET inmediato; 5xx = sospecha, 413 = ni llega a PHP). El checklist va
  al final como referencia. `--sin-oom` omite el POST grande.
- **Evil twin capturamanos**: 12 s de airodump ANTES del deauth para
  ver quién está asociado de verdad; deauth dirigido por cliente y
  aviso claro si el AP real no tiene nadie conectado.
- **MAC** (`--modo mac`, Tarjeta de red → 5): randomizar (`--mac
  random`), fijar (`--mac AA:BB:...`) o restaurar la de fábrica
  (`--restaurar`). Probado: random → internet sigue → restaurar.
- **Escaneo vivo** (`--modo vivo`, Escaneo → 3): `watch --color -d` +
  `nmcli device wifi list --rescan yes` cada 5 s, sin modo monitor;
  cae al escaneo clásico con aviso si faltan herramientas o no hay
  terminal.
- **Interfaz con `activar`**: donde se pide una interfaz en monitor,
  responde `activar` y la pone ahora. Y todo es numerado: `1` = plan,
  `2` = prueba, `1..N` = interfaz de la lista (las palabras siguen
  sirviendo).
- **KRACK, aclarado**: ataca al supplicant del CLIENTE que se conecta;
  comprobar tu propia máquina solo dice si tú estás parcheado. Para la
  prueba activa: emite un AP con `wifi-evil-twin` y conecta a él el
  dispositivo objetivo (móvil/tablet antiguos); el parche que importa
  es el del cliente atacado.

### Reinicio de la interfaz (v1.7.0)

En **WiFi · Tarjeta de red → 4) Reiniciar/resetear interfaz**
(`--modo reset [--interfaz X] [--con-driver]`): link down/up, arranque de
NetworkManager si estaba tumbado y reconexión a los perfiles guardados.
Con rebind de driver PCI (`--con-driver`) la tarjeta entera se apaga y
enciende — útil cuando la mt7925 queda colgada tras experimentos con
monitor/evil twin. No actúa sobre interfaces en modo monitor.

### Navegador de capturas y apartado PHP (v1.6.0)

- En cualquier prompt de ruta de las auditorías WiFi y de ficheros se
  puede responder **`navegar`**: se lista el directorio indicado
  (`~/capturas_wifi` por defecto) con las capturas crackables más
  recientes y se elige por número.
- **Auditoría Web → PHP** (`--modo php --url …`) hace ~13 GETs acotados:
  huella de versión, veredicto de los **CVE-2026-109618/109619** del core
  (RCE sin autenticar + fuga de memoria, CVSS 9.2, PHP 5.4–8.5.11,
  parches 8.5.12/8.4.27/8.3.36/8.2.35, ≤8.1 EOL sin fix), phpinfo()
  expuesto y LFI por `php://filter/convert.base64-encode`. Con
  `--modo php-checklist` se imprime el checklist clásico de 14 vectores
  (bugbase top-10, hacktricks, gist de funciones de explotación,
  netsolutions). Probado contra un servidor PHP 8.4 real: versión,
  phpinfo y LFI detectados correctamente.

## Autocomprobación rápida

Sin descargar ninguna lista:

```bash
for script in auditor_generico.sh wordlists/descargar_wordlists.sh rainbowcrack/build.sh \
  run_captura_wifi.sh run_captura_wifi_wps.sh run_reaver_largo.sh run_mascara_larga.sh; do
  bash -n "$script" || break
done
python3 -m unittest -v test_kit test_wifi_capture test_wps_capture test_wifi_monitor \
  test_escaneo_wpsplinter test_oui_lookup test_extras test_regresiones
# test_extras_web abre un socket local y se ejecuta donde estén permitidos:
python3 -m unittest -v test_extras_web
python3 demo_controles.py

printf 'prueba\n' > /tmp/prueba.txt
printf 'solo_demo_ficticio_03!\n' > /tmp/demo-lista.txt
7z a -p'solo_demo_ficticio_03!' -tzip /tmp/prueba.zip /tmp/prueba.txt
./auditor_generico.sh --yes --nivel 1 --wl /tmp/demo-lista.txt /tmp/prueba.zip
# esperado: candidato oculto y verificación=ok en resultado.txt
```

## Créditos

- Wordlists: [SecLists](https://github.com/danielmiessler/SecLists) de Daniel Miessler.
  Comprueba la licencia y procedencia de cada lista antes de redistribuirla;
  el descargador no incorpora sus contenidos al repositorio.
- Crackeo: hashcat y John the Ripper jumbo (cada uno su licencia).
- RainbowCrack 1.2, Zhu Shuanglei — `rainbowcrack/disclaimer.txt`. Ese archivo
  contiene una exención de garantía, pero no aclara por sí solo los derechos
  de redistribución; compruébalos antes de publicar una copia del código.

## Límites de la demostración

Una contraseña fuerte y única, almacenada con una función adecuada, ofrece
una resistencia muy distinta de un hash rápido sin sal. Los intentos offline
contra un hash obtenido y los intentos online contra un inicio de sesión tienen
límites diferentes. Véanse las guías de [OWASP sobre almacenamiento](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
y [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html).
