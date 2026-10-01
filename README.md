# kit-auditoria-claves

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

## Estructura

```text
kit-auditoria-claves/
├── auditor_generico.sh          script principal (menú guiado o CLI)
├── demo_controles.py            demo pequeña con datos ficticios
├── test_kit.py                  pruebas sin credenciales reales
├── PRESENTACION.md              guion breve para el equipo
├── README.md                    este archivo
├── .gitignore                   wordlists descargadas y resultados no se versionan
├── wordlists/
│   ├── manifest.tsv             nombre, líneas, sha256, origen SecLists
│   ├── descargar_wordlists.sh   trae las listas y verifica sha256
│   └── (tus listas propias: .gitignore las excluye del repo)
└── rainbowcrack/
    ├── build.sh                 compila la fuente a rainbowcrack/bin/
    ├── src/                     RainbowCrack 1.2 parcheado (g++ y openssl actuales)
    ├── disclaimer.txt           aviso del autor original
    └── readme_src.txt           instrucciones de build originales
```

## Requisitos

```bash
sudo apt-get update
sudo apt-get install -y p7zip-full python3 curl tar john hashcat \
  python3-olefile libcompress-raw-lzma-perl poppler-utils \
  hcxtools aircrack-ng build-essential libssl-dev
```

- **Motor de crackeo:** `hashcat` (GPU) y/o `john`. El script prefiere hashcat y cae a
  john automáticamente. Comprueba que tu john es la variante *jumbo* con
  `command -v zip2john`; si no lo es, instala la jumbo desde <https://www.openwall.com/john/>.
- **`p7zip-full`** permite verificar candidatos contra rar/zip/7z.
- **Office:** `python3-olefile` para `office2john.py`.
- **PDF 7z/LZMA:** `libcompress-raw-lzma-perl` para `7z2john.pl`.
- **WiFi:** `hcxtools` convierte `.cap/.pcap` al formato `22000` de hashcat; sin él,
  el script avisa y usa john (más lento).
- **Rainbow (nivel 5):** sólo si compilas `rainbowcrack/build.sh`.

## Puesta en marcha

```bash
git clone <la-url-del-repo> kit-auditoria-claves
cd kit-auditoria-claves

wordlists/descargar_wordlists.sh          # 12 listas, ~260 MB, con sha256
rainbowcrack/build.sh                     # opcional: tablas del nivel 5
```

Para la demo no hace falta descargar nada: `python3 demo_controles.py`.
La descarga de listas y la compilación de RainbowCrack son opcionales.
`descargar_wordlists.sh` sólo baja lo que falte; `--comprobar` revalida sha256,
`--fuerza` repite la descarga y `wordlists/descargar_wordlists.sh rockyou.txt`
baja una lista concreta. Las descargas están en `.gitignore`: cada compañero
las trae con ese comando en su copia.

## Uso

Modo guiado (menú de tipo de objetivo, ruta y niveles):

```bash
./auditor_generico.sh
```

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

**Niveles (`--nivel` 1..5 o rango, por defecto `1-3`):**

| Nivel | Qué hace |
|-------|----------|
| 1 | intentos inmediatos: `stupid-ones`, `unkown-azul` y `custom.txt` si existe |
| 2 | listas comunes con reglas: `days`, `months`, `Most-Popular`, `JWT` (+best66) |
| 3 | listas grandes con reglas: Merriam-Webster SCRABBLE, SCRABBLE-large, darkc0de |
| 4 | masivas y combinaciones: Pwdb 10M, rockyou (solo y con best66), azul×días, híbrido lista propia+6 dígitos (si hay lista propia) |
| 5 | máscaras (`?d?d?d?d?d?d?d?d`, …) y rainbow tables (MD5/SHA1 sin sal) |

Los trabajos se ejecutan **en secuencia**. Al aparecer un candidato, se distingue
entre verificación independiente (`ok`), rechazo (`rechazado`) y coincidencia
según el motor sin verificación independiente (`motor`). Los hashes hexadecimales
MD5, SHA-1 y SHA-256 se recalculan para comprobar el candidato; para Office,
otros hashes y Wi-Fi no se afirma una verificación independiente. `7z t`
puede comprobar un documento Office normal sin comprobar ninguna clave.

Otras opciones: `--dry-run` (plan orientativo sin ejecutar motores ni crear
archivos), `--yes` (sin preguntar), `--guardar-secretos` (conserva salida sensible),
`--max-min N` (omite trabajos estimados sobre N minutos), `--sin-calibrar`
(estimaciones sin medir), `--wl lista1,lista2` (sustituye niveles 1-2),
`--formato NOMBRE` (formato john si hay duda), `--rainbow-dir DIR`.

`--help` imprime toda la ayuda.
Un hash hexadecimal sin metadatos es ambiguo: para hashcat, indica siempre
`--modo` en lugar de asumir MD5 por su longitud.

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

## Wordlists

No se versiona ninguna lista `.txt`: las doce de abajo se traen con
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

## Autocomprobación rápida

Sin descargar ninguna lista:

```bash
bash -n auditor_generico.sh wordlists/descargar_wordlists.sh rainbowcrack/build.sh
python3 -m unittest -v test_kit
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
