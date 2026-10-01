# kit-auditoria-claves

Base común para auditorías de contraseñas: un único script guiado (`auditor_generico.sh`)
que va de lo simple a lo complejo, con los wordlists, las reglas de ataque y (opcional)
RainbowCrack compilable desde la fuente incluida.

> **Uso autorizado.** Este material sirve para auditar sistemas y ficheros propios o
> para los que tengas autorización expresa por escrito. Las contraseñas que salgan
> quedan en tus logs locales; no las subas al repositorio.

## Estructura

```text
kit-auditoria-claves/
├── auditor_generico.sh          script principal (menú guiado o CLI)
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
- **`p7zip-full`** además hace falta para *verificar* la contraseña contra rar/zip/7z/office.
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
./auditor_generico.sh --tipo hash --modo 0 --nivel 5 hash_md5.txt
./auditor_generico.sh --tipo wifi captura.cap
./auditor_generico.sh --motor john --dry-run objetivo.rar   # sólo plan
./auditor_generico.sh --tipo externo --externo-cmd './verificador.sh %P' fichero.xdf
```

**Tipos (`--tipo`):** `archivo` (rar/zip/7z/pdf/keepass, autodetecta), `office`,
`wifi`, `hash`, `externo` (formato no reconocido) y `auto` (por defecto).

**Niveles (`--nivel` 1..5 o rango, por defecto `1-3`):**

| Nivel | Qué hace |
|-------|----------|
| 1 | intentos inmediatos: `stupid-ones`, `unkown-azul` (y tu lista propia si la dejas en `wordlists/`) |
| 2 | listas comunes con reglas: `days`, `months`, `Most-Popular`, `JWT` (+best66) |
| 3 | listas grandes con reglas: Merriam-Webster SCRABBLE, SCRABBLE-large, darkc0de |
| 4 | masivas y combinaciones: Pwdb 10M, rockyou (solo y con best66), azul×días, híbrido lista propia+6 dígitos (si hay lista propia) |
| 5 | máscaras (`?d?d?d?d?d?d?d?d`, …) y rainbow tables (MD5/SHA1/LM) |

Los ataques salen ordenados de rápido a lento, se ejecutan **en secuencia**, se
**para en cuanto aparece** la contraseña y el resultado se **verifica siempre con
una herramienta externa** (`7z t`, `7z l`, `pdfinfo`…).

Otras opciones: `--dry-run` (plan sin ejecutar), `--yes` (sin preguntar),
`--max-min N` (omite trabajos estimados sobre N minutos), `--sin-calibrar`
(estimaciones sin medir), `--wl lista1,lista2` (sustituye niveles 1-2),
`--formato NOMBRE` (formato john si hay duda), `--rainbow-dir DIR`.

`--help` imprime toda la ayuda.

### Formatos no reconocidos (`.xdf`, firmas propias…)

El tipo `externo` necesita un verificador: una orden que reciba la contraseña
candidata por `%P` y termine con código 0 sólo si es la correcta.

```bash
./auditor_generico.sh --tipo externo --externo-cmd '/ruta/verificar.sh %P' fichero.xdf
```

Si no existe verificador, ese objetivo no se puede auditar con el kit.

## Resultados

Cada ejecución crea `~/auditoria_logs/<fecha>_<fichero>.XXXXXX/` con:

- `password.txt` — la contraseña encontrada
- `resultado.txt` — fecha, objetivo, tipo, motor, modo, fase, contraseña y verificación
- `hashcat.pot` / `john.pot` — potfiles de los motores
- `*.log` — log de cada trabajo del plan

Queda fuera del repositorio (ver `.gitignore`): **no subas nunca** esos directorios.

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
Si tenéis listas propias del equipo, ponedlas en `wordlists/` con el nombre que
queráis: el script las coge en el nivel 1 sin que se suban al repo (o apuntadlas
con `--wl`). Origen y `sha256` de todo en `manifest.tsv`, desde
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

rockyou llega como `tar.gz` y el script lo extrae a texto plano: si tienes un
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

Con las wordlists ya descargadas:

```bash
bash -n auditor_generico.sh wordlists/descargar_wordlists.sh rainbowcrack/build.sh

printf 'prueba\n' > /tmp/prueba.txt
7z a -p'secret' -tzip /tmp/prueba.zip /tmp/prueba.txt
./auditor_generico.sh --yes --nivel 1 /tmp/prueba.zip
# esperado: CONTRASEÑA ENCONTRADA: secret y "contenido verificado: 1 ficheros"
```

## Créditos

- Wordlists: [SecLists](https://github.com/danielmiessler/SecLists) de Daniel Miessler
  (cada lista conserva la licencia de su origen).
- Crackeo: hashcat y John the Ripper jumbo (cada uno su licencia).
- RainbowCrack 1.2, Zhu Shuanglei — `rainbowcrack/disclaimer.txt`.
