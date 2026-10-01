# Ocho casos ficticios para el auditor

Son cadenas inventadas con el prefijo `Ficcion` y dos PIN elegidos sólo para
esta demostración. No proceden de personas, servicios ni filtraciones. Cada
archivo generado contiene **un único hash MD5** para enseñar cómo cambia el
espacio de candidatos; MD5 no es adecuado para almacenar contraseñas reales.

| Archivo | Cadena ficticia | Método que la encuentra |
|---|---|---|
| `01_directa.md5` | `FiccionCometa` | lista pequeña, nivel 1 |
| `02_cambio_caso.md5` | `FICCIONNUBE` | cambio de mayúsculas, `--ampliar`, nivel 2 |
| `03_anio_simbolo.md5` | `FiccionCometa<AÑO>!` | año actual más símbolo, `--ampliar`, nivel 2 |
| `04_sufijo_dos_cifras.md5` | `FiccionLago37` | sufijo numérico, `--ampliar`, nivel 2 |
| `05_prefijo_dos_cifras.md5` | `42FiccionBosque` | prefijo numérico, `--ampliar`, nivel 2 |
| `06_dos_palabras.md5` | `FiccionCometa-FiccionNube` | unión de dos semillas, `--ampliar`, nivel 2 |
| `07_pin_cuatro.md5` | `0427` | máscara de 4 cifras, `--ampliar`, nivel 1 |
| `08_pin_seis.md5` | `004271` | máscara de 6 cifras, `--ampliar`, nivel 2 |

Genera los ocho hashes en un directorio temporal nuevo:

```bash
DEMO_DIR=$(mktemp -d)
python3 ejemplos/crear_casos.py --salida "$DEMO_DIR"
```

Ejemplo con John the Ripper jumbo, sólo contra uno de esos hashes:

```bash
./auditor_generico.sh --tipo hash --motor john --formato raw-md5 \
  --nivel 2 --ampliar --wl ejemplos/semillas_ficticias.txt \
  --sin-calibrar --yes "$DEMO_DIR/03_anio_simbolo.md5"
```

El informe debe mostrar `fase=n2_extra_anios` y `verificacion=ok` sin revelar
la cadena. Cambia el archivo y el nivel para mostrar otro método. Consulta el
plan con `--dry-run`; para evitar trabajos largos, usa `--max-min N`. La opción
`--guardar-secretos` sólo tiene sentido para revisar pruebas ficticias en un
equipo privado.

Con John jumbo, las reglas comunes pueden resolver los casos de mayúsculas y
sufijo numérico antes de que lleguen los trabajos `n2_extra_*`. Eso ilustra que
varios métodos solapan candidatos; no son ocho vulnerabilidades independientes.
