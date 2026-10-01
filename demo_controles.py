#!/usr/bin/env python3
"""Demostración local con cadenas ficticias; no lee credenciales ni usa red."""

import hashlib
import hmac
import secrets
import time


CANDIDATOS = tuple(f"solo_demo_ficticio_{i:02d}!" for i in range(8))
OBJETIVO = CANDIDATOS[3]


def medir(funcion, repeticiones=8):
    inicio = time.perf_counter()
    for _ in range(repeticiones):
        funcion()
    return (time.perf_counter() - inicio) / repeticiones


def resumen():
    dato = OBJETIVO.encode()
    sal_a = secrets.token_bytes(16)
    sal_b = secrets.token_bytes(16)

    rapido = lambda: hashlib.sha256(dato).digest()
    con_sal = lambda: hashlib.sha256(sal_a + dato).digest()
    lento = lambda: hashlib.pbkdf2_hmac("sha256", dato, sal_a, 100_000)

    tabla = {hashlib.sha256(c.encode()).digest(): c for c in CANDIDATOS}
    sin_sal_en_tabla = rapido() in tabla
    # La tabla anterior no sirve contra un verificador con una sal única.
    sal_unica_cambia_resultado = con_sal() != hashlib.sha256(sal_b + dato).digest()

    intentos_permitidos = 3
    intentos_incorrectos = 4
    bloqueado = intentos_incorrectos >= intentos_permitidos
    clave_correcta_sin_segundo_factor_autentica = False

    resultado = {
        "candidatos_ficticios": len(CANDIDATOS),
        "tabla_reutilizable_sin_sal": sin_sal_en_tabla,
        "sal_unica_cambia_verificador": sal_unica_cambia_resultado,
        "sha256_ms": medir(rapido) * 1000,
        "sha256_con_sal_ms": medir(con_sal) * 1000,
        "pbkdf2_100000_ms": medir(lento, 2) * 1000,
        "login_bloqueado_tras_tres_fallos": bloqueado,
        "clave_sin_segundo_factor_autentica": clave_correcta_sin_segundo_factor_autentica,
    }
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        resultado["argon2id"] = "opcional: instala argon2-cffi para medirlo"
    else:
        funcion = lambda: hash_secret_raw(dato, sal_a, time_cost=2,
                                          memory_cost=19 * 1024, parallelism=1,
                                          hash_len=32, type=Type.ID)
        resultado["argon2id_ms"] = medir(funcion, 2) * 1000
    return resultado


def main():
    resultado = resumen()
    print("Demo local: ocho cadenas inventadas; no se imprimen secretos ni hashes.")
    print(f"Tabla sin sal reutilizable: {resultado['tabla_reutilizable_sin_sal']}")
    print(f"Sal única cambia el verificador: {resultado['sal_unica_cambia_verificador']}")
    for clave in ("sha256_ms", "sha256_con_sal_ms", "pbkdf2_100000_ms", "argon2id_ms"):
        if clave in resultado:
            print(f"{clave}: {resultado[clave]:.3f} ms por cálculo")
    if "argon2id" in resultado:
        print(resultado["argon2id"])
    print(f"Login local bloqueado tras tres fallos: {resultado['login_bloqueado_tras_tres_fallos']}")
    print(f"Contraseña sin segundo factor da acceso: {resultado['clave_sin_segundo_factor_autentica']}")
    print("Tiempos ilustrativos de esta máquina; no son una estimación de resistencia.")


if __name__ == "__main__":
    main()
