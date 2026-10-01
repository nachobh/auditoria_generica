#!/usr/bin/env python3
"""Demostración local con cadenas ficticias; no lee credenciales ni usa red."""

import hashlib
import hmac
import secrets
import time


CANDIDATOS = tuple(f"solo_demo_ficticio_{i:02d}!" for i in range(8))
OBJETIVO = CANDIDATOS[3]


class LoginFicticio:
    def __init__(self, secreto, max_fallos=3):
        self.secreto = secreto
        self.max_fallos = max_fallos
        self.fallos = 0

    def intentar(self, candidato, segundo_factor=False):
        if self.fallos >= self.max_fallos:
            return False
        if not hmac.compare_digest(candidato, self.secreto):
            self.fallos += 1
            return False
        return segundo_factor


def medir(funcion, repeticiones=5000):
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
    tabla_falla_con_sal = con_sal() not in tabla
    sal_unica_cambia_resultado = con_sal() != hashlib.sha256(sal_b + dato).digest()

    acceso = LoginFicticio(OBJETIVO)
    for _ in range(3):
        acceso.intentar(CANDIDATOS[0])
    bloqueado = not acceso.intentar(OBJETIVO, segundo_factor=True)
    otro_acceso = LoginFicticio(OBJETIVO)
    clave_correcta_sin_segundo_factor_autentica = otro_acceso.intentar(OBJETIVO)
    clave_con_segundo_factor_autentica = otro_acceso.intentar(OBJETIVO, segundo_factor=True)
    cuentas_ficticias = (OBJETIVO, OBJETIVO, CANDIDATOS[6])
    cuentas_que_reutilizan = sum(hmac.compare_digest(valor, OBJETIVO)
                                for valor in cuentas_ficticias)

    resultado = {
        "candidatos_ficticios": len(CANDIDATOS),
        "tabla_reutilizable_sin_sal": sin_sal_en_tabla,
        "tabla_falla_con_sal": tabla_falla_con_sal,
        "sal_unica_cambia_verificador": sal_unica_cambia_resultado,
        "sha256_us": medir(rapido) * 1_000_000,
        "sha256_con_sal_us": medir(con_sal) * 1_000_000,
        "pbkdf2_100000_ms": medir(lento, 2) * 1000,
        "login_bloqueado_tras_tres_fallos": bloqueado,
        "clave_sin_segundo_factor_autentica": clave_correcta_sin_segundo_factor_autentica,
        "clave_con_segundo_factor_autentica": clave_con_segundo_factor_autentica,
        "cuentas_ficticias_que_reutilizan": cuentas_que_reutilizan,
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
    print(f"La misma tabla no resuelve el hash con sal: {resultado['tabla_falla_con_sal']}")
    print(f"Sal única cambia el verificador: {resultado['sal_unica_cambia_verificador']}")
    for clave in ("sha256_us", "sha256_con_sal_us"):
        print(f"{clave}: {resultado[clave]:.2f} µs por cálculo")
    for clave in ("pbkdf2_100000_ms", "argon2id_ms"):
        if clave in resultado:
            print(f"{clave}: {resultado[clave]:.2f} ms por cálculo")
    if "argon2id" in resultado:
        print(resultado["argon2id"])
    print(f"Login local bloqueado tras tres fallos: {resultado['login_bloqueado_tras_tres_fallos']}")
    print(f"Contraseña sin segundo factor da acceso: {resultado['clave_sin_segundo_factor_autentica']}")
    print(f"Contraseña con segundo factor da acceso: {resultado['clave_con_segundo_factor_autentica']}")
    print(f"Cuentas ficticias que reutilizan la misma cadena: {resultado['cuentas_ficticias_que_reutilizan']} de 3")
    print("Tiempos ilustrativos de esta máquina; no son una estimación de resistencia.")


if __name__ == "__main__":
    main()
