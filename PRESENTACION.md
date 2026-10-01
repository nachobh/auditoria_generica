# Guion de presentación (5–7 minutos)

Usa sólo datos ficticios y una máquina local. No hace falta descargar listas,
copiar credenciales ni iniciar un servicio de red.

1. **Pregunta inicial:** ¿qué protege una contraseña: la cadena elegida, el
   almacenamiento o el control de acceso? Explica que el ataque offline a un
   archivo de hashes y los intentos online contra un login son escenarios
   distintos.
2. **Demo local:** ejecuta `python3 demo_controles.py`. La tabla de ocho cadenas
   ficticias recupera el ejemplo sin sal. La sal única cambia el verificador;
   no vuelve segura por sí sola una función rápida. PBKDF2 y, si se instaló
   `argon2-cffi`, Argon2id elevan el coste de cada intento. Los milisegundos
   medidos pertenecen a esta máquina y a esos parámetros.
3. **Control online simulado:** señala el límite de tres fallos y que conocer
   la contraseña no basta si falta el segundo factor. Muestra además dos de
   tres cuentas ficticias que reutilizan la misma cadena. El simulador no hace
   peticiones de red ni reproduce un servicio de autenticación completo.
4. **Auditoría reproducible:** genera los [ocho casos ficticios](ejemplos/README.md)
   y muestra cómo una lista de cuatro semillas, sus variantes y dos máscaras
   encuentran patrones distintos. `python3 -m unittest -v test_kit` comprueba
   el plan y los informes. `ok` significa verificación independiente; `motor`
   sólo informa una coincidencia del motor.
5. **Cierre:** recomienda contraseñas únicas y largas, un gestor de contraseñas,
   verificación de contraseñas comprometidas al registrarse, almacenamiento
   adecuado, límite de intentos y MFA. Para cuentas compatibles, considera
   autenticadores resistentes al phishing como passkeys.

No presentes una tabla rainbow como ataque contra hashes con sal única ni
extrapoles la velocidad de SHA-256 a Argon2id. Evita mostrar el contenido de
potfiles, listas descargadas, rutas personales o candidatos de una auditoría
real. Revisa cualquier captura antes de compartirla.

Referencias: [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
[OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
y [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html).
