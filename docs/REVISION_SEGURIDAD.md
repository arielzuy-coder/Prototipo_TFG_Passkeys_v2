# Revisión de seguridad — Prototipo TFG Passkeys (v2)

**Base revisada:** `Prototipo_TFG_Passkeys` @ `671293c` (10/11/2025)
**Fecha:** 29/10/2026
**Método:** lectura de código del backend + prueba de concepto ejecutada contra el backend levantado localmente (FastAPI + PostgreSQL 16). El script de la PoC está en `docs/poc_bypass.py`.

---

## Resumen

La autenticación WebAuthn **no verifica criptográficamente nada**: no valida la firma, no valida el challenge y guarda una clave pública ficticia. Sumado a que ningún endpoint exige token, hoy cualquiera puede:

1. Iniciar sesión como cualquier usuario sabiendo solo su email.
2. Superar el step-up, porque el OTP viene en la misma respuesta.
3. Enrolar su propia passkey en la cuenta de otro sin estar logueado.
4. Leer y modificar políticas, auditoría y passkeys de terceros.

La librería `webauthn` (py_webauthn 1.11) está en `requirements.txt` y se importa, pero sus funciones de verificación nunca se llaman.

| # | Hallazgo | Severidad | Verificado |
|---|----------|-----------|-----------|
| H1 | Verificación de autenticación WebAuthn simulada (sin firma) | Crítica | Sí, PoC |
| H2 | Challenge tomado del cliente y nunca comparado | Crítica | Sí, PoC |
| H3 | Registro de passkeys sin autenticación previa (account takeover) | Crítica | Sí, PoC |
| H4 | Ningún endpoint valida el JWT; admin abierto | Crítica | Sí, PoC |
| H5 | OTP de step-up devuelto en la respuesta y escrito en el log | Alta | Sí, PoC |
| H6 | `verify_token` lanza `AttributeError` ante un token inválido | Media | Sí |
| H7 | Fingerprint de dispositivo por User-Agent y no atado al usuario | Alta | Código |
| H8 | CORS con credenciales para cualquier `*.onrender.com` | Alta | Código |
| H9 | IP de cliente detrás de proxy / IPs privadas tratadas como Argentina | Media | Código (verificar en Render) |
| H10 | Estado efímero en memoria (challenges, step-up) | Media | Código |
| H11 | OTP generado con `random` y sin límite de intentos | Media | Código |
| H12 | Errores internos expuestos al cliente (`detail=str(e)`) | Baja | Código |
| H13 | Dependencias faltantes y desactualizadas | Baja | Sí |

---

## Detalle

### H1 — Verificación de autenticación simulada (Crítica)
`backend/auth/webauthn_handler.py`, `verify_authentication()`: solo decodifica `clientDataJSON` y compara `type` y `origin`. Lee `authenticatorData` y `signature` pero no los usa, y devuelve `verified: True` siempre. El contador se incrementa en el servidor (`current_counter + 1`) en lugar de tomarse del autenticador, así que tampoco detecta clonación.

En el registro, `_extract_public_key()` devuelve `b"mock_public_key_bytes"`: **todas las passkeys tienen la misma "clave pública" falsa**, por lo que aunque se agregara verificación de firma no habría con qué verificar.

**PoC:** login exitoso enviando `signature: "basura"`, sin autenticador.

### H2 — Challenge controlado por el cliente (Crítica)
`app.py` llama a la verificación con `expected_challenge=credential.get('challenge')`, es decir, el valor lo manda el atacante. Además el handler nunca compara ese valor con `clientDataJSON.challenge`. El `challenge_store` se llena pero no se consulta ni se invalida. No hay protección contra replay.

### H3 — Enrolamiento sin autenticación (Crítica)
`/auth/register/begin` crea el usuario si no existe y `/auth/register/complete` agrega una passkey a **cualquier usuario existente** con solo el email. No se exige sesión, invitación ni verificación del titular. Contradice RNF-C2 de la tesis ("verificación fuerte del titular").

**PoC:** el atacante agrega "cred-atacante" a la cuenta de la víctima.

### H4 — Endpoints sin control de acceso (Crítica)
`token_manager.verify_token()` no se invoca en ningún endpoint. Los tokens se emiten pero nadie los valida. Tampoco existe el concepto de rol en `models.py`. Quedan abiertos, entre otros:

- `/admin/policies` (GET, POST, PUT, DELETE, toggle): cualquiera puede desactivar las políticas de riesgo.
- `/passkeys/{email}` y `DELETE /passkeys/{id}`: enumerar y borrar passkeys ajenas.
- `/audit/*`, `/risk/dashboard` y el router de `audit_reports.py` (exportación CSV/JSON).

Contradice RNF-S3 y la matriz RBAC de la tesis (tres perfiles).

**PoC:** `GET /admin/policies`, `PUT /admin/policies/{id}/toggle`, `GET /passkeys/{email}`, `GET /audit/events` → 200 sin token.

### H5 — OTP expuesto (Alta)
`app.py`, rama step-up de `login_complete`: la respuesta incluye `"otp_code": otp_code` y el log registra `OTP: {otp_code}`. El step-up no agrega ningún factor.

### H6 — `verify_token` roto (Media)
Usa `except jwt.JWTError`, que existe en `python-jose` pero no en PyJWT (la librería que se importa). Ante cualquier token inválido lanza `AttributeError` en vez de devolver `None`. Hoy no explota porque nadie llama a la función (ver H4), pero rompería al proteger endpoints.

### H7 — Confianza en el dispositivo (Alta)
El fingerprint es `browser_os_useragent[:50]`, enviado por el cliente y trivial de copiar. Además la búsqueda en `_evaluate_device_risk` **no filtra por usuario**: un dispositivo conocido de cualquier usuario baja el riesgo de todos. El factor "dispositivo" (peso alto en el motor) es manipulable.

Mejor señal disponible sin agregar fingerprinting: la propia passkey usada (`credential_id`) más los flags del autenticador (backup eligible/state) que da py_webauthn.

### H8 — CORS (Alta)
`allow_origin_regex=r"https://.*\.onrender\.com"` con `allow_credentials=True`: cualquier sitio desplegado por cualquier persona en Render puede hacer requests autenticados contra la API. Las entradas con `*` en `allow_origins` no funcionan como comodín (Starlette las compara literalmente).

### H9 — IP del cliente (Media, verificar)
Detrás del proxy de Render, `request.client.host` puede ser una IP interna si uvicorn no confía en `X-Forwarded-For`. `_get_location_from_ip` trata `10.*` y `192.168.*` como "Argentina", con lo que el factor ubicación quedaría siempre en bajo riesgo. Además la IP del usuario se envía a un tercero (ipapi.co) en cada login, cosa a declarar según RNF-N2 (minimización de datos).

### H10 — Estado en memoria (Media)
`challenge_store` y `stepup_tokens` son diccionarios del proceso: se pierden al reiniciar, no funcionan con más de un worker y crecen sin límite (no se purgan).

### H11 — OTP débil (Media)
`random.randint` no es criptográficamente seguro (usar `secrets`). No hay límite de intentos sobre `/auth/stepup/verify` ni sobre los endpoints de login.

### H12 — Fuga de errores (Baja)
Varios `except Exception as e: raise HTTPException(..., detail=str(e))` y el `/health` devuelven mensajes internos (incluida la cadena de conexión fallida).

### H13 — Dependencias (Baja)
- `risk_engine.py` y `threat_intelligence.py` importan `requests`, que no está en `requirements.txt`.
- `python-jose` y `passlib` figuran pero no se usan; `jwt` es PyJWT.
- Versiones de 2023 (`fastapi` 0.104, `cryptography` 41.0.7) con avisos de seguridad publicados para `cryptography`.

---

## Otros puntos (no son vulnerabilidades)

- Archivos residuales: `app_back.py` (copia de `app.py`), `app_admin.py.py`, `main` vacío, `requirements` sin extensión, y scripts de arreglo puntual (`fix_db_direct.py`, `fix_stepup_policies.py`, `check_policies.py`, etc.).
- Diferencias con la tesis: la tesis describe Keycloak con OIDC/SAML (RF-05, RF-09) y despliegue en VMs con TLS; el código es un backend propio con JWT desplegado en Render. Ver `docs/` para el plan.

---

## Plan de corrección propuesto

**Fase 1 — Autenticación real (H1, H2, H3, H5, H10, H11)**
- Usar `verify_registration_response` / `verify_authentication_response` de py_webauthn con la clave pública real (COSE), `sign_count` del autenticador y `require_user_verification=True`.
- Challenges guardados en base de datos, de un solo uso, con vencimiento, atados al usuario y al tipo de ceremonia.
- Enrolamiento solo con invitación de un administrador (token de un uso) o con sesión activa para agregar una passkey adicional. Límite de 5 por usuario (como dice la tesis).
- Step-up resuelto con una nueva ceremonia WebAuthn con verificación de usuario. El OTP pasa a ser opcional y, si se mantiene, se envía por canal aparte, se genera con `secrets` y se guarda hasheado.

**Fase 2 — Autorización (H4, H6, H8)**
- Dependencia `get_current_user` que valida JWT, tipo de token y sesión no revocada.
- Campo `role` (usuario, auditor, administrador) y dependencia `require_role`, según la matriz RBAC de la tesis.
- CORS solo con orígenes explícitos tomados de configuración.

**Fase 3 — Motor de riesgo y operación (H7, H9, H12, H13)**
- Dispositivo de confianza = passkey del usuario, no User-Agent.
- Manejo correcto de `X-Forwarded-For` con proxies de confianza configurables.
- Límite de intentos, mensajes de error genéricos, dependencias actualizadas, limpieza de archivos.
- Tests automatizados que reproduzcan esta PoC y fallen si alguna regresión la vuelve a habilitar.
