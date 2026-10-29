# Cambios v2 — Fases 1 y 2

Correcciones de la revisión de seguridad (`docs/REVISION_SEGURIDAD.md`) manteniendo la lógica de la tesis:
alta de usuarios por el administrador, máximo 5 passkeys por usuario, step-up por re-autenticación
biométrica, OTP o aprobación de supervisor, perfiles Usuario / Auditor / Administrador (Tabla 4) y tokens
de 15 minutos con refresh de 8 horas y rotación obligatoria.

## Autenticación WebAuthn (H1, H2, H10)

- La verificación la hace **py_webauthn 3.0** (`auth/webauthn_handler.py`): firma, challenge, origen, RP ID,
  flags de presencia y verificación de usuario (UV obligatoria) y contador de firmas.
- Se guarda la **clave pública COSE real** de cada passkey (antes era la misma constante falsa para todas).
- Los challenges viven en la tabla `webauthn_challenges`: un solo uso, vencen a los 5 minutos y están atados
  al usuario y a la ceremonia (`register`, `login`, `stepup`). Un challenge de login no sirve para un step-up.
- El contador se toma del autenticador; si retrocede, la autenticación se rechaza (detección de clonado).

## Alta por invitación y recuperación (H3)

- `register/begin` y `register/complete` exigen una **invitación de un solo uso** (`invitations`, vence a
  las 72 h). El token se guarda hasheado y se muestra una sola vez al administrador.
- El administrador da de alta usuarios desde *Panel Admin → Usuarios y Aprobaciones*; el usuario queda
  `pending` hasta enrolar su primera passkey.
- **Recuperación** (pérdida de dispositivo / cuenta comprometida, sección 4 de Seguridad): revoca todas las
  passkeys y sesiones y emite una invitación de re-enrolamiento. La verificación de identidad del titular se
  hace fuera del sistema antes de entregar el link.
- Un usuario con sesión puede agregar passkeys propias hasta el máximo de 5 y no puede revocar la última.
- **Primer administrador:** con `BOOTSTRAP_ADMIN_EMAIL` definido y sin administradores, `init_db.py`
  escribe en el log el link de invitación. También existe `python create_invitation.py <email> --role admin`.

## Autorización (H4, H6, H8)

- Todos los endpoints salvo login, enrolamiento por invitación y `/health` exigen `Authorization: Bearer`.
- `auth/deps.py`: valida el JWT (PyJWT), que la sesión no esté revocada ni vencida y que el usuario esté
  activo. El rol se lee de la base en cada request, así que un cambio de rol o una suspensión aplican en el acto.

| Perfil | Puede | No puede |
|---|---|---|
| Usuario | Sus passkeys (alta, renombre, baja) y su historial (`/me/events`) | Ver auditoría general ni administrar |
| Auditor | Auditoría, estadísticas, reportes y exportación | Cambiar políticas ni gestionar usuarios |
| Administrador | Usuarios, invitaciones, recuperación, políticas, aprobación de step-up y auditoría | Actuar sobre su propia cuenta o aprobar su propio acceso |

- Refresh con **rotación obligatoria**: cada uso entrega un refresh nuevo. Si se reutiliza uno ya rotado
  (posible robo), se revoca la sesión completa. `POST /auth/logout` revoca la sesión en el servidor.
- CORS solo con orígenes explícitos (`ORIGIN` + `CORS_ORIGINS`), sin regex ni comodines.

## Step-up (H5, H11)

- Estado en la tabla `stepup_transactions` (antes, diccionario en memoria). Vence a los 10 minutos.
- Métodos: **passkey** (nueva ceremonia WebAuthn con UV y challenge propio), **aprobación de supervisor**
  (un administrador aprueba o rechaza desde el panel viendo IP, ubicación, navegador y política) y **OTP por
  email** solo si hay SMTP configurado. El OTP ya no se devuelve en la respuesta ni se escribe en logs; se
  genera con `secrets` y se guarda con HMAC.
- Se eliminaron los métodos que no verificaban nada (`biometric` aceptado sin más y "cualquier PIN de 4 dígitos").
- 5 intentos fallidos bloquean la transacción.

## Motor de riesgo y políticas (H7 parcial, H14)

- Las condiciones `new_device` y `unusual_location` **no se evaluaban**: cualquier política que las usara
  coincidía siempre (por ejemplo, `new_device_stepup` pedía step-up en todos los logins de riesgo bajo).
  Ahora se calculan a partir de los factores del motor.
- Si ninguna política aplica, la decisión por defecto es step-up (antes era `allow`).
- Los dispositivos se buscan dentro del usuario y la huella es única por usuario (antes era global y un
  mismo navegador usado por dos personas dejaba a la segunda sin dispositivo conocido).

## Operación

- `init_db.py` aplica migraciones idempotentes sobre bases de la v1: agrega columnas, cambia el índice de
  dispositivos y **elimina las passkeys con la clave falsa** (no se pueden verificar). Esos usuarios quedan
  `pending` y necesitan una invitación de recuperación.
- Errores internos con mensaje genérico; cabeceras `nosniff`, `no-referrer` y `no-store`.
- Dependencias actualizadas (FastAPI 0.162, PyJWT 2.15, cryptography 50, py_webauthn 3.0); se agregó
  `requests`, que se usaba sin estar declarada, y se quitaron `python-jose`, `passlib` y `geoip2`, que no se usaban.
- Se eliminaron `app_back.py`, `app_admin.py.py`, `main` (vacío) y `backend/requirements` (duplicado).
- `app.py` quedó como armado de la aplicación; los endpoints están en `routers/`.

## Configuración en Render

- **`RP_ID` debe ser el dominio del frontend**, no del backend: es donde el navegador crea y usa la passkey.
  `ORIGIN` es el origen exacto del frontend (`https://...`).
- Definir `BOOTSTRAP_ADMIN_EMAIL`, desplegar y copiar el link de invitación del log del primer arranque.
  Mientras el admin no enrole, cada reinicio emite un link nuevo y revoca el anterior.
- Ver `.env.example` para el resto de las variables (SMTP opcional para el OTP).

## Verificación

- `backend/tests/`: 38 tests con un autenticador FIDO2 por software que firma con claves reales.
  Cada ataque de la revisión tiene su test (firma alterada, challenge propio, replay, otro origen,
  invitación reutilizada, endpoints sin token, matriz de roles, reuso de refresh, bloqueo de step-up, etc.).

      cd backend
      TEST_DATABASE_URL=postgresql://postgres@localhost/auth_test pytest -q

- `backend/tests/e2e_browser.py`: recorrido completo en Chromium con autenticador virtual (enrolamiento por
  invitación, login, alta de usuario, step-up por passkey y por supervisor, recuperación).

## Pendiente (fase 3 y siguientes)

- **H9:** IP real detrás del proxy de Render (`X-Forwarded-For` con proxies de confianza); hoy el motor
  puede ver una IP interna. Revisar también el envío de IPs a ipapi.co (minimización de datos).
- **H11:** límite de intentos por IP y por cuenta en login. `/auth/login/failed` lo informa el cliente, así
  que un tercero puede inflar el contador de otra cuenta (solo provoca step-up, no da acceso).
- **H7:** dispositivo de confianza basado en la passkey usada en lugar del User-Agent.
- Tesis, no implementado aún: aprobación dual para cambios críticos del administrador, step-up previo a
  operaciones sensibles del admin, y la verificación continua de sesión (`session_reevaluation.py` existe
  pero no está conectado a la aplicación).
- Brecha con la tesis: la tesis describe Keycloak con OIDC/SAML (RF-05, RF-09); el prototipo es un backend
  propio con JWT.
