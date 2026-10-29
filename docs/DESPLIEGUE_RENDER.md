# Despliegue en Render

El `render.yaml` crea tres recursos nuevos:

| Recurso | Nombre | Plan | Por qué |
|---|---|---|---|
| Backend (FastAPI) | `zuy-tfg-passkeys-api` | `0.5c-512mb` (pago) | El gratuito se apaga a los 15 min sin tráfico y tarda ~1 min en volver |
| Frontend (React) | `zuy-tfg-passkeys` | Sitio estático (gratis) | Se sirve directo, no se apaga |
| Base de datos | `auth-postgres` | `0.1c-256mb` (pago) | La gratuita vence a los 30 días y se borra |

Todo queda en la región `virginia`, la más cercana a Argentina entre las de Render. La región no se puede cambiar después de crear los recursos.

Los servicios de la versión original siguen funcionando aparte. Si el link de la tesis apunta a ellos, decidí si los suspendés o los dejás como están.

## 1. Crear el Blueprint

1. En el dashboard de Render: **New → Blueprint**.
2. Elegí el repositorio `Prototipo_TFG_Passkeys_v2` (Render tiene que tener acceso a GitHub).
3. Render muestra los tres recursos. Te pide el valor de `BOOTSTRAP_ADMIN_EMAIL`: poné el email con el que vas a ser administrador.
4. **Apply**. El primer build tarda unos minutos.

## 2. Confirmar las URLs

Cuando termine, verificá que las URLs sean exactamente:

- Frontend: `https://zuy-tfg-passkeys.onrender.com`
- Backend: `https://zuy-tfg-passkeys-api.onrender.com`

Si Render asignó otra (por ejemplo, con un sufijo porque el nombre estaba tomado), hay que actualizar `RP_ID`, `ORIGIN` y `REACT_APP_API_URL` en `render.yaml` y volver a desplegar. **Hacelo antes de enrolar passkeys**: quedan atadas al dominio.

Prueba rápida: `https://zuy-tfg-passkeys-api.onrender.com/health` tiene que responder `{"status":"healthy","database":"connected"}`.

## 3. Enrolar al administrador

1. En el backend, pestaña **Logs**, buscá el bloque *Invitación de administrador inicial*. Tiene un link `https://zuy-tfg-passkeys.onrender.com/enroll?invite=...`
2. Abrilo en el dispositivo que vas a usar en la defensa y enrolá la passkey (Windows Hello, Touch ID o el celular).
3. Recomendado: con la sesión iniciada, agregá una segunda passkey desde otro dispositivo (Mis Passkeys → Agregar). Es tu respaldo si uno falla.

Si el link vence (72 h) o se reinicia el servicio antes de usarlo, cada arranque genera uno nuevo mientras el admin no haya enrolado.

## 4. Calibrar la IP del cliente

Panel Admin → Usuarios y Aprobaciones → **Diagnóstico de red**.

- *IP detectada* tiene que ser tu IP pública (comparala con cualquier sitio de "cuál es mi IP").
- En Render el valor correcto resultó ser `2`: Cloudflare está delante del proxy de Render, así que la IP del cliente es la penúltima de `X-Forwarded-For`. Con `1` se ve una IP de Cloudflare (por ejemplo `162.158.x.x`).
- Si aparece una IP interna (10.x, 172.16–31.x) o de Cloudflare, ajustá `TRUSTED_PROXY_HOPS` y volvé a desplegar.

Si queda mal, el sistema no se rompe: ve una ubicación desconocida y pide step-up más seguido.

## 5. Preparar la demo

- Creá desde el panel los usuarios que vas a mostrar (por ejemplo, uno estándar y un auditor) y enrolalos en otro navegador o perfil.
- Probá una vez cada flujo: login, step-up por passkey, aprobación por supervisor, recuperación.
- El día de la defensa abrí la app unos minutos antes para verificar que responde.

## Problemas frecuentes

| Síntoma | Causa | Solución |
|---|---|---|
| "El dominio no coincide con el configurado (RP ID)" al enrolar | `RP_ID` no es el dominio del frontend | Corregir `RP_ID` (sin `https://`) |
| Error de CORS en la consola del navegador | `ORIGIN` distinto de la URL del frontend | Corregir `ORIGIN` (con `https://`, sin barra final) |
| El link de invitación apunta a otro dominio | `ORIGIN` o `FRONTEND_URL` mal | Corregir y reemitir la invitación |
| Falla el build del backend | Versión de Python | `.python-version` fija 3.13; Render ignora `runtime.txt` |
| El frontend llama a una URL vieja | `REACT_APP_API_URL` se fija al compilar | Corregirla y redesplegar el frontend |
