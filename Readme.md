# 🔐 Prototipo de Autenticación Passwordless con Evaluación de Riesgo Zero Trust

## 📋 Información del Proyecto

**Trabajo Final de Grado (TFG)**  
**Universidad:** Universidad Siglo 21  
**Carrera:** Licenciatura en Seguridad Informática  
**Alumno:** Zuy, Ariel Hernán  
**Legajo:** VLSI002384  
**Año:** 2025

---

> **Versión 2 (en desarrollo).** Esta rama corrige los hallazgos de la revisión de seguridad
> (`docs/REVISION_SEGURIDAD.md`): verificación WebAuthn real con py_webauthn, alta de usuarios por
> invitación, control de acceso por roles (Usuario / Auditor / Administrador), step-up por passkey,
> OTP o aprobación de supervisor, y rotación de refresh tokens. Detalle y configuración en
> `docs/CAMBIOS_V2.md`. El primer administrador se crea con `BOOTSTRAP_ADMIN_EMAIL` (ver `.env.example`).

---

## 🎯 Descripción

Sistema de autenticación sin contraseñas (passwordless) basado en el estándar FIDO2/WebAuthn, integrado con un motor de evaluación de riesgo continuo bajo el paradigma Zero Trust. El sistema implementa autenticación adaptativa (step-up) según el nivel de riesgo detectado y proporciona un panel de administración para gestionar políticas de seguridad.

### **Características Principales:**

✅ **Autenticación Passwordless:** Uso de Passkeys (FIDO2/WebAuthn)  
✅ **Evaluación de Riesgo Continua:** Motor que analiza múltiples factores en cada acceso  
✅ **Autenticación Adaptativa (Step-up):** Verificación adicional según nivel de riesgo  
✅ **Panel de Administración:** Gestión de políticas de acceso y umbrales de riesgo  
✅ **Auditoría Completa:** Registro de todos los eventos de seguridad  
✅ **Dashboard con Métricas:** Visualización de estadísticas en tiempo real  
✅ **Detección Geográfica:** Análisis de accesos desde ubicaciones inusuales  
✅ **Exportación de Reportes:** Auditoría en formato CSV/JSON  

---

## 🏗️ Arquitectura del Sistema

```
┌──────────────────────────────────────────────────────┐
│                  RENDER.COM (Cloud)                  │
│                                                      │
│  ┌────────────────────┐    ┌─────────────────────┐ │
│  │   Frontend (React) │───▶│  Backend (FastAPI)  │ │
│  │   Web Service      │    │   Web Service       │ │
│  │   Build: npm       │    │   Python 3.11       │ │
│  └────────────────────┘    └──────────┬──────────┘ │
│                                       │             │
│                            ┌──────────▼──────────┐  │
│                            │  PostgreSQL 17      │  │
│                            │  Managed Database   │  │
│                            │                     │  │
│                            │  • Usuarios         │  │
│                            │  • Passkeys         │  │
│                            │  • Políticas        │  │
│                            │  • Eventos          │  │
│                            └─────────────────────┘  │
└──────────────────────────────────────────────────────┘
                           │
                   ┌───────▼───────┐
                   │    GitHub     │
                   │   Repository  │
                   │  Auto-Deploy  │
                   └───────────────┘
```

---

## 🛠️ Tecnologías Utilizadas

### **Backend:**
- Python 3.11
- FastAPI
- SQLAlchemy (ORM)
- PostgreSQL 17
- WebAuthn (py_webauthn)
- JWT (python-jose)
- Uvicorn
- GeoIP2 (detección de ubicación)

### **Frontend:**
- React 18
- React Router v6
- Axios
- CSS3 moderno

### **Infraestructura:**
- **Hosting:** Render.com (Web Services + PostgreSQL)
- **Repositorio:** GitHub (auto-deploy)
- **SSL/TLS:** Certificados automáticos (Render)

---

## 🌐 Despliegue en Producción

El proyecto está configurado para desplegarse automáticamente en Render.com desde GitHub.

### **URLs de Producción:**

- **Aplicación Frontend:** [Tu URL en Render]
- **API Backend:** [Tu URL Backend en Render]
- **Documentación API (Swagger):** [Tu URL Backend]/docs
- **Base de Datos:** PostgreSQL 17 (administrada por Render)

### **Flujo de Despliegue:**

1. **Commit** → Push a GitHub (rama `main`)
2. **Render detecta cambios** → Inicia build automático
3. **Frontend:** `npm install` → `npm run build` → Deploy estático
4. **Backend:** `pip install -r requirements.txt` → `uvicorn app.main:app`
5. **PostgreSQL:** Base de datos persistente (sin reiniciar)

---

## 📦 Instalación Local (Desarrollo)

### **Requisitos Previos:**
- Python 3.11+
- Node.js 18+ y npm
- PostgreSQL 14+ (local o remoto)
- Navegador compatible con WebAuthn:
  - Chrome/Edge 67+
  - Firefox 60+
  - Safari 13+

### **1. Clonar el repositorio**

```bash
git clone <repository-url>
cd Prototipo_TFG
```

### **2. Configurar Backend**

```bash
cd backend

# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno (crear archivo .env)
# Ver sección "Variables de Entorno" más abajo

# Ejecutar servidor de desarrollo
python -m app.main
```

El backend estará disponible en: `http://localhost:8000`

### **3. Configurar Frontend**

```bash
cd frontend

# Instalar dependencias
npm install

# Configurar variables de entorno (crear archivo .env)
# REACT_APP_API_URL=http://localhost:8000

# Ejecutar servidor de desarrollo
npm start
```

El frontend estará disponible en: `http://localhost:3000`

---

## 🔑 Variables de Entorno

### **Backend (.env en /backend):**

```env
# Base de datos (ejemplo local)
DATABASE_URL=postgresql://usuario:password@localhost:5432/authdb

# JWT
JWT_SECRET_KEY=tu_clave_secreta_super_segura_cambiar_en_produccion
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=7

# CORS (ajustar según entorno)
ALLOWED_ORIGINS=http://localhost:3000,https://tu-frontend.onrender.com

# WebAuthn
RP_ID=localhost
RP_NAME=Prototipo Auth TFG
RP_ORIGIN=http://localhost:3000
```

### **Frontend (.env en /frontend):**

```env
# URL del backend
REACT_APP_API_URL=http://localhost:8000
```

**Nota:** En producción (Render), estas variables se configuran en el dashboard de Render, NO en archivos `.env`.

---

## 📂 Estructura del Proyecto

```
Prototipo_TFG/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # Punto de entrada FastAPI
│   │   ├── database.py          # Configuración DB
│   │   ├── models/              # Modelos SQLAlchemy
│   │   │   ├── user.py
│   │   │   ├── passkey.py
│   │   │   ├── policy.py
│   │   │   └── audit_event.py
│   │   ├── routers/             # Endpoints de la API
│   │   │   ├── auth.py
│   │   │   ├── admin.py
│   │   │   ├── audit.py
│   │   │   └── passkeys.py
│   │   ├── services/            # Lógica de negocio
│   │   │   ├── webauthn_service.py
│   │   │   ├── risk_engine.py
│   │   │   └── policy_engine.py
│   │   └── utils/               # Utilidades
│   └── requirements.txt         # Dependencias Python
│
└── frontend/
    ├── public/
    │   └── index.html
    ├── src/
    │   ├── components/          # Componentes React
    │   │   ├── EnrollPasskey.js
    │   │   ├── LoginPasswordless.js
    │   │   ├── Dashboard.js
    │   │   ├── AdminPanel.js
    │   │   ├── RiskMonitor.js
    │   │   ├── StepUpChallenge.js
    │   │   └── AuditReports.js
    │   ├── services/            # Cliente API
    │   │   ├── api.js
    │   │   └── webauthn.js
    │   ├── styles/              # Estilos CSS
    │   │   ├── App.css
    │   │   ├── Dashboard_styles.css
    │   │   └── RiskMonitor_styles.css
    │   ├── App.js               # Componente principal
    │   └── index.js             # Punto de entrada
    ├── package.json             # Dependencias Node
    └── package-lock.json
```

---

## 👤 Uso del Sistema

### **1. Registro de Usuario y Passkey**

**Ruta:** `/enroll`

1. Ingresar email del usuario
2. Hacer click en **"Registrar Passkey"**
3. El navegador solicitará autenticación biométrica:
   - **Windows Hello:** PIN, huella digital o reconocimiento facial
   - **macOS/iOS:** Touch ID o Face ID
   - **Android:** Huella digital o patrón
4. El sistema crea el usuario y registra la credencial FIDO2

### **2. Inicio de Sesión**

**Ruta:** `/login`

1. Ingresar email
2. Click en **"Iniciar Sesión con Passkey"**
3. Autenticar con biométrico
4. **Evaluación automática de riesgo:**
   - Analiza IP, geolocalización, horario, dispositivo
   - Calcula score de riesgo (0-100)
   - Aplica política de acceso correspondiente
5. **Posibles resultados:**
   - **Riesgo bajo (0-39):** Acceso directo al Dashboard ✅
   - **Riesgo medio (40-74):** Requiere Step-up Authentication ⚠️
   - **Riesgo alto (75-100):** Acceso denegado ❌

### **3. Dashboard del Usuario**

**Ruta:** `/dashboard`

**Pestañas disponibles:**

📊 **Mis Passkeys:**
- Ver todas las credenciales registradas
- Renombrar passkeys
- Revocar credenciales
- Estadísticas: activas, biométricas, hardware

📋 **Historial de Acceso:**
- Eventos de autenticación
- IP y ubicación geográfica
- Nivel de riesgo detectado
- Fecha y hora

📈 **Estadísticas del Sistema:**
- Total de autenticaciones
- Tasa de éxito
- Eventos por tipo
- Desglose de actividad

### **4. Panel de Administración**

**Ruta:** `/admin`

**Requiere:** Usuario con rol administrador

**Pestañas:**

🔒 **Políticas de Acceso:**
- Crear, editar, eliminar políticas
- Configurar condiciones:
  - Umbrales de riesgo (min/max)
  - Países permitidos/bloqueados
  - Horarios permitidos
- Definir acciones:
  - **Allow:** Permitir acceso
  - **Step-up:** Requerir verificación adicional
  - **Deny:** Denegar acceso
- Activar/desactivar políticas
- Ajustar prioridades

📊 **Auditoría y Reportes:**
- Visualización de eventos de seguridad
- Filtros por tipo, fecha, usuario
- Exportación en CSV/JSON
- Estadísticas consolidadas

---

## 📊 Casos de Uso Implementados

| ID | Caso de Uso | Estado | Descripción |
|----|-------------|--------|-------------|
| UC-01 | Enrolar Passkey | ✅ 100% | Registro de credencial FIDO2 con validación completa |
| UC-02 | Login Passwordless | ✅ 100% | Autenticación sin contraseña con evaluación de riesgo |
| UC-03 | Verificación Continua | ✅ 100% | Motor de riesgo analiza cada acceso en tiempo real |
| UC-04 | Step-up Authentication | ✅ 100% | Autenticación adaptativa por nivel de riesgo |
| UC-05 | Administrar Políticas | ✅ 100% | CRUD completo de políticas con condiciones avanzadas |
| UC-06 | Auditoría de Eventos | ✅ 100% | Registro completo con exportación CSV/JSON |
| UC-07 | Detección Geográfica | ✅ 100% | Análisis de ubicación y anomalías geográficas |
| UC-08 | Gestión de Passkeys | ✅ 100% | Renombrar y revocar credenciales |

---

## 🔐 Motor de Evaluación de Riesgo

### **Factores Analizados:**

| Factor | Peso | Descripción |
|--------|------|-------------|
| **Nueva ubicación geográfica** | 30 puntos | IP desde país/ciudad no vista antes |
| **Fuera del horario laboral** | 15 puntos | Acceso fuera de 9:00-18:00 |
| **Múltiples intentos fallidos** | 25 puntos | 3+ fallos en última hora |
| **Dispositivo no reconocido** | 20 puntos | User-Agent nuevo |
| **Velocidad imposible** | 35 puntos | Cambio geográfico físicamente imposible |
| **IP sospechosa** | 40 puntos | IP en lista negra o VPN/Proxy |

### **Políticas por Defecto:**

1. **high_risk_deny** (Prioridad 10)
   - Condición: Score ≥ 75
   - Acción: **DENY** (denegar acceso)

2. **medium_risk_stepup** (Prioridad 11)
   - Condición: 40 ≤ Score ≤ 74
   - Acción: **STEP-UP** (verificación adicional)

3. **low_risk_allow** (Prioridad 12)
   - Condición: Score ≤ 39
   - Acción: **ALLOW** (acceso directo)

4. **foreign_country_stepup** (Prioridad 1)
   - Condición: IP fuera de Argentina
   - Acción: **STEP-UP**

5. **outside_business_hours_stepup** (Prioridad 2)
   - Condición: Acceso fuera de horario laboral
   - Acción: **STEP-UP**

---

## 🧪 Testing y Pruebas

### **Probar Evaluación de Riesgo:**

1. **Riesgo Bajo:**
   - Login en horario laboral (9-18hs)
   - Desde ubicación conocida
   - Sin intentos fallidos previos
   - → Acceso directo ✅

2. **Riesgo Medio (Step-up):**
   - Login desde nueva ubicación geográfica
   - O fuera de horario laboral
   - O desde país diferente a Argentina
   - → Requiere verificación adicional ⚠️

3. **Riesgo Alto (Denegado):**
   - Múltiples intentos fallidos
   - Cambio geográfico imposible
   - IP en lista negra
   - → Acceso denegado ❌

### **Documentación API (Swagger):**

Disponible en: `[URL-Backend]/docs`

Todos los endpoints documentados con:
- Parámetros requeridos
- Esquemas de request/response
- Códigos de estado HTTP
- Ejemplos de uso

### **Endpoints Principales:**

#### **Autenticación:**
```
POST /auth/register/begin         # Iniciar registro de passkey
POST /auth/register/complete      # Completar registro
POST /auth/login/begin            # Iniciar login
POST /auth/login/complete         # Completar login + evaluación riesgo
POST /auth/stepup/verify          # Verificar step-up authentication
POST /auth/refresh                # Renovar tokens JWT
```

#### **Administración:**
```
GET    /admin/policies            # Listar todas las políticas
POST   /admin/policies            # Crear nueva política
PUT    /admin/policies/{id}       # Actualizar política
DELETE /admin/policies/{id}       # Eliminar política
PUT    /admin/policies/{id}/toggle # Activar/desactivar política
```

#### **Auditoría:**
```
GET /audit/events                 # Listar eventos de auditoría
GET /audit/stats                  # Estadísticas consolidadas
GET /audit/export                 # Exportar eventos (CSV/JSON)
```

#### **Passkeys:**
```
GET    /passkeys/{email}          # Listar passkeys del usuario
PUT    /passkeys/{id}/rename      # Renombrar passkey
DELETE /passkeys/{id}             # Revocar passkey
```

---

## 🐛 Troubleshooting

### **Error: Passkey no funciona**

**Posibles causas:**
- Navegador no soporta WebAuthn → Actualizar navegador
- No hay biométrico configurado → Configurar Windows Hello / Touch ID
- Dominio no es HTTPS → Solo funciona en localhost o HTTPS

**Solución:**
1. Verificar navegador compatible (Chrome 67+, Firefox 60+, Safari 13+)
2. Asegurar que el dispositivo tiene biométrico activo
3. Confirmar que la URL usa HTTPS o es localhost

### **Error: "CORS policy blocked"**

**Causa:** El backend no permite el origen del frontend.

**Solución:**
1. Verificar variable `ALLOWED_ORIGINS` en backend
2. Agregar la URL del frontend a la lista de orígenes permitidos
3. Reiniciar el backend

### **Error: Base de datos no conecta**

**Causa:** `DATABASE_URL` incorrecta o PostgreSQL no accesible.

**Solución:**
1. Verificar que PostgreSQL está corriendo
2. Confirmar credenciales en `DATABASE_URL`
3. Formato correcto: `postgresql://user:pass@host:5432/dbname`

### **Error 401: Token inválido**

**Causa:** Token JWT expirado o inválido.

**Solución:**
1. Cerrar sesión y volver a iniciar
2. Verificar que `JWT_SECRET_KEY` es la misma en backend
3. Los tokens expiran después de 60 minutos

---

## 🔒 Consideraciones de Seguridad

### **✅ Implementado:**
- Autenticación sin contraseñas (resistente a phishing)
- Claves criptográficas en hardware seguro (FIDO2)
- Tokens JWT con expiración
- CORS configurado
- Evaluación de riesgo en cada acceso
- Auditoría completa de eventos
- HTTPS obligatorio en producción (Render)
- Detección de anomalías geográficas
- Rate limiting en endpoints críticos

### **📋 Recomendaciones para Producción:**
- Usar `JWT_SECRET_KEY` largo y aleatorio (256+ bits)
- Configurar backup automático de PostgreSQL
- Implementar monitoreo y alertas (Sentry, New Relic)
- Revisar logs de auditoría periódicamente
- Actualizar dependencias regularmente
- Configurar límites de rate por IP
- Implementar honeypots para detectar bots

---

## 📖 Referencias

### **Estándares y Especificaciones:**
- **FIDO Alliance:** https://fidoalliance.org/
- **WebAuthn W3C Spec:** https://www.w3.org/TR/webauthn-2/
- **Zero Trust Architecture (NIST SP 800-207):** https://www.nist.gov/publications/zero-trust-architecture

### **Frameworks y Librerías:**
- **FastAPI Documentation:** https://fastapi.tiangolo.com/
- **React Documentation:** https://react.dev/
- **SQLAlchemy ORM:** https://www.sqlalchemy.org/
- **py_webauthn Library:** https://github.com/duo-labs/py_webauthn

### **Plataformas:**
- **Render.com Docs:** https://render.com/docs
- **PostgreSQL 17:** https://www.postgresql.org/docs/17/

---

## 📞 Contacto

**Autor:** Zuy, Ariel Hernán  
**Universidad:** Universidad Siglo 21  
**Carrera:** Licenciatura en Seguridad Informática  
**Legajo:** VLSI002384  
**Año:** 2025  

---

## 📄 Licencia

Este proyecto es un Trabajo Final de Grado desarrollado con fines académicos y de investigación para la Universidad Siglo 21.

---

## ✅ Checklist de Verificación

### **Instalación Local:**
- [ ] Python 3.11+ instalado
- [ ] Node.js 18+ y npm instalados
- [ ] PostgreSQL 14+ corriendo
- [ ] Variables de entorno configuradas (.env)
- [ ] Backend corriendo en `http://localhost:8000`
- [ ] Frontend corriendo en `http://localhost:3000`
- [ ] Swagger docs accesible en `/docs`

### **Funcionalidad:**
- [ ] Registro de passkey funciona
- [ ] Login con passkey exitoso
- [ ] Evaluación de riesgo calculada correctamente
- [ ] Step-up authentication se dispara cuando corresponde
- [ ] Dashboard muestra información del usuario
- [ ] Panel de administración accesible
- [ ] Políticas de acceso se pueden crear/editar
- [ ] Auditoría registra eventos correctamente
- [ ] Exportación de reportes funciona

---

**🎉 Sistema listo para demostración y entrega final del TFG**

---

## 🚀 Próximos Pasos (Mejoras Futuras)

- [ ] Implementar notificaciones por email en eventos críticos
- [ ] Agregar soporte para múltiples factores (TOTP, SMS)
- [ ] Dashboard con gráficos interactivos (Chart.js)
- [ ] Integración con SIEM (Splunk, ELK)
- [ ] Machine Learning para detección de anomalías
- [ ] Soporte para WebAuthn nivel 3 (conditional UI)
- [ ] App móvil nativa (React Native)
