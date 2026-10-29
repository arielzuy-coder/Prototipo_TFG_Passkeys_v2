from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, func, text
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
from typing import Optional
import logging
import secrets
import random
from pydantic import BaseModel
import user_agents

from config import settings
from models import Base, User, Passkey, Device, Session as DBSession, AuditEvent, Policy, RiskEvaluation
from auth.webauthn_handler import WebAuthnHandler
from auth.token_manager import TokenManager
from auth.session_manager import SessionManager
from risk.risk_engine import RiskEngine
from risk.policies import PolicyEngine

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear FastAPI app
app = FastAPI(
    title="Prototipo Autenticación Passkeys + Zero Trust",
    description="Sistema de autenticación passwordless con evaluación de riesgo contextual",
    version="1.0.0"
)

# CORS - Configuración para desarrollo y producción
import os
allowed_origins = [
    settings.ORIGIN,
    "http://localhost:3000",
    "https://localhost:3000",
]

# En producción, agregar dominios de Render
if "onrender.com" in settings.ORIGIN:
    # Permitir todas las URLs de Render del proyecto
    allowed_origins.extend([
        "https://auth-frontend.onrender.com",
        "https://auth-frontend-*.onrender.com",
    ])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_origin_regex=r"https://.*\.onrender\.com",  # Permitir cualquier subdominio de Render
)

# Database
engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency para obtener DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Inicializar componentes
webauthn_handler = WebAuthnHandler()
token_manager = TokenManager()
session_manager = SessionManager()
risk_engine = RiskEngine()
policy_engine = PolicyEngine()

# Almacenamiento temporal para step-up (en producción usar Redis)
stepup_tokens = {}  # {token: {user_id, email, expires_at, session_data, otp}}

# ============================================
# MODELOS PYDANTIC PARA REQUEST BODIES
# ============================================

class RegisterBeginRequest(BaseModel):
    email: str

class RegisterCompleteRequest(BaseModel):
    email: str
    credential: dict
    device_name: Optional[str] = None

class LoginBeginRequest(BaseModel):
    email: str

class LoginCompleteRequest(BaseModel):
    email: str
    credential: dict

class LoginFailedRequest(BaseModel):
    email: str
    reason: str
    error_message: Optional[str] = None

class StepUpVerifyRequest(BaseModel):
    stepup_token: str
    verification_type: str  # 'biometric', 'otp', 'pin'
    verification_data: Optional[dict] = None

class PolicyCreateRequest(BaseModel):
    name: str
    description: str
    conditions: dict
    action: str  # 'allow', 'stepup', 'deny'
    priority: int
    enabled: bool = True

class PolicyUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    conditions: Optional[dict] = None
    action: Optional[str] = None
    priority: Optional[int] = None
    enabled: Optional[bool] = None

# ============================================
# ENDPOINTS DE SALUD Y INFO
# ============================================

@app.get("/")
async def root():
    return {
        "message": "Prototipo Autenticación Passkeys + Zero Trust",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "error": str(e)}
        )

# ============================================
# ENDPOINTS DE REGISTRO (ENROLAMIENTO)
# ============================================

@app.post("/auth/register/begin")
async def register_begin(
    request: Request,
    data: RegisterBeginRequest,
    db: Session = Depends(get_db)
):
    """Inicia el proceso de enrolamiento de Passkeys."""
    try:
        email = data.email
        
        user = db.query(User).filter(User.email == email).first()
        
        if not user:
            user = User(email=email, display_name=email.split('@')[0])
            db.add(user)
            db.commit()
            db.refresh(user)
            
            audit = AuditEvent(
                user_id=user.id,
                event_type="user_created",
                event_data={"email": email},
                ip_address=request.client.host
            )
            db.add(audit)
            db.commit()
        
        registration_options = webauthn_handler.generate_registration_options(
            user_id=str(user.id),
            username=user.email,
            display_name=user.display_name
        )
        
        return registration_options
        
    except Exception as e:
        logger.error(f"Error in register_begin: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.post("/auth/register/complete")
async def register_complete(
    request: Request,
    data: RegisterCompleteRequest,
    db: Session = Depends(get_db)
):
    """Completa el enrolamiento de Passkeys."""
    try:
        email = data.email
        credential = data.credential
        device_name = data.device_name
        
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
        
        verified_credential = webauthn_handler.verify_registration(
            credential=credential,
            expected_challenge=credential.get('challenge'),
            expected_origin=settings.ORIGIN,
            expected_rp_id=settings.RP_ID
        )
        
        # Crear Passkey
        passkey = Passkey(
            user_id=user.id,
            credential_id=verified_credential['credential_id'],
            public_key=verified_credential['public_key'],
            attestation_fmt=verified_credential.get('fmt', 'none'),
            aaguid=verified_credential.get('aaguid'),
            counter=verified_credential.get('counter', 0),
            device_name=device_name or "Dispositivo sin nombre",
            device_type=verified_credential.get('device_type', 'platform')
        )
        
        db.add(passkey)
        db.commit()
        
        # NUEVO: Crear Device asociado
        ua = user_agents.parse(request.headers.get('user-agent', ''))
        user_agent_str = request.headers.get('user-agent', '')
        
        # Usar la misma fórmula de fingerprint que risk_engine.py
        device_fingerprint = f"{ua.browser.family}_{ua.os.family}_{user_agent_str[:50]}"
        
        # Verificar si el dispositivo ya existe
        existing_device = db.query(Device).filter(
            Device.device_fingerprint == device_fingerprint
        ).first()
        
        if not existing_device:
            # Crear nuevo dispositivo
            device = Device(
                user_id=user.id,
                device_fingerprint=device_fingerprint,
                device_name=device_name or "Dispositivo sin nombre",
                os=ua.os.family,
                browser=ua.browser.family,
                trust_level=50,
                last_seen_ip=request.client.host,
                last_seen_location=f"IP: {request.client.host}"
            )
            db.add(device)
            db.commit()
            logger.info(f"Device created for user {email}: {device_fingerprint}")
        else:
            # Actualizar dispositivo existente
            existing_device.last_seen_at = datetime.utcnow()
            existing_device.last_seen_ip = request.client.host
            db.commit()
            logger.info(f"Device updated for user {email}: {device_fingerprint}")
        
        # Auditoría
        audit = AuditEvent(
            user_id=user.id,
            event_type="passkey_enrolled",
            event_data={
                "credential_id": verified_credential['credential_id'][:20] + "...",
                "device_name": device_name,
                "device_type": verified_credential.get('device_type')
            },
            ip_address=request.client.host
        )
        db.add(audit)
        db.commit()
        
        return {
            "success": True,
            "message": "Passkey enrolada exitosamente",
            "credential_id": verified_credential['credential_id']
        }
        
    except Exception as e:
        logger.error(f"Error in register_complete: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error al verificar credencial: {str(e)}"
        )
# ============================================
# ENDPOINTS DE AUTENTICACIÓN
# ============================================

@app.post("/auth/login/begin")
async def login_begin(
    request: Request,
    data: LoginBeginRequest,
    db: Session = Depends(get_db)
):
    """Inicia el proceso de autenticación passwordless."""
    try:
        email = data.email
        
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
        
        if user.status != 'active':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Usuario suspendido o deshabilitado"
            )
        
        passkeys = db.query(Passkey).filter(Passkey.user_id == user.id).all()
        
        if not passkeys:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No hay Passkeys registradas para este usuario"
            )
        
        authentication_options = webauthn_handler.generate_authentication_options(
            user_id=str(user.id),
            credentials=[pk.credential_id for pk in passkeys]
        )
        
        return authentication_options
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in login_begin: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.post("/auth/login/complete")
async def login_complete(
    request: Request,
    data: LoginCompleteRequest,
    db: Session = Depends(get_db)
):
    """Completa la autenticación passwordless."""
    try:
        email = data.email
        credential = data.credential
        
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
        
        credential_id = credential.get('id')
        passkey = db.query(Passkey).filter(
            Passkey.credential_id == credential_id,
            Passkey.user_id == user.id
        ).first()
        
        if not passkey:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credencial no encontrada"
            )
        
        verified = webauthn_handler.verify_authentication(
            credential=credential,
            expected_challenge=credential.get('challenge'),
            public_key=passkey.public_key,
            expected_origin=settings.ORIGIN,
            expected_rp_id=settings.RP_ID,
            current_counter=passkey.counter
        )
        
        if not verified['verified']:
            audit = AuditEvent(
                user_id=user.id,
                event_type="auth_failed",
                event_data={"reason": "assertion_verification_failed"},
                ip_address=request.client.host
            )
            db.add(audit)
            db.commit()
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Verificación de credencial fallida"
            )
        
        passkey.counter = verified['new_counter']
        passkey.last_used_at = datetime.utcnow()
        db.commit()
        
        # Evaluación de riesgo (Zero Trust)
        user_agent = request.headers.get('user-agent', '')
        ip_address = request.client.host
        
        risk_assessment = risk_engine.evaluate_risk(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            db=db
        )
        
        policy_decision = policy_engine.evaluate_policies(
            user=user,
            risk_score=risk_assessment['score'],
            context=risk_assessment['context'],
            db=db
        )
        
        if policy_decision['action'] == 'deny':
            audit = AuditEvent(
                user_id=user.id,
                event_type="access_denied",
                event_data={
                    "reason": "risk_too_high",
                    "risk_score": float(risk_assessment['score']),
                    "policy": policy_decision['policy_name']
                },
                ip_address=ip_address,
                user_agent=user_agent
            )
            db.add(audit)
            db.commit()
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "message": "Acceso denegado por política de seguridad",
                    "risk_score": float(risk_assessment['score']),
                    "factors": risk_assessment['factors'],
                    "requires_admin_approval": True
                }
            )
        
        # Manejar Step-up Authentication
        if policy_decision['action'] == 'stepup':
            # Generar token temporal de step-up (válido 15 minutos)
            stepup_token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(minutes=15)
            
            # Generar OTP de 6 dígitos
            otp_code = f"{random.randint(100000, 999999)}"
            
            # Guardar en memoria temporal
            stepup_tokens[stepup_token] = {
                'user_id': user.id,
                'email': user.email,
                'expires_at': expires_at,
                'otp': otp_code,
                'session_data': {
                    'ip_address': ip_address,
                    'user_agent': user_agent,
                    'location': risk_assessment['context'].get('location'),
                    'risk_score': risk_assessment['score'],
                    'credential_id': credential_id
                }
            }
            
            # Registrar solicitud de step-up
            audit = AuditEvent(
                user_id=user.id,
                event_type="stepup_requested",
                event_data={
                    "risk_score": float(risk_assessment['score']),
                    "policy": policy_decision['policy_name'],
                    "factors": risk_assessment['factors']
                },
                ip_address=ip_address,
                user_agent=user_agent
            )
            db.add(audit)
            db.commit()
            
            logger.info(f"Step-up requested for user {user.email}. OTP: {otp_code}")
            
            response = {
                "success": True,
                "requires_stepup": True,
                "stepup_token": stepup_token,
                "expires_at": expires_at.isoformat(),
                "verification_methods": ["biometric", "otp", "pin"],
                "otp_code": otp_code,  # En producción, enviar por email/SMS
                "risk_assessment": {
                    "score": float(risk_assessment['score']),
                    "level": risk_assessment['level'],
                    "factors": risk_assessment['factors']
                },
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "display_name": user.display_name
                }
            }
            
            return response
        
        # Flujo normal (allow) - crear sesión y emitir tokens
        session = session_manager.create_session(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            location=risk_assessment['context'].get('location'),
            risk_score=risk_assessment['score'],
            db=db
        )
        
        # NUEVO: Actualizar dispositivo conocido después del login exitoso
        ua_login = user_agents.parse(user_agent)
        device_fingerprint_login = f"{ua_login.browser.family}_{ua_login.os.family}_{user_agent[:50]}"
        
        existing_device = db.query(Device).filter(
            Device.device_fingerprint == device_fingerprint_login,
            Device.user_id == user.id
        ).first()
        
        if existing_device:
            existing_device.last_seen_at = datetime.utcnow()
            existing_device.last_seen_ip = ip_address
            existing_device.last_seen_location = risk_assessment['context'].get('location')
            db.commit()
            logger.info(f"Device updated after login for user {user.email}: {device_fingerprint_login}")
        
        risk_eval = RiskEvaluation(
            session_id=session.id,
            user_id=user.id,
            risk_score=risk_assessment['score'],
            factors=risk_assessment['factors'],
            decision=policy_decision['action']
        )
        db.add(risk_eval)
        
        audit = AuditEvent(
            user_id=user.id,
            session_id=session.id,
            event_type="auth_success",
            event_data={
                "risk_score": float(risk_assessment['score']),
                "decision": policy_decision['action'],
                "credential_id": credential_id[:20] + "..."
            },
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.add(audit)
        db.commit()
        
        tokens = token_manager.create_tokens(
            user_id=str(user.id),
            email=user.email,
            session_id=str(session.id),
            risk_score=float(risk_assessment['score'])
        )
        
        response = {
            "success": True,
            "requires_stepup": False,
            "risk_assessment": {
                "score": float(risk_assessment['score']),
                "level": risk_assessment['level'],
                "factors": risk_assessment['factors']
            },
            "tokens": tokens,
            "user": {
                "id": str(user.id),
                "email": user.email,
                "display_name": user.display_name
            }
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in login_complete: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.post("/auth/login/failed")
async def login_failed(
    request: Request,
    data: LoginFailedRequest,
    db: Session = Depends(get_db)
):
    """Registra intentos de autenticación fallidos."""
    try:
        user = db.query(User).filter(User.email == data.email).first()
        
        if user:
            # Registrar evento de autenticación fallida
            audit = AuditEvent(
                user_id=user.id,
                event_type="auth_failed",
                event_data={
                    "reason": data.reason,
                    "error_message": data.error_message
                },
                ip_address=request.client.host,
                user_agent=request.headers.get('user-agent', '')
            )
            db.add(audit)
            db.commit()
            
            logger.info(f"Autenticación fallida registrada para usuario {data.email}: {data.reason}")
        
        return {
            "success": True,
            "message": "Fallo de autenticación registrado"
        }
        
    except Exception as e:
        logger.error(f"Error al registrar fallo de autenticación: {e}")
        # No lanzamos excepción para no interrumpir el flujo del usuario
        return {
            "success": False,
            "message": "Error al registrar fallo"
        }
@app.post("/auth/stepup/verify")
async def stepup_verify(
    request: Request,
    data: StepUpVerifyRequest,
    db: Session = Depends(get_db)
):
    """Verifica el desafío adicional de step-up authentication."""
    try:
        stepup_token = data.stepup_token
        
        # Verificar que el token existe
        if stepup_token not in stepup_tokens:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de step-up inválido o expirado"
            )
        
        token_data = stepup_tokens[stepup_token]
        
        # Verificar expiración
        if datetime.utcnow() > token_data['expires_at']:
            del stepup_tokens[stepup_token]
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de step-up expirado"
            )
        
        # Obtener usuario
        user = db.query(User).filter(User.id == token_data['user_id']).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
        
        # Verificar según el tipo de verificación
        verification_valid = False
        
        if data.verification_type == 'otp':
            # Verificar OTP
            provided_otp = data.verification_data.get('otp') if data.verification_data else None
            if provided_otp == token_data['otp']:
                verification_valid = True
        
        elif data.verification_type == 'biometric':
            # Para biometría, asumir que WebAuthn ya validó
            # En un caso real, aquí se verificaría otra passkey o biometría adicional
            verification_valid = True
        
        elif data.verification_type == 'pin':
            # Verificar PIN (en este prototipo, cualquier PIN de 4-6 dígitos)
            provided_pin = data.verification_data.get('pin') if data.verification_data else None
            if provided_pin and len(str(provided_pin)) >= 4:
                verification_valid = True
        
        if not verification_valid:
            # Registrar fallo
            audit = AuditEvent(
                user_id=user.id,
                event_type="stepup_failed",
                event_data={
                    "verification_type": data.verification_type,
                    "reason": "verification_failed"
                },
                ip_address=request.client.host,
                user_agent=request.headers.get('user-agent', '')
            )
            db.add(audit)
            db.commit()
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Verificación adicional fallida"
            )
        
        # Verificación exitosa - crear sesión y emitir tokens
        session_data = token_data['session_data']
        
        session = session_manager.create_session(
            user_id=user.id,
            ip_address=session_data['ip_address'],
            user_agent=session_data['user_agent'],
            location=session_data.get('location'),
            risk_score=session_data['risk_score'],
            db=db
        )
        
        # NUEVO: Actualizar dispositivo conocido después del step-up exitoso
        ua_login = user_agents.parse(session_data['user_agent'])
        device_fingerprint_login = f"{ua_login.browser.family}_{ua_login.os.family}_{session_data['user_agent'][:50]}"
        
        logger.info(f"[STEPUP] Buscando device con fingerprint: {device_fingerprint_login} y user_id: {user.id}")
        
        existing_device = db.query(Device).filter(
            Device.device_fingerprint == device_fingerprint_login
        ).first()
        
        if existing_device:
            existing_device.last_seen_at = datetime.utcnow()
            existing_device.last_seen_ip = session_data['ip_address']
            existing_device.last_seen_location = session_data.get('location')
            existing_device.user_id = user.id
            db.commit()
            logger.info(f"Device updated after step-up for user {user.email}: {device_fingerprint_login}")
        else:
            logger.info(f"[STEPUP] ❌ Device NO encontrado para user {user.email} con fingerprint: {device_fingerprint_login}")
        
        # Registrar éxito de step-up
        audit = AuditEvent(
            user_id=user.id,
            session_id=session.id,
            event_type="stepup_success",
            event_data={
                "verification_type": data.verification_type,
                "risk_score": float(session_data['risk_score'])
            },
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent', '')
        )
        db.add(audit)
        db.commit()
        
        # Emitir tokens
        tokens = token_manager.create_tokens(
            user_id=str(user.id),
            email=user.email,
            session_id=str(session.id),
            risk_score=float(session_data['risk_score'])
        )
        
        # Limpiar token usado
        del stepup_tokens[stepup_token]
        
        logger.info(f"Step-up verification successful for user {user.email}")
        # Registrar autenticación exitosa
        audit_success = AuditEvent(
             user_id=user.id,
            session_id=session.id,
            event_type="authentication_success",
            event_data={
                "location": session_data.get('location'),
                "risk_score": float(session_data['risk_score'])
            },
            ip_address=session_data['ip_address'],
            user_agent=session_data['user_agent']
        )
        db.add(audit_success)
        db.commit()
        return {
            "success": True,
            "message": "Verificación adicional exitosa",
            "tokens": tokens,
            "user": {
                "id": str(user.id),
                "email": user.email,
                "display_name": user.display_name
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in stepup_verify: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

# ============================================
# ENDPOINTS DE GESTIÓN DE PASSKEYS
# ============================================

@app.get("/passkeys/{user_email}")
async def list_passkeys(
    user_email: str,
    db: Session = Depends(get_db)
):
    """Lista todas las Passkeys de un usuario."""
    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    passkeys = db.query(Passkey).filter(Passkey.user_id == user.id).all()
    
    return {
        "user_email": user.email,
        "passkeys": [
            {
                "id": str(pk.id),
                "device_name": pk.device_name,
                "device_type": pk.device_type,
                "created_at": pk.created_at.isoformat(),
                "last_used_at": pk.last_used_at.isoformat() if pk.last_used_at else None
            }
            for pk in passkeys
        ]
    }

@app.delete("/passkeys/{passkey_id}")
async def revoke_passkey(
    passkey_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """Revoca (elimina) una Passkey específica."""
    passkey = db.query(Passkey).filter(Passkey.id == passkey_id).first()
    if not passkey:
        raise HTTPException(status_code=404, detail="Passkey no encontrada")
    
    user_id = passkey.user_id
    credential_id = passkey.credential_id
    
    db.delete(passkey)
    
    audit = AuditEvent(
        user_id=user_id,
        event_type="passkey_revoked",
        event_data={"credential_id": credential_id[:20] + "..."},
        ip_address=request.client.host
    )
    db.add(audit)
    db.commit()
    
    return {"success": True, "message": "Passkey revocada exitosamente"}

# ============================================
# ENDPOINTS DE AUDITORÍA
# ============================================

@app.get("/audit/events")
async def get_audit_events(
    user_email: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Obtiene eventos de auditoría con filtros opcionales."""
    query = db.query(AuditEvent)
    
    if user_email:
        user = db.query(User).filter(User.email == user_email).first()
        if user:
            query = query.filter(AuditEvent.user_id == user.id)
    
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    
    events = query.order_by(AuditEvent.timestamp.desc()).limit(limit).all()
    
    return {
        "total": len(events),
        "events": [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "timestamp": e.timestamp.isoformat(),
                "ip_address": e.ip_address,
                "event_data": e.event_data
            }
            for e in events
        ]
    }

@app.get("/audit/stats")
async def get_audit_stats(db: Session = Depends(get_db)):
    """Estadísticas agregadas de eventos de auditoría."""
    
    events_by_type = db.query(
        AuditEvent.event_type,
        func.count(AuditEvent.id).label('count')
    ).group_by(AuditEvent.event_type).all()
    
    auth_success = db.query(func.count(AuditEvent.id)).filter(
        AuditEvent.event_type == 'auth_success'
    ).scalar()
    
    auth_failed = db.query(func.count(AuditEvent.id)).filter(
        AuditEvent.event_type == 'auth_failed'
    ).scalar()
    
    return {
        "events_by_type": {et: count for et, count in events_by_type},
        "authentication": {
            "success": auth_success,
            "failed": auth_failed,
            "success_rate": f"{(auth_success / (auth_success + auth_failed) * 100):.2f}%" if (auth_success + auth_failed) > 0 else "0%"
        }
    }

# ============================================
# ENDPOINTS DE MÉTRICAS DE RIESGO
# ============================================

@app.get("/risk/dashboard")
async def risk_dashboard(db: Session = Depends(get_db)):
    """Dashboard con métricas de riesgo en tiempo real."""
    
    risk_distribution = db.query(
        func.count(RiskEvaluation.id).label('count'),
        func.avg(RiskEvaluation.risk_score).label('avg_score')
    ).filter(
        RiskEvaluation.evaluated_at >= datetime.utcnow() - timedelta(days=7)
    ).first()
    
    decisions = db.query(
        RiskEvaluation.decision,
        func.count(RiskEvaluation.id).label('count')
    ).group_by(RiskEvaluation.decision).all()
    
    high_risk_users = db.query(
        User.email,
        func.avg(RiskEvaluation.risk_score).label('avg_risk')
    ).join(RiskEvaluation, User.id == RiskEvaluation.user_id) \
     .group_by(User.email) \
     .order_by(func.avg(RiskEvaluation.risk_score).desc()) \
     .limit(10).all()
    
    return {
        "summary": {
            "total_evaluations": risk_distribution.count if risk_distribution else 0,
            "average_risk_score": float(risk_distribution.avg_score) if risk_distribution and risk_distribution.avg_score else 0
        },
        "decisions": {decision: count for decision, count in decisions},
        "high_risk_users": [
            {"email": email, "avg_risk": float(avg_risk)}
            for email, avg_risk in high_risk_users
        ]
    }
# ============================================
# ENDPOINTS DE ADMINISTRACIÓN DE POLÍTICAS
# ============================================

@app.get("/admin/policies")
async def list_policies(db: Session = Depends(get_db)):
    """Lista todas las políticas configuradas."""
    try:
        policies = db.query(Policy).order_by(Policy.priority.asc()).all()
        
        return {
            "total": len(policies),
            "policies": [
                {
                    "id": str(p.id),
                    "name": p.name,
                    "description": p.description,
                    "conditions": p.conditions,
                    "action": p.action,
                    "priority": p.priority,
                    "enabled": p.enabled,
                    "created_at": p.created_at.isoformat(),
                    "updated_at": p.updated_at.isoformat() if p.updated_at else None
                }
                for p in policies
            ]
        }
    except Exception as e:
        logger.error(f"Error listing policies: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.get("/admin/policies/{policy_id}")
async def get_policy(policy_id: str, db: Session = Depends(get_db)):
    """Obtiene una política específica por ID."""
    try:
        policy = db.query(Policy).filter(Policy.id == policy_id).first()
        
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Política no encontrada"
            )
        
        return {
            "id": str(policy.id),
            "name": policy.name,
            "description": policy.description,
            "conditions": policy.conditions,
            "action": policy.action,
            "priority": policy.priority,
            "enabled": policy.enabled,
            "created_at": policy.created_at.isoformat(),
            "updated_at": policy.updated_at.isoformat() if policy.updated_at else None
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting policy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.post("/admin/policies")
async def create_policy(
    request: Request,
    data: PolicyCreateRequest,
    db: Session = Depends(get_db)
):
    """Crea una nueva política de acceso."""
    try:
        # Validar que no exista una política con el mismo nombre
        existing = db.query(Policy).filter(Policy.name == data.name).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Ya existe una política con el nombre '{data.name}'"
            )
        
        # Validar acción
        if data.action not in ['allow', 'stepup', 'deny']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La acción debe ser 'allow', 'stepup' o 'deny'"
            )
        
        # Crear política
        policy = policy_engine.create_custom_policy(
            name=data.name,
            description=data.description,
            conditions=data.conditions,
            action=data.action,
            priority=data.priority,
            db=db
        )
        
        # Registrar en auditoría
        audit = AuditEvent(
            event_type="policy_created",
            event_data={
                "policy_id": str(policy.id),
                "policy_name": policy.name,
                "action": policy.action
            },
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent', '')
        )
        db.add(audit)
        db.commit()
        
        logger.info(f"Policy created: {policy.name}")
        
        return {
            "success": True,
            "message": "Política creada exitosamente",
            "policy": {
                "id": str(policy.id),
                "name": policy.name,
                "description": policy.description,
                "conditions": policy.conditions,
                "action": policy.action,
                "priority": policy.priority,
                "enabled": policy.enabled
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating policy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.put("/admin/policies/{policy_id}")
async def update_policy(
    policy_id: str,
    request: Request,
    data: PolicyUpdateRequest,
    db: Session = Depends(get_db)
):
    """Actualiza una política existente."""
    try:
        policy = db.query(Policy).filter(Policy.id == policy_id).first()
        
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Política no encontrada"
            )
        
        # Actualizar campos proporcionados
        updates = data.dict(exclude_unset=True)
        
        # Validar acción si se proporciona
        if 'action' in updates and updates['action'] not in ['allow', 'stepup', 'deny']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La acción debe ser 'allow', 'stepup' o 'deny'"
            )
        
        for key, value in updates.items():
            setattr(policy, key, value)
        
        policy.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(policy)
        
        # Registrar en auditoría
        audit = AuditEvent(
            event_type="policy_updated",
            event_data={
                "policy_id": str(policy.id),
                "policy_name": policy.name,
                "updates": updates
            },
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent', '')
        )
        db.add(audit)
        db.commit()
        
        logger.info(f"Policy updated: {policy.name}")
        
        return {
            "success": True,
            "message": "Política actualizada exitosamente",
            "policy": {
                "id": str(policy.id),
                "name": policy.name,
                "description": policy.description,
                "conditions": policy.conditions,
                "action": policy.action,
                "priority": policy.priority,
                "enabled": policy.enabled
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating policy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.delete("/admin/policies/{policy_id}")
async def delete_policy(
    policy_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """Elimina una política."""
    try:
        policy = db.query(Policy).filter(Policy.id == policy_id).first()
        
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Política no encontrada"
            )
        
        policy_name = policy.name
        
        db.delete(policy)
        db.commit()
        
        # Registrar en auditoría
        audit = AuditEvent(
            event_type="policy_deleted",
            event_data={
                "policy_id": str(policy_id),
                "policy_name": policy_name
            },
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent', '')
        )
        db.add(audit)
        db.commit()
        
        logger.info(f"Policy deleted: {policy_name}")
        
        return {
            "success": True,
            "message": "Política eliminada exitosamente"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting policy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.put("/admin/policies/{policy_id}/toggle")
async def toggle_policy(
    policy_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """Activa o desactiva una política."""
    try:
        policy = db.query(Policy).filter(Policy.id == policy_id).first()
        
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Política no encontrada"
            )
        
        # Toggle enabled
        policy.enabled = not policy.enabled
        policy.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(policy)
        
        # Registrar en auditoría
        audit = AuditEvent(
            event_type="policy_toggled",
            event_data={
                "policy_id": str(policy.id),
                "policy_name": policy.name,
                "enabled": policy.enabled
            },
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent', '')
        )
        db.add(audit)
        db.commit()
        
        logger.info(f"Policy {'enabled' if policy.enabled else 'disabled'}: {policy.name}")
        
        return {
            "success": True,
            "message": f"Política {'activada' if policy.enabled else 'desactivada'} exitosamente",
            "policy": {
                "id": str(policy.id),
                "name": policy.name,
                "enabled": policy.enabled
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling policy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

# ============================================
# MANEJO DE ERRORES GLOBAL
# ============================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Error interno del servidor",
            "type": type(exc).__name__
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)