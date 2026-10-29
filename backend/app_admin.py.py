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

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.ORIGIN, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
