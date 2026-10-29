"""
Autenticación: enrolamiento por invitación (UC-01), login passwordless (UC-02),
evaluación de riesgo (UC-03), step-up (UC-04) y ciclo de vida de tokens (RF-05).
"""
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DBSession

from auth.deps import CurrentUser, get_current_user
from auth.session_manager import SessionManager
from auth.token_manager import TokenManager, hash_token
from auth.webauthn_handler import WebAuthnError, WebAuthnHandler
from config import settings
from database import get_db
from models import Passkey, RiskEvaluation, StepUpTransaction, User
from risk.policies import PolicyEngine
from risk.risk_engine import RiskEngine
from services.common import (
    audit, client_ip, create_invitation, get_valid_invitation, normalize_email,
    serialize_user, touch_device, user_agent,
)
from services.mailer import send_otp_email

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Autenticación"])

webauthn_handler = WebAuthnHandler()
token_manager = TokenManager()
session_manager = SessionManager()
risk_engine = RiskEngine()
policy_engine = PolicyEngine()

_GENERIC_LOGIN_ERROR = "No se pudo iniciar sesión con esas credenciales"


# ============================================================================
# Modelos de request
# ============================================================================
class InvitationRegisterBegin(BaseModel):
    invitation_token: str


class InvitationRegisterComplete(BaseModel):
    invitation_token: str
    credential: Dict[str, Any]
    device_name: Optional[str] = Field(default=None, max_length=100)


class LoginBeginRequest(BaseModel):
    email: str


class LoginCompleteRequest(BaseModel):
    email: str
    credential: Dict[str, Any]


class LoginFailedRequest(BaseModel):
    email: str
    reason: str = Field(max_length=50)
    error_message: Optional[str] = Field(default=None, max_length=300)


class StepUpTokenRequest(BaseModel):
    stepup_token: str


class StepUpVerifyRequest(BaseModel):
    stepup_token: str
    verification_type: str  # 'passkey' | 'otp' | 'supervisor'
    credential: Optional[Dict[str, Any]] = None
    otp: Optional[str] = None


class RefreshRequest(BaseModel):
    refresh_token: str


# ============================================================================
# Helpers
# ============================================================================
def _location_display(risk_assessment: Dict[str, Any]) -> str:
    loc = risk_assessment["context"].get("location", {})
    return loc.get("display", "Unknown") if isinstance(loc, dict) else str(loc)


def _issue_session(db: DBSession, request: Request, user: User, *, ip: str, ua: str, location: str,
                   risk_score: float, decision: str, factors: Dict[str, Any], event_data: Dict[str, Any]) -> Dict:
    session = session_manager.create_session(
        user_id=user.id, ip_address=ip, user_agent=ua, location=location, risk_score=risk_score, db=db
    )
    tokens = token_manager.create_tokens(str(user.id), user.email, str(session.id), float(risk_score))
    session.refresh_jti_hash = hash_token(tokens.pop("refresh_jti"))
    db.add(RiskEvaluation(
        session_id=session.id, user_id=user.id, risk_score=risk_score, factors=factors, decision=decision
    ))
    audit(db, "auth_success", request, user_id=user.id, session_id=session.id,
          data={"risk_score": float(risk_score), "decision": decision, **event_data}, commit=False)
    db.commit()
    touch_device(db, user, request, location)
    return tokens


def _jsonable_factors(factors: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in factors.items():
        out[k] = {kk: (float(vv) if hasattr(vv, "is_finite") else vv) for kk, vv in v.items()} if isinstance(v, dict) else v
    return out


def _available_stepup_methods() -> list:
    methods = ["passkey", "supervisor"]
    if settings.otp_enabled:
        methods.insert(1, "otp")
    return methods


def _load_stepup(db: DBSession, token: str) -> StepUpTransaction:
    tx = (
        db.query(StepUpTransaction)
        .filter(StepUpTransaction.token_hash == hash_token(token or ""))
        .with_for_update()
        .first()
    )
    if tx is None or tx.expires_at < datetime.utcnow():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Verificación adicional inválida o vencida")
    if tx.status in ("completed", "locked", "denied"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Verificación adicional inválida o vencida")
    return tx


def _stepup_failure(db: DBSession, request: Request, tx: StepUpTransaction, method: str, reason: str):
    tx.attempts = (tx.attempts or 0) + 1
    locked = tx.attempts >= settings.STEPUP_MAX_ATTEMPTS
    if locked:
        tx.status = "locked"
    audit(db, "stepup_failed", request, user_id=tx.user_id,
          data={"verification_type": method, "reason": reason, "attempts": tx.attempts, "locked": locked},
          commit=False)
    db.commit()
    detail = "Demasiados intentos. Iniciá sesión nuevamente." if locked else "Verificación adicional fallida"
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail)


def _otp_hash(tx: StepUpTransaction, code: str) -> str:
    return hmac.new(settings.SECRET_KEY.encode(), f"{tx.id}:{code}".encode(), hashlib.sha256).hexdigest()


# ============================================================================
# Enrolamiento por invitación (UC-01)
# ============================================================================
@router.get("/auth/invitations/{token}")
def invitation_info(token: str, db: DBSession = Depends(get_db)):
    inv = get_valid_invitation(db, token)
    if inv is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Invitación inválida, vencida o ya utilizada")
    user = db.query(User).filter(User.id == inv.user_id).first()
    return {
        "email": user.email,
        "display_name": user.display_name,
        "purpose": inv.purpose,
        "expires_at": inv.expires_at.isoformat() + "Z",
    }


@router.post("/auth/register/begin")
def register_begin(data: InvitationRegisterBegin, db: DBSession = Depends(get_db)):
    inv = get_valid_invitation(db, data.invitation_token)
    if inv is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invitación inválida, vencida o ya utilizada")
    user = db.query(User).filter(User.id == inv.user_id).first()
    if user.status == "suspended":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cuenta suspendida")
    return webauthn_handler.begin_registration(db, user, ref_id=inv.id)


@router.post("/auth/register/complete")
def register_complete(request: Request, data: InvitationRegisterComplete, db: DBSession = Depends(get_db)):
    inv = get_valid_invitation(db, data.invitation_token)
    if inv is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invitación inválida, vencida o ya utilizada")
    user = db.query(User).filter(User.id == inv.user_id).first()
    if user.status == "suspended":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cuenta suspendida")

    try:
        cred = webauthn_handler.finish_registration(db, user, data.credential, ref_id=inv.id)
    except WebAuthnError as e:
        audit(db, "enrollment_failed", request, user_id=user.id, data={"reason": str(e)})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    if db.query(Passkey).filter(Passkey.user_id == user.id).count() >= settings.MAX_PASSKEYS_PER_USER:
        raise HTTPException(status.HTTP_409_CONFLICT, "Se alcanzó el máximo de passkeys por usuario")

    db.add(Passkey(
        user_id=user.id,
        credential_id=cred["credential_id"],
        public_key=cred["public_key"],
        attestation_fmt=cred["fmt"],
        aaguid=cred["aaguid"],
        counter=cred["sign_count"],
        device_name=(data.device_name or "Dispositivo sin nombre").strip()[:100],
        device_type=cred["device_type"],
        backed_up=cred["backed_up"],
        transports=cred["transports"],
    ))
    inv.used_at = datetime.utcnow()
    user.status = "active"
    audit(db, "passkey_enrolled", request, user_id=user.id, commit=False, data={
        "credential_id": cred["credential_id"][:16] + "...",
        "device_name": data.device_name,
        "device_type": cred["device_type"],
        "via": inv.purpose,
    })
    db.commit()

    location = risk_engine._get_location_from_ip(client_ip(request))
    location = location.get("display") if isinstance(location, dict) else location
    touch_device(db, user, request, location, device_name=data.device_name, create=True)

    return {"success": True, "message": "Passkey enrolada exitosamente", "credential_id": cred["credential_id"]}


# ============================================================================
# Login passwordless (UC-02) + evaluación de riesgo (UC-03)
# ============================================================================
def _active_user(db: DBSession, email: str) -> Optional[User]:
    user = db.query(User).filter(User.email == normalize_email(email)).first()
    if user is None or user.status != "active":
        return None
    return user


@router.post("/auth/login/begin")
def login_begin(data: LoginBeginRequest, db: DBSession = Depends(get_db)):
    user = _active_user(db, data.email)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _GENERIC_LOGIN_ERROR)
    try:
        return webauthn_handler.begin_authentication(db, user, purpose="login")
    except WebAuthnError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _GENERIC_LOGIN_ERROR)


@router.post("/auth/login/complete")
def login_complete(request: Request, data: LoginCompleteRequest, db: DBSession = Depends(get_db)):
    user = _active_user(db, data.email)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _GENERIC_LOGIN_ERROR)

    try:
        passkey = webauthn_handler.finish_authentication(db, user, data.credential, purpose="login")
    except WebAuthnError as e:
        audit(db, "auth_failed", request, user_id=user.id, data={"reason": "assertion_rejected", "detail": str(e)})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _GENERIC_LOGIN_ERROR)

    ip, ua = client_ip(request), user_agent(request)
    risk = risk_engine.evaluate_risk(user=user, ip_address=ip, user_agent=ua, db=db)
    decision = policy_engine.evaluate_policies(user=user, risk_score=risk["score"], context=risk["context"], db=db)
    score = float(risk["score"])
    factors = _jsonable_factors(risk["factors"])
    location = _location_display(risk)

    if decision["action"] == "deny":
        audit(db, "access_denied", request, user_id=user.id,
              data={"reason": "risk_too_high", "risk_score": score, "policy": decision["policy_name"]})
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={
            "message": "Acceso denegado por política de seguridad",
            "risk_score": score,
            "factors": factors,
            "requires_admin_approval": True,
        })

    if decision["action"] == "stepup":
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(minutes=settings.STEPUP_TTL_MINUTES)
        adjusted_score = max(float(settings.RISK_THRESHOLD_LOW), score)
        # El nivel mostrado debe ser coherente con el puntaje ajustado
        adjusted_level = "high" if adjusted_score >= settings.RISK_THRESHOLD_HIGH else "medium"
        tx = StepUpTransaction(
            user_id=user.id,
            token_hash=hash_token(token),
            status="pending",
            expires_at=expires_at,
            context={
                "ip_address": ip,
                "user_agent": ua,
                "location": location,
                "risk_score": adjusted_score,
                "risk_level": adjusted_level,
                "policy": decision["policy_name"],
                "credential_id": passkey.credential_id[:16] + "...",
                "factors": factors,
            },
        )
        db.add(tx)
        audit(db, "stepup_requested", request, user_id=user.id, commit=False,
              data={"risk_score": adjusted_score, "policy": decision["policy_name"]})
        db.commit()
        return {
            "success": True,
            "requires_stepup": True,
            "stepup_token": token,
            "expires_at": expires_at.isoformat() + "Z",
            "verification_methods": _available_stepup_methods(),
            "risk_assessment": {"score": adjusted_score, "level": adjusted_level, "factors": factors},
            "user": serialize_user(user),
        }

    tokens = _issue_session(db, request, user, ip=ip, ua=ua, location=location, risk_score=score,
                            decision=decision["action"], factors=factors,
                            event_data={"credential_id": passkey.credential_id[:16] + "..."})
    return {
        "success": True,
        "requires_stepup": False,
        "risk_assessment": {"score": score, "level": risk["level"], "factors": factors},
        "tokens": tokens,
        "user": serialize_user(user),
    }


@router.post("/auth/login/failed")
def login_failed(request: Request, data: LoginFailedRequest, db: DBSession = Depends(get_db)):
    """El cliente informa que el usuario canceló o el autenticador falló (alimenta el factor 'intentos fallidos')."""
    user = db.query(User).filter(User.email == normalize_email(data.email)).first()
    if user:
        audit(db, "auth_failed", request, user_id=user.id,
              data={"reason": data.reason, "error_message": data.error_message, "reported_by": "client"})
    return {"success": True}


# ============================================================================
# Step-up (UC-04): re-autenticación con passkey, OTP por email o aprobación de supervisor
# ============================================================================
@router.post("/auth/stepup/passkey/begin")
def stepup_passkey_begin(data: StepUpTokenRequest, db: DBSession = Depends(get_db)):
    tx = _load_stepup(db, data.stepup_token)
    user = db.query(User).filter(User.id == tx.user_id).first()
    db.commit()  # libera el lock
    return webauthn_handler.begin_authentication(db, user, purpose="stepup", ref_id=tx.id)


@router.post("/auth/stepup/otp/send")
def stepup_otp_send(request: Request, data: StepUpTokenRequest, db: DBSession = Depends(get_db)):
    if not settings.otp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "El envío de OTP no está habilitado")
    tx = _load_stepup(db, data.stepup_token)
    user = db.query(User).filter(User.id == tx.user_id).first()
    code = f"{secrets.randbelow(1_000_000):06d}"
    tx.otp_hash = _otp_hash(tx, code)
    tx.attempts = (tx.attempts or 0) + 1  # cada envío consume un intento: limita el reenvío
    db.commit()
    minutes = max(1, int((tx.expires_at - datetime.utcnow()).total_seconds() // 60))
    if not send_otp_email(user.email, code, minutes):
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "No se pudo enviar el código")
    audit(db, "stepup_otp_sent", request, user_id=user.id)
    return {"success": True, "message": "Código enviado al email registrado"}


@router.post("/auth/stepup/supervisor/request")
def stepup_supervisor_request(request: Request, data: StepUpTokenRequest, db: DBSession = Depends(get_db)):
    tx = _load_stepup(db, data.stepup_token)
    if tx.status == "pending":
        tx.status = "approval_requested"
        audit(db, "stepup_approval_requested", request, user_id=tx.user_id, commit=False)
    db.commit()
    return {"success": True, "status": tx.status}


@router.post("/auth/stepup/verify")
def stepup_verify(request: Request, data: StepUpVerifyRequest, db: DBSession = Depends(get_db)):
    tx = _load_stepup(db, data.stepup_token)
    user = db.query(User).filter(User.id == tx.user_id).first()
    if user is None or user.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Verificación adicional inválida o vencida")
    method = data.verification_type

    if method == "passkey":
        if not data.credential:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Falta la credencial")
        db.commit()  # libera el lock antes de la verificación (que hace commits propios)
        try:
            webauthn_handler.finish_authentication(db, user, data.credential, purpose="stepup", ref_id=tx.id)
        except WebAuthnError as e:
            tx = _load_stepup(db, data.stepup_token)
            _stepup_failure(db, request, tx, method, str(e))
        tx = _load_stepup(db, data.stepup_token)

    elif method == "otp":
        if not settings.otp_enabled or not tx.otp_hash:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "No hay un código OTP pendiente")
        provided = (data.otp or "").strip()
        if not hmac.compare_digest(_otp_hash(tx, provided), tx.otp_hash):
            _stepup_failure(db, request, tx, method, "otp_mismatch")

    elif method == "supervisor":
        if tx.status in ("pending", "approval_requested"):
            db.commit()
            return JSONResponse(status_code=status.HTTP_202_ACCEPTED,
                                content={"success": False, "status": tx.status,
                                         "message": "Esperando aprobación de un supervisor"})
        if tx.status != "approved":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Verificación adicional inválida o vencida")

    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Método de verificación no soportado")

    tx.status = "completed"
    tx.completed_at = datetime.utcnow()
    ctx = tx.context
    audit(db, "stepup_success", request, user_id=user.id, commit=False,
          data={"verification_type": method, "risk_score": ctx["risk_score"]})
    db.commit()

    tokens = _issue_session(db, request, user, ip=ctx["ip_address"], ua=ctx["user_agent"],
                            location=ctx.get("location"), risk_score=ctx["risk_score"], decision="stepup",
                            factors=ctx.get("factors", {}), event_data={"stepup_method": method})
    return {"success": True, "message": "Verificación adicional exitosa", "tokens": tokens,
            "user": serialize_user(user)}


# ============================================================================
# Tokens y sesión (RF-05)
# ============================================================================
@router.post("/auth/refresh")
def refresh(request: Request, data: RefreshRequest, db: DBSession = Depends(get_db)):
    claims = token_manager.verify_token(data.refresh_token, expected_type="refresh")
    if not claims or "jti" not in claims:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token inválido")
    session = session_manager.validate_session(claims.get("session_id"), db)
    if session is None or str(session.user_id) != claims["sub"]:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesión inválida o revocada")

    if not session.refresh_jti_hash or not hmac.compare_digest(session.refresh_jti_hash, hash_token(claims["jti"])):
        # Un refresh token ya rotado se volvió a usar: posible robo. Se revoca la sesión entera.
        session.revoked = True
        audit(db, "refresh_reuse_detected", request, user_id=session.user_id, session_id=session.id, commit=False)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesión revocada")

    user = db.query(User).filter(User.id == session.user_id).first()
    if user is None or user.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesión inválida o revocada")

    tokens = token_manager.create_tokens(str(user.id), user.email, str(session.id), float(session.risk_score or 0))
    session.refresh_jti_hash = hash_token(tokens.pop("refresh_jti"))
    db.commit()
    return tokens


@router.post("/auth/logout")
def logout(request: Request, current: CurrentUser = Depends(get_current_user), db: DBSession = Depends(get_db)):
    current.session.revoked = True
    audit(db, "logout", request, user_id=current.user.id, session_id=current.session.id, commit=False)
    db.commit()
    return {"success": True}


@router.get("/auth/me")
def me(current: CurrentUser = Depends(get_current_user)):
    return serialize_user(current.user)
