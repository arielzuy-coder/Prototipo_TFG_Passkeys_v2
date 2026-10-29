"""
Verificación continua de sesión (UC-03 / RF-03, NIST SP 800-207).

En cada request autenticado se compara el contexto actual con el de la sesión. Todo el
contexto lo obtiene el servidor (IP de la conexión y User-Agent), nunca lo informa el cliente.

  - Otro navegador/dispositivo usando el token   -> se revoca la sesión (posible robo de token).
  - Cambio de país de la IP                       -> se exige re-autenticación con passkey.
  - Cambio de IP dentro del mismo país            -> se registra y se actualiza la sesión.
  - Pasado el intervalo según el nivel de riesgo  -> se reevalúan el motor de riesgo y las políticas:
        deny -> revoca, stepup -> exige re-autenticación, allow -> continúa.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from config import settings
from models import RiskEvaluation, Session, User
from risk import geo
from services.common import audit, client_ip, device_fingerprint, user_agent

logger = logging.getLogger(__name__)

REVOKE, REAUTH, OK = "revoke", "reauth", "ok"


def reauth_required(reason: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"code": "reauth_required", "reason": reason, "message": message},
    )


def reevaluation_interval(risk_score: Optional[float]) -> timedelta:
    score = float(risk_score or 0)
    if score >= settings.RISK_THRESHOLD_HIGH:
        minutes = settings.SESSION_REEVAL_MINUTES_HIGH
    elif score >= settings.RISK_THRESHOLD_LOW:
        minutes = settings.SESSION_REEVAL_MINUTES_MEDIUM
    else:
        minutes = settings.SESSION_REEVAL_MINUTES_LOW
    return timedelta(minutes=minutes)


def check_device(db: DBSession, request: Request, session: Session) -> None:
    """El token solo vale desde el navegador en el que se abrió la sesión."""
    if session.device_fingerprint and device_fingerprint(user_agent(request)) != session.device_fingerprint:
        session.revoked = True
        audit(db, "session_revoked", request, user_id=session.user_id, session_id=session.id, commit=False,
              data={"reason": "device_changed", "original_ip": session.ip_address})
        db.commit()
        logger.warning("Sesión %s revocada: token usado desde otro dispositivo", session.id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesión revocada",
                            headers={"WWW-Authenticate": "Bearer"})


def _reevaluate(db: DBSession, request: Request, session: Session, user: User, ip: str) -> Tuple[str, str]:
    # Import diferido: el motor de riesgo importa modelos y servicios pesados
    from routers.auth_routes import policy_engine, risk_engine

    risk = risk_engine.evaluate_risk(user=user, ip_address=ip, user_agent=user_agent(request), db=db,
                                     credential_id=session.credential_id)
    decision = policy_engine.evaluate_policies(user=user, risk_score=risk["score"], context=risk["context"], db=db)
    score = float(risk["score"])
    session.risk_score = score
    session.last_evaluated_at = datetime.utcnow()
    factors = {k: {kk: (float(vv) if hasattr(vv, "is_finite") else vv) for kk, vv in v.items()}
               for k, v in risk["factors"].items()}
    db.add(RiskEvaluation(session_id=session.id, user_id=user.id, risk_score=score, factors=factors,
                          decision=f"reeval_{decision['action']}"))
    audit(db, "session_reevaluated", request, user_id=user.id, session_id=session.id, commit=False,
          data={"risk_score": score, "decision": decision["action"], "policy": decision["policy_name"]})
    db.commit()
    if decision["action"] == "deny":
        return REVOKE, "policy_deny"
    if decision["action"] == "stepup":
        return REAUTH, "policy_stepup"
    return OK, ""


def verify_session_context(db: DBSession, request: Request, session: Session, user: User) -> None:
    """Lanza 401 (sesión revocada) o 403 reauth_required si el contexto ya no es confiable."""
    check_device(db, request, session)

    ip = client_ip(request)
    if ip != session.ip_address:
        location = geo.lookup(ip)
        country = location.get("country")
        if session.country and country != session.country:
            audit(db, "session_context_changed", request, user_id=user.id, session_id=session.id,
                  data={"reason": "country_changed", "from": session.country, "to": country})
            raise reauth_required("country_changed", "Cambió la ubicación de la sesión. Confirmá tu identidad.")
        audit(db, "session_ip_changed", request, user_id=user.id, session_id=session.id, commit=False,
              data={"from": session.ip_address, "to": ip})
        session.ip_address = ip
        session.location = location.get("display")
        db.commit()

    last = session.last_evaluated_at or session.created_at
    if last and datetime.utcnow() - last >= reevaluation_interval(session.risk_score):
        action, reason = _reevaluate(db, request, session, user, ip)
        if action == REVOKE:
            session.revoked = True
            audit(db, "session_revoked", request, user_id=user.id, session_id=session.id, commit=False,
                  data={"reason": reason})
            db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesión revocada por política de seguridad",
                                headers={"WWW-Authenticate": "Bearer"})
        if action == REAUTH:
            raise reauth_required(reason, "Por tu seguridad, confirmá tu identidad para continuar.")


def require_recent_strong_auth(session: Session) -> None:
    """Operaciones sensibles: exige una autenticación fuerte reciente (Tabla 4: step-up del administrador)."""
    limit = timedelta(minutes=settings.REAUTH_MAX_AGE_MINUTES)
    if not session.strong_auth_at or datetime.utcnow() - session.strong_auth_at > limit:
        raise reauth_required("sensitive_operation", "Esta operación requiere confirmar tu identidad.")
