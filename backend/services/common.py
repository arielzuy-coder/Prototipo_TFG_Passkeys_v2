"""Utilidades compartidas: auditoría, invitaciones, dispositivos, serialización."""
import ipaddress
import logging
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import user_agents
from fastapi import Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from auth.token_manager import hash_token
from config import settings
from models import AuditEvent, Device, Invitation, User

logger = logging.getLogger(__name__)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def client_ip(request: Request) -> str:
    """
    IP real del cliente.

    Detrás de un proxy, la IP de la conexión es la del proxy. El cliente puede mandar su propio
    X-Forwarded-For, así que solo se confía en las últimas TRUSTED_PROXY_HOPS entradas (las que
    agregaron proxies propios) o en un header que el proxy sobrescribe (CLIENT_IP_HEADER).
    """
    peer = request.client.host if request.client else "unknown"
    if settings.CLIENT_IP_HEADER:
        value = (request.headers.get(settings.CLIENT_IP_HEADER) or "").strip()
        if _valid_ip(value):
            return value
    hops = settings.TRUSTED_PROXY_HOPS
    if hops > 0:
        chain = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if len(chain) >= hops and _valid_ip(chain[-hops]):
            return chain[-hops]
    return peer


def user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:500]


def audit(db: DBSession, event_type: str, request: Optional[Request] = None, *,
          user_id=None, session_id=None, actor_id=None, data: Optional[Dict[str, Any]] = None,
          commit: bool = True) -> None:
    payload = dict(data or {})
    if actor_id is not None:
        payload["actor_id"] = str(actor_id)
    from services import audit_chain  # import diferido: audit_chain importa models

    audit_chain.append(db, AuditEvent(
        user_id=user_id,
        session_id=session_id,
        event_type=event_type,
        event_data=payload,
        ip_address=client_ip(request) if request else None,
        user_agent=user_agent(request) if request else None,
    ))
    if commit:
        db.commit()


def serialize_user(user: User) -> Dict[str, Any]:
    return {
        "id": str(user.id),
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "status": user.status,
    }


def normalize_email(email: str) -> str:
    return email.strip().lower()


# ----------------------------------------------------------------------
# Invitaciones
# ----------------------------------------------------------------------
def create_invitation(db: DBSession, user: User, purpose: str = "enroll",
                      created_by: Optional[uuid.UUID] = None) -> Dict[str, Any]:
    """Revoca invitaciones previas sin usar y emite una nueva. El token solo se devuelve acá."""
    db.query(Invitation).filter(
        Invitation.user_id == user.id, Invitation.used_at.is_(None), Invitation.revoked == False  # noqa: E712
    ).update({Invitation.revoked: True})

    token = secrets.token_urlsafe(32)
    invitation = Invitation(
        user_id=user.id,
        token_hash=hash_token(token),
        purpose=purpose,
        created_by=created_by,
        expires_at=datetime.utcnow() + timedelta(hours=settings.INVITATION_TTL_HOURS),
    )
    db.add(invitation)
    db.commit()
    db.refresh(invitation)
    return {
        "invitation_id": str(invitation.id),
        "token": token,
        "url": f"{settings.frontend_url}/enroll?invite={token}",
        "expires_at": invitation.expires_at.isoformat() + "Z",
        "purpose": purpose,
    }


def get_valid_invitation(db: DBSession, token: str) -> Optional[Invitation]:
    if not token:
        return None
    inv = db.query(Invitation).filter(Invitation.token_hash == hash_token(token)).first()
    if inv is None or inv.revoked or inv.used_at is not None or inv.expires_at < datetime.utcnow():
        return None
    return inv


# ----------------------------------------------------------------------
# Dispositivos (señal de contexto para el motor de riesgo)
# ----------------------------------------------------------------------
def device_fingerprint(ua_string: str) -> str:
    ua = user_agents.parse(ua_string)
    return f"{ua.browser.family}_{ua.os.family}_{ua_string[:50]}"


def touch_device(db: DBSession, user: User, request: Request, location: Optional[str],
                 device_name: Optional[str] = None, create: bool = False,
                 credential_id: Optional[str] = None) -> None:
    """
    Actualiza el dispositivo del usuario y registra la passkey verificada desde él.
    create=True lo crea si no existe (enrolamiento o step-up superado). Nunca toca dispositivos de otro.
    """
    ua_string = user_agent(request)
    fp = device_fingerprint(ua_string)
    device = db.query(Device).filter(Device.device_fingerprint == fp, Device.user_id == user.id).first()
    if device is None:
        if not create:
            return
        ua = user_agents.parse(ua_string)
        try:
            with db.begin_nested():
                db.add(Device(
                    user_id=user.id,
                    device_fingerprint=fp,
                    device_name=device_name or "Dispositivo sin nombre",
                    os=ua.os.family,
                    browser=ua.browser.family,
                    trust_level=50,
                    last_seen_ip=client_ip(request),
                    last_seen_location=location,
                    credential_ids=[credential_id] if credential_id else [],
                ))
            db.commit()
        except IntegrityError:
            db.rollback()  # carrera entre dos requests del mismo usuario
        return

    device.last_seen_at = datetime.utcnow()
    device.last_seen_ip = client_ip(request)
    if location:
        device.last_seen_location = location
    if credential_id and credential_id not in (device.credential_ids or []):
        device.credential_ids = [*(device.credential_ids or []), credential_id][-10:]
    db.commit()
