"""Utilidades compartidas: auditoría, invitaciones, dispositivos, serialización."""
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


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:500]


def audit(db: DBSession, event_type: str, request: Optional[Request] = None, *,
          user_id=None, session_id=None, actor_id=None, data: Optional[Dict[str, Any]] = None,
          commit: bool = True) -> None:
    payload = dict(data or {})
    if actor_id is not None:
        payload["actor_id"] = str(actor_id)
    db.add(AuditEvent(
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
                 device_name: Optional[str] = None, create: bool = False) -> None:
    """Actualiza (o crea, si create=True) el dispositivo del usuario. Nunca toca dispositivos de otro."""
    ua_string = user_agent(request)
    fp = device_fingerprint(ua_string)
    device = db.query(Device).filter(Device.device_fingerprint == fp, Device.user_id == user.id).first()
    if device:
        device.last_seen_at = datetime.utcnow()
        device.last_seen_ip = client_ip(request)
        if location:
            device.last_seen_location = location
        db.commit()
        return
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
            ))
        db.commit()
    except IntegrityError:
        # El esquema original tiene fingerprint único global; si otro usuario
        # ya lo registró, no se crea (pendiente de migración en fase 3).
        db.rollback()
        logger.info("Fingerprint de dispositivo ya registrado por otro usuario; se omite")
