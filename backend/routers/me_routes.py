"""Autoservicio del usuario: sus passkeys (RF-08, máx. 5) y su historial de accesos."""
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DBSession

from auth.deps import CurrentUser, get_current_user
from auth.webauthn_handler import WebAuthnError, WebAuthnHandler
from config import settings
from database import get_db
from models import AuditEvent, Passkey
from services.common import audit, touch_device

router = APIRouter(tags=["Usuario"])
webauthn_handler = WebAuthnHandler()


class RenamePasskey(BaseModel):
    device_name: str = Field(min_length=1, max_length=100)


class AddPasskeyComplete(BaseModel):
    credential: Dict[str, Any]
    device_name: Optional[str] = Field(default=None, max_length=100)


def _own_passkey(db: DBSession, current: CurrentUser, passkey_id: str) -> Optional[Passkey]:
    try:
        pid = uuid.UUID(passkey_id)
    except ValueError:
        return None
    return db.query(Passkey).filter(Passkey.id == pid, Passkey.user_id == current.user.id).first()


def serialize_passkey(pk: Passkey) -> Dict[str, Any]:
    return {
        "id": str(pk.id),
        "device_name": pk.device_name,
        "device_type": pk.device_type,
        "backed_up": bool(pk.backed_up),
        "created_at": pk.created_at.isoformat() + "Z",
        "last_used_at": (pk.last_used_at.isoformat() + "Z") if pk.last_used_at else None,
    }


@router.get("/passkeys")
def list_my_passkeys(current: CurrentUser = Depends(get_current_user), db: DBSession = Depends(get_db)):
    passkeys = db.query(Passkey).filter(Passkey.user_id == current.user.id).order_by(Passkey.created_at).all()
    return {
        "user_email": current.user.email,
        "max_passkeys": settings.MAX_PASSKEYS_PER_USER,
        "passkeys": [serialize_passkey(pk) for pk in passkeys],
    }


@router.post("/passkeys/register/begin")
def add_passkey_begin(current: CurrentUser = Depends(get_current_user), db: DBSession = Depends(get_db)):
    count = db.query(Passkey).filter(Passkey.user_id == current.user.id).count()
    if count >= settings.MAX_PASSKEYS_PER_USER:
        raise HTTPException(status.HTTP_409_CONFLICT, "Se alcanzó el máximo de passkeys por usuario")
    return webauthn_handler.begin_registration(db, current.user, ref_id=current.session.id)


@router.post("/passkeys/register/complete")
def add_passkey_complete(request: Request, data: AddPasskeyComplete,
                         current: CurrentUser = Depends(get_current_user), db: DBSession = Depends(get_db)):
    user = current.user
    try:
        cred = webauthn_handler.finish_registration(db, user, data.credential, ref_id=current.session.id)
    except WebAuthnError as e:
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
    audit(db, "passkey_enrolled", request, user_id=user.id, session_id=current.session.id, commit=False, data={
        "credential_id": cred["credential_id"][:16] + "...", "device_name": data.device_name, "via": "self_service",
    })
    db.commit()
    touch_device(db, user, request, current.session.location, device_name=data.device_name, create=True)
    return {"success": True, "message": "Passkey agregada"}


@router.put("/passkeys/{passkey_id}")
def rename_my_passkey(passkey_id: str, data: RenamePasskey,
                      current: CurrentUser = Depends(get_current_user), db: DBSession = Depends(get_db)):
    passkey = _own_passkey(db, current, passkey_id)
    if passkey is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Passkey no encontrada")
    passkey.device_name = data.device_name.strip()
    db.commit()
    return {"success": True, "passkey": serialize_passkey(passkey)}


@router.delete("/passkeys/{passkey_id}")
def revoke_my_passkey(passkey_id: str, request: Request,
                      current: CurrentUser = Depends(get_current_user), db: DBSession = Depends(get_db)):
    passkey = _own_passkey(db, current, passkey_id)
    if passkey is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Passkey no encontrada")
    if db.query(Passkey).filter(Passkey.user_id == current.user.id).count() <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "No se puede revocar la única passkey: agregá otra antes o pedí una recuperación")
    audit(db, "passkey_revoked", request, user_id=current.user.id, session_id=current.session.id, commit=False,
          data={"credential_id": passkey.credential_id[:16] + "...", "by": "owner"})
    db.delete(passkey)
    db.commit()
    return {"success": True, "message": "Passkey revocada exitosamente"}


@router.get("/me/events")
def my_events(limit: int = 50, current: CurrentUser = Depends(get_current_user), db: DBSession = Depends(get_db)):
    limit = max(1, min(limit, 200))
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.user_id == current.user.id)
        .order_by(AuditEvent.timestamp.desc())
        .limit(limit)
        .all()
    )
    return {
        "total": len(events),
        "events": [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "timestamp": e.timestamp.isoformat() + "Z",
                "ip_address": e.ip_address,
                "event_data": {k: v for k, v in (e.event_data or {}).items() if k not in ("actor_id",)},
            }
            for e in events
        ],
    }


# ============================================================================
# Sesiones propias (RF-05: revocar tokens)
# ============================================================================
@router.get("/me/sessions")
def my_sessions(current: CurrentUser = Depends(get_current_user), db: DBSession = Depends(get_db)):
    from datetime import datetime
    from models import Session as SessionModel
    sessions = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == current.user.id, SessionModel.revoked == False,  # noqa: E712
                SessionModel.expires_at > datetime.utcnow())
        .order_by(SessionModel.created_at.desc())
        .all()
    )
    return {"sessions": [
        {
            "id": str(s.id),
            "current": s.id == current.session.id,
            "ip_address": s.ip_address,
            "location": s.location,
            "user_agent": s.user_agent,
            "created_at": s.created_at.isoformat() + "Z",
            "expires_at": s.expires_at.isoformat() + "Z",
        }
        for s in sessions
    ]}


@router.delete("/me/sessions/{session_id}")
def revoke_my_session(session_id: str, request: Request,
                      current: CurrentUser = Depends(get_current_user), db: DBSession = Depends(get_db)):
    from models import Session as SessionModel
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sesión no encontrada")
    session = db.query(SessionModel).filter(SessionModel.id == sid, SessionModel.user_id == current.user.id).first()
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sesión no encontrada")
    session.revoked = True
    audit(db, "session_revoked", request, user_id=current.user.id, session_id=session.id, commit=False,
          data={"reason": "user_request"})
    db.commit()
    return {"success": True}
