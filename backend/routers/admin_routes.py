"""
Administración (solo rol 'admin'): ciclo de vida de usuarios, invitaciones, recuperación,
aprobación de step-up por supervisor y políticas de acceso (UC-05).
"""
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from auth.deps import ROLES, CurrentUser, require_admin, require_admin_reauth
from auth.session_manager import SessionManager
from database import get_db
from models import Invitation, Passkey, Policy, StepUpTransaction, User
from risk.policies import PolicyEngine
from services.common import audit, create_invitation, normalize_email, serialize_user

router = APIRouter(prefix="/admin", tags=["Administración"])
session_manager = SessionManager()
policy_engine = PolicyEngine()

VALID_ACTIONS = ("allow", "stepup", "deny")


# ============================================================================
# Modelos
# ============================================================================
class UserCreateRequest(BaseModel):
    email: str = Field(max_length=255)
    display_name: Optional[str] = Field(default=None, max_length=100)
    role: str = "user"


class RoleUpdateRequest(BaseModel):
    role: str


class PolicyCreateRequest(BaseModel):
    name: str = Field(max_length=100)
    description: str = ""
    conditions: Dict[str, Any]
    action: str
    priority: int
    enabled: bool = True


class PolicyUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, max_length=100)
    description: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    action: Optional[str] = None
    priority: Optional[int] = None
    enabled: Optional[bool] = None


# ============================================================================
# Helpers
# ============================================================================
def _uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (ValueError, TypeError):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No encontrado")


def _get_user(db: DBSession, user_id: str) -> User:
    user = db.query(User).filter(User.id == _uuid(user_id)).first()
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuario no encontrado")
    return user


def _not_self(current: CurrentUser, user: User, action: str):
    if current.user.id == user.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"No podés {action} tu propia cuenta")


def _revoke_pending_invitations(db: DBSession, user: User):
    db.query(Invitation).filter(
        Invitation.user_id == user.id, Invitation.used_at.is_(None), Invitation.revoked == False  # noqa: E712
    ).update({Invitation.revoked: True})


def _serialize_policy(p: Policy) -> Dict[str, Any]:
    return {
        "id": str(p.id),
        "name": p.name,
        "description": p.description,
        "conditions": p.conditions,
        "action": p.action,
        "priority": p.priority,
        "enabled": p.enabled,
        "created_at": p.created_at.isoformat() + "Z" if p.created_at else None,
        "updated_at": (p.updated_at.isoformat() + "Z") if p.updated_at else None,
    }


# ============================================================================
# Usuarios e invitaciones
# ============================================================================
@router.get("/users")
def list_users(current: CurrentUser = Depends(require_admin), db: DBSession = Depends(get_db)):
    users = db.query(User).order_by(User.created_at).all()
    counts = dict(
        db.query(Passkey.user_id, func.count(Passkey.id)).group_by(Passkey.user_id).all()
    )
    return {"users": [{**serialize_user(u), "passkeys": counts.get(u.id, 0),
                       "created_at": u.created_at.isoformat() + "Z" if u.created_at else None} for u in users]}


@router.post("/users")
def create_user(request: Request, data: UserCreateRequest,
                current: CurrentUser = Depends(require_admin_reauth), db: DBSession = Depends(get_db)):
    """Alta de usuario (pendiente) + invitación de un solo uso para enrolar su primera passkey."""
    if data.role not in ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Rol inválido. Opciones: {', '.join(ROLES)}")
    email = normalize_email(data.email)
    if "@" not in email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email inválido")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Ya existe un usuario con ese email")

    user = User(email=email, display_name=data.display_name or email.split("@")[0], role=data.role, status="pending")
    db.add(user)
    db.commit()
    db.refresh(user)
    invitation = create_invitation(db, user, "enroll", created_by=current.user.id)
    audit(db, "user_created", request, user_id=user.id, actor_id=current.user.id,
          data={"email": email, "role": data.role})
    return {"user": serialize_user(user), "invitation": invitation}


@router.post("/users/{user_id}/invitation")
def reissue_invitation(user_id: str, request: Request,
                       current: CurrentUser = Depends(require_admin_reauth), db: DBSession = Depends(get_db)):
    """Reemite la invitación de alta de un usuario que todavía no enroló su passkey."""
    user = _get_user(db, user_id)
    if user.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "El usuario ya está activo: para reemplazar sus passkeys usá recuperación")
    invitation = create_invitation(db, user, "enroll", created_by=current.user.id)
    audit(db, "invitation_reissued", request, user_id=user.id, actor_id=current.user.id)
    return {"user": serialize_user(user), "invitation": invitation}


@router.post("/users/{user_id}/recovery")
def start_recovery(user_id: str, request: Request,
                   current: CurrentUser = Depends(require_admin_reauth), db: DBSession = Depends(get_db)):
    """
    Recuperación (pérdida de dispositivo o cuenta comprometida, sección 4 de Seguridad):
    revoca todas las passkeys y sesiones y emite una invitación de re-enrolamiento.
    La verificación de identidad del titular se hace fuera del sistema, antes de entregar el link.
    """
    user = _get_user(db, user_id)
    _not_self(current, user, "iniciar la recuperación de")
    removed = db.query(Passkey).filter(Passkey.user_id == user.id).delete()
    sessions = session_manager.revoke_all_user_sessions(user.id, db)
    user.status = "pending"
    db.commit()
    invitation = create_invitation(db, user, "recovery", created_by=current.user.id)
    audit(db, "account_recovery_started", request, user_id=user.id, actor_id=current.user.id,
          data={"passkeys_revoked": removed, "sessions_revoked": sessions})
    return {"user": serialize_user(user), "invitation": invitation}


@router.post("/users/{user_id}/suspend")
def suspend_user(user_id: str, request: Request,
                 current: CurrentUser = Depends(require_admin_reauth), db: DBSession = Depends(get_db)):
    user = _get_user(db, user_id)
    _not_self(current, user, "suspender")
    user.status = "suspended"
    _revoke_pending_invitations(db, user)
    sessions = session_manager.revoke_all_user_sessions(user.id, db)
    audit(db, "user_suspended", request, user_id=user.id, actor_id=current.user.id,
          data={"sessions_revoked": sessions})
    return {"user": serialize_user(user)}


@router.post("/users/{user_id}/reactivate")
def reactivate_user(user_id: str, request: Request,
                    current: CurrentUser = Depends(require_admin_reauth), db: DBSession = Depends(get_db)):
    user = _get_user(db, user_id)
    if user.status != "suspended":
        raise HTTPException(status.HTTP_409_CONFLICT, "El usuario no está suspendido")
    has_passkeys = db.query(Passkey).filter(Passkey.user_id == user.id).count() > 0
    user.status = "active" if has_passkeys else "pending"
    audit(db, "user_reactivated", request, user_id=user.id, actor_id=current.user.id, commit=False)
    db.commit()
    return {"user": serialize_user(user)}


@router.put("/users/{user_id}/role")
def change_role(user_id: str, request: Request, data: RoleUpdateRequest,
                current: CurrentUser = Depends(require_admin_reauth), db: DBSession = Depends(get_db)):
    if data.role not in ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Rol inválido. Opciones: {', '.join(ROLES)}")
    user = _get_user(db, user_id)
    _not_self(current, user, "cambiar el rol de")
    previous = user.role
    user.role = data.role
    audit(db, "user_role_changed", request, user_id=user.id, actor_id=current.user.id, commit=False,
          data={"from": previous, "to": data.role})
    db.commit()
    return {"user": serialize_user(user)}


@router.get("/users/{user_id}/passkeys")
def list_user_passkeys(user_id: str, current: CurrentUser = Depends(require_admin), db: DBSession = Depends(get_db)):
    from routers.me_routes import serialize_passkey
    user = _get_user(db, user_id)
    passkeys = db.query(Passkey).filter(Passkey.user_id == user.id).order_by(Passkey.created_at).all()
    return {"user": serialize_user(user), "passkeys": [serialize_passkey(pk) for pk in passkeys]}


@router.delete("/users/{user_id}/passkeys/{passkey_id}")
def admin_revoke_passkey(user_id: str, passkey_id: str, request: Request,
                         current: CurrentUser = Depends(require_admin_reauth), db: DBSession = Depends(get_db)):
    user = _get_user(db, user_id)
    passkey = db.query(Passkey).filter(Passkey.id == _uuid(passkey_id), Passkey.user_id == user.id).first()
    if passkey is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Passkey no encontrada")
    audit(db, "passkey_revoked", request, user_id=user.id, actor_id=current.user.id, commit=False,
          data={"credential_id": passkey.credential_id[:16] + "...", "by": "admin"})
    db.delete(passkey)
    db.commit()
    if db.query(Passkey).filter(Passkey.user_id == user.id).count() == 0 and user.status == "active":
        user.status = "pending"
        session_manager.revoke_all_user_sessions(user.id, db)
        db.commit()
    return {"success": True}


@router.get("/diagnostics/client-ip")
def client_ip_diagnostics(request: Request, current: CurrentUser = Depends(require_admin)):
    """Ayuda a configurar TRUSTED_PROXY_HOPS / CLIENT_IP_HEADER en el despliegue."""
    from config import settings
    from risk import geo
    from services.common import client_ip
    ip = client_ip(request)
    return {
        "connection_ip": request.client.host if request.client else None,
        "x_forwarded_for": request.headers.get("x-forwarded-for"),
        "true_client_ip": request.headers.get("true-client-ip"),
        "x_real_ip": request.headers.get("x-real-ip"),
        "trusted_proxy_hops": settings.TRUSTED_PROXY_HOPS,
        "client_ip_header": settings.CLIENT_IP_HEADER,
        "resolved_client_ip": ip,
        "geolocation": geo.lookup(ip),
        "hint": "resolved_client_ip debe ser tu IP pública. Si no lo es, ajustá TRUSTED_PROXY_HOPS.",
    }


# ============================================================================
# Step-up: aprobación manual por supervisor
# ============================================================================
@router.get("/stepup/pending")
def pending_stepups(current: CurrentUser = Depends(require_admin), db: DBSession = Depends(get_db)):
    rows = (
        db.query(StepUpTransaction, User)
        .join(User, User.id == StepUpTransaction.user_id)
        .filter(StepUpTransaction.status == "approval_requested", StepUpTransaction.expires_at > datetime.utcnow())
        .order_by(StepUpTransaction.created_at)
        .all()
    )
    return {"requests": [
        {
            "id": str(tx.id),
            "user": serialize_user(u),
            "requested_at": tx.created_at.isoformat() + "Z",
            "expires_at": tx.expires_at.isoformat() + "Z",
            "context": {k: tx.context.get(k) for k in ("ip_address", "location", "user_agent", "risk_score",
                                                      "risk_level", "policy", "factors")},
        }
        for tx, u in rows
    ]}


def _review_stepup(db: DBSession, request: Request, current: CurrentUser, tx_id: str, approve: bool):
    tx = db.query(StepUpTransaction).filter(StepUpTransaction.id == _uuid(tx_id)).with_for_update().first()
    if tx is None or tx.status != "approval_requested" or tx.expires_at < datetime.utcnow():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Solicitud inexistente o vencida")
    if tx.user_id == current.user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "No podés aprobar tu propio acceso")
    tx.status = "approved" if approve else "denied"
    tx.reviewed_by = current.user.id
    audit(db, "stepup_approved" if approve else "stepup_denied", request, user_id=tx.user_id,
          actor_id=current.user.id, commit=False)
    db.commit()
    return {"success": True, "status": tx.status}


@router.post("/stepup/{tx_id}/approve")
def approve_stepup(tx_id: str, request: Request, current: CurrentUser = Depends(require_admin_reauth),
                   db: DBSession = Depends(get_db)):
    return _review_stepup(db, request, current, tx_id, True)


@router.post("/stepup/{tx_id}/deny")
def deny_stepup(tx_id: str, request: Request, current: CurrentUser = Depends(require_admin_reauth),
                db: DBSession = Depends(get_db)):
    return _review_stepup(db, request, current, tx_id, False)


# ============================================================================
# Políticas de acceso (UC-05)
# ============================================================================
@router.get("/policies")
def list_policies(current: CurrentUser = Depends(require_admin), db: DBSession = Depends(get_db)):
    policies = db.query(Policy).order_by(Policy.priority.asc()).all()
    return {"total": len(policies), "policies": [_serialize_policy(p) for p in policies]}


@router.get("/policies/{policy_id}")
def get_policy(policy_id: str, current: CurrentUser = Depends(require_admin), db: DBSession = Depends(get_db)):
    policy = db.query(Policy).filter(Policy.id == _uuid(policy_id)).first()
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Política no encontrada")
    return _serialize_policy(policy)


@router.post("/policies")
def create_policy(request: Request, data: PolicyCreateRequest,
                  current: CurrentUser = Depends(require_admin_reauth), db: DBSession = Depends(get_db)):
    if data.action not in VALID_ACTIONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "La acción debe ser 'allow', 'stepup' o 'deny'")
    if db.query(Policy).filter(Policy.name == data.name).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Ya existe una política con el nombre '{data.name}'")
    policy = policy_engine.create_custom_policy(
        name=data.name, description=data.description, conditions=data.conditions,
        action=data.action, priority=data.priority, db=db,
    )
    if not data.enabled:
        policy.enabled = False
        db.commit()
    audit(db, "policy_created", request, actor_id=current.user.id,
          data={"policy_id": str(policy.id), "policy_name": policy.name, "action": policy.action})
    return {"success": True, "message": "Política creada exitosamente", "policy": _serialize_policy(policy)}


@router.put("/policies/{policy_id}")
def update_policy(policy_id: str, request: Request, data: PolicyUpdateRequest,
                  current: CurrentUser = Depends(require_admin_reauth), db: DBSession = Depends(get_db)):
    policy = db.query(Policy).filter(Policy.id == _uuid(policy_id)).first()
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Política no encontrada")
    updates = data.model_dump(exclude_unset=True)
    if "action" in updates and updates["action"] not in VALID_ACTIONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "La acción debe ser 'allow', 'stepup' o 'deny'")
    for key, value in updates.items():
        setattr(policy, key, value)
    policy.updated_at = datetime.utcnow()
    audit(db, "policy_updated", request, actor_id=current.user.id, commit=False,
          data={"policy_id": str(policy.id), "policy_name": policy.name, "updates": updates})
    db.commit()
    return {"success": True, "message": "Política actualizada exitosamente", "policy": _serialize_policy(policy)}


@router.delete("/policies/{policy_id}")
def delete_policy(policy_id: str, request: Request,
                  current: CurrentUser = Depends(require_admin_reauth), db: DBSession = Depends(get_db)):
    policy = db.query(Policy).filter(Policy.id == _uuid(policy_id)).first()
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Política no encontrada")
    name = policy.name
    db.delete(policy)
    audit(db, "policy_deleted", request, actor_id=current.user.id, commit=False,
          data={"policy_id": policy_id, "policy_name": name})
    db.commit()
    return {"success": True, "message": "Política eliminada exitosamente"}


@router.put("/policies/{policy_id}/toggle")
def toggle_policy(policy_id: str, request: Request,
                  current: CurrentUser = Depends(require_admin_reauth), db: DBSession = Depends(get_db)):
    policy = db.query(Policy).filter(Policy.id == _uuid(policy_id)).first()
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Política no encontrada")
    policy.enabled = not policy.enabled
    policy.updated_at = datetime.utcnow()
    audit(db, "policy_toggled", request, actor_id=current.user.id, commit=False,
          data={"policy_id": str(policy.id), "policy_name": policy.name, "enabled": policy.enabled})
    db.commit()
    return {
        "success": True,
        "message": f"Política {'activada' if policy.enabled else 'desactivada'} exitosamente",
        "policy": {"id": str(policy.id), "name": policy.name, "enabled": policy.enabled},
    }
