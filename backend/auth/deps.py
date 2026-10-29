"""
Dependencias de autenticación y autorización (RBAC).

Perfiles según la Tabla 4 de la tesis:
  - user:    sus propias passkeys e historial
  - auditor: lectura de auditoría, reportes y métricas (sin cambios de configuración)
  - admin:   usuarios, invitaciones, políticas y aprobación de step-up
"""
from dataclasses import dataclass
from typing import Dict

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from auth.session_manager import SessionManager
from auth.token_manager import TokenManager
from database import get_db
from models import Session, User

ROLE_USER = "user"
ROLE_ADMIN = "admin"
ROLE_AUDITOR = "auditor"
ROLES = (ROLE_USER, ROLE_ADMIN, ROLE_AUDITOR)

_tokens = TokenManager()
_sessions = SessionManager()

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="No autenticado",
    headers={"WWW-Authenticate": "Bearer"},
)


@dataclass
class CurrentUser:
    user: User
    session: Session
    claims: Dict

    @property
    def role(self) -> str:
        return self.user.role


def get_current_user(request: Request, db: DBSession = Depends(get_db)) -> CurrentUser:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise _UNAUTHORIZED

    claims = _tokens.verify_token(token, expected_type="access")
    if not claims:
        raise _UNAUTHORIZED

    session = _sessions.validate_session(claims.get("session_id"), db)
    if session is None or str(session.user_id) != claims.get("sub"):
        raise _UNAUTHORIZED

    user = db.query(User).filter(User.id == session.user_id).first()
    if user is None or user.status != "active":
        raise _UNAUTHORIZED

    return CurrentUser(user=user, session=session, claims=claims)


def require_roles(*roles: str):
    """El rol se lee de la base en cada request: un cambio de rol aplica de inmediato."""

    def checker(current: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current.user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permisos insuficientes")
        return current

    return checker


require_admin = require_roles(ROLE_ADMIN)
require_audit_reader = require_roles(ROLE_ADMIN, ROLE_AUDITOR)
