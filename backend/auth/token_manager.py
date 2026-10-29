"""Emisión y validación de JWT (PyJWT). Access 15 min, refresh 8 h con rotación."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

import jwt

from config import settings


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class TokenManager:
    def __init__(self):
        self.secret_key = settings.JWT_SECRET
        self.algorithm = settings.ALGORITHM
        self.access_token_expire = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire = settings.REFRESH_TOKEN_EXPIRE_HOURS

    def _encode(self, payload: Dict) -> str:
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def create_access_token(self, user_id: str, email: str, session_id: str, risk_score: float) -> str:
        now = datetime.now(timezone.utc)
        return self._encode({
            "sub": user_id,
            "email": email,
            "session_id": session_id,
            "risk_score": risk_score,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=self.access_token_expire),
        })

    def create_refresh_token(self, user_id: str, session_id: str) -> (str, str):
        """Devuelve (token, jti). El jti se guarda hasheado en la sesión para la rotación."""
        now = datetime.now(timezone.utc)
        jti = secrets.token_urlsafe(24)
        token = self._encode({
            "sub": user_id,
            "session_id": session_id,
            "type": "refresh",
            "jti": jti,
            "iat": now,
            "exp": now + timedelta(hours=self.refresh_token_expire),
        })
        return token, jti

    def create_tokens(self, user_id: str, email: str, session_id: str, risk_score: float) -> Dict:
        """Crea access + refresh. Devuelve también 'refresh_jti' (uso interno, no enviar al cliente)."""
        access_token = self.create_access_token(user_id, email, session_id, risk_score)
        refresh_token, jti = self.create_refresh_token(user_id, session_id)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.access_token_expire * 60,
            "refresh_jti": jti,
        }

    def verify_token(self, token: str, expected_type: Optional[str] = None) -> Optional[Dict]:
        """Devuelve el payload si el token es válido, o None. Nunca lanza excepción."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"require": ["exp", "iat", "sub", "type"]},
            )
        except jwt.PyJWTError:
            return None
        if expected_type and payload.get("type") != expected_type:
            return None
        return payload
