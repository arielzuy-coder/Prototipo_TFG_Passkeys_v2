from datetime import datetime, timedelta
from typing import Dict, Optional
import jwt
from config import settings

class TokenManager:
    def __init__(self):
        self.secret_key = settings.JWT_SECRET
        self.algorithm = settings.ALGORITHM
        self.access_token_expire = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire = settings.REFRESH_TOKEN_EXPIRE_HOURS
    
    def create_access_token(
        self,
        user_id: str,
        email: str,
        session_id: str,
        risk_score: float
    ) -> str:
        """Crea un token de acceso JWT."""
        
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire)
        
        payload = {
            "sub": user_id,
            "email": email,
            "session_id": session_id,
            "risk_score": risk_score,
            "type": "access",
            "exp": expire,
            "iat": datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token
    
    def create_refresh_token(
        self,
        user_id: str,
        session_id: str
    ) -> str:
        """Crea un token de refresco JWT."""
        
        expire = datetime.utcnow() + timedelta(hours=self.refresh_token_expire)
        
        payload = {
            "sub": user_id,
            "session_id": session_id,
            "type": "refresh",
            "exp": expire,
            "iat": datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token
    
    def create_tokens(
        self,
        user_id: str,
        email: str,
        session_id: str,
        risk_score: float
    ) -> Dict[str, str]:
        """Crea ambos tokens (acceso y refresco)."""
        
        access_token = self.create_access_token(user_id, email, session_id, risk_score)
        refresh_token = self.create_refresh_token(user_id, session_id)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.access_token_expire * 60
        }
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verifica y decodifica un token JWT."""
        
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.JWTError:
            return None
    
    def refresh_access_token(
        self,
        refresh_token: str,
        email: str,
        risk_score: float
    ) -> Optional[str]:
        """Genera un nuevo access token usando el refresh token."""
        
        payload = self.verify_token(refresh_token)
        
        if not payload or payload.get('type') != 'refresh':
            return None
        
        new_access_token = self.create_access_token(
            user_id=payload['sub'],
            email=email,
            session_id=payload['session_id'],
            risk_score=risk_score
        )
        
        return new_access_token