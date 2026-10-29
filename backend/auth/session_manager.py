from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session as DBSession
from models import Session, User
import uuid

class SessionManager:
    def __init__(self):
        self.session_duration_hours = 8
    
    def create_session(
        self,
        user_id: uuid.UUID,
        ip_address: str,
        user_agent: str,
        location: Optional[str],
        risk_score: float,
        db: DBSession
    ) -> Session:
        """Crea una nueva sesión para el usuario."""
        
        expires_at = datetime.utcnow() + timedelta(hours=self.session_duration_hours)
        
        session = Session(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            location=location,
            risk_score=risk_score,
            expires_at=expires_at,
            revoked=False
        )
        
        db.add(session)
        db.commit()
        db.refresh(session)
        
        return session
    
    def validate_session(
        self,
        session_id: uuid.UUID,
        db: DBSession
    ) -> Optional[Session]:
        """Valida si una sesión es válida y activa."""
        
        session = db.query(Session).filter(Session.id == session_id).first()
        
        if not session:
            return None
        
        if session.revoked:
            return None
        
        if session.expires_at < datetime.utcnow():
            return None
        
        return session
    
    def revoke_session(
        self,
        session_id: uuid.UUID,
        db: DBSession
    ) -> bool:
        """Revoca una sesión específica."""
        
        session = db.query(Session).filter(Session.id == session_id).first()
        
        if not session:
            return False
        
        session.revoked = True
        db.commit()
        
        return True
    
    def revoke_all_user_sessions(
        self,
        user_id: uuid.UUID,
        db: DBSession
    ) -> int:
        """Revoca todas las sesiones de un usuario."""
        
        sessions = db.query(Session).filter(
            Session.user_id == user_id,
            Session.revoked == False
        ).all()
        
        count = 0
        for session in sessions:
            session.revoked = True
            count += 1
        
        db.commit()
        
        return count
    
    def cleanup_expired_sessions(self, db: DBSession) -> int:
        """Limpia sesiones expiradas de la base de datos."""
        
        expired_sessions = db.query(Session).filter(
            Session.expires_at < datetime.utcnow()
        ).all()
        
        count = len(expired_sessions)
        
        for session in expired_sessions:
            db.delete(session)
        
        db.commit()
        
        return count