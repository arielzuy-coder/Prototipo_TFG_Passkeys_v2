from datetime import datetime, timedelta
from typing import Optional
import uuid

from sqlalchemy.orm import Session as DBSession

from config import settings
from models import Session


class SessionManager:
    def __init__(self):
        self.session_duration_hours = settings.REFRESH_TOKEN_EXPIRE_HOURS

    def create_session(
        self,
        user_id: uuid.UUID,
        ip_address: str,
        user_agent: str,
        location: Optional[str],
        risk_score: float,
        db: DBSession,
    ) -> Session:
        session = Session(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            location=location,
            risk_score=risk_score,
            expires_at=datetime.utcnow() + timedelta(hours=self.session_duration_hours),
            revoked=False,
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        return session

    def validate_session(self, session_id, db: DBSession) -> Optional[Session]:
        try:
            sid = session_id if isinstance(session_id, uuid.UUID) else uuid.UUID(str(session_id))
        except (ValueError, TypeError):
            return None
        session = db.query(Session).filter(Session.id == sid).first()
        if not session or session.revoked or session.expires_at < datetime.utcnow():
            return None
        return session

    def revoke_session(self, session_id, db: DBSession) -> bool:
        session = db.query(Session).filter(Session.id == session_id).first()
        if not session:
            return False
        session.revoked = True
        db.commit()
        return True

    def revoke_all_user_sessions(self, user_id: uuid.UUID, db: DBSession) -> int:
        count = (
            db.query(Session)
            .filter(Session.user_id == user_id, Session.revoked == False)  # noqa: E712
            .update({Session.revoked: True})
        )
        db.commit()
        return count

    def cleanup_expired_sessions(self, db: DBSession) -> int:
        count = db.query(Session).filter(Session.expires_at < datetime.utcnow()).delete()
        db.commit()
        return count
