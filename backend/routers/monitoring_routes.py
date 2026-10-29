"""Auditoría y métricas (UC-06). Lectura para administradores y auditores."""
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from auth.deps import require_audit_reader
from database import get_db
from models import AuditEvent, RiskEvaluation, User

router = APIRouter(tags=["Auditoría"], dependencies=[Depends(require_audit_reader)])


@router.get("/audit/events")
def get_audit_events(user_email: Optional[str] = None, event_type: Optional[str] = None, limit: int = 100,
                     db: DBSession = Depends(get_db)):
    limit = max(1, min(limit, 1000))
    query = db.query(AuditEvent)
    if user_email:
        user = db.query(User).filter(User.email == user_email.strip().lower()).first()
        if user is None:
            return {"total": 0, "events": []}
        query = query.filter(AuditEvent.user_id == user.id)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    events = query.order_by(AuditEvent.timestamp.desc()).limit(limit).all()
    return {
        "total": len(events),
        "events": [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "timestamp": e.timestamp.isoformat() + "Z",
                "ip_address": e.ip_address,
                "event_data": e.event_data,
            }
            for e in events
        ],
    }


@router.get("/audit/stats")
def get_audit_stats(db: DBSession = Depends(get_db)):
    events_by_type = db.query(AuditEvent.event_type, func.count(AuditEvent.id)).group_by(AuditEvent.event_type).all()
    counts = {et: c for et, c in events_by_type}
    ok, failed = counts.get("auth_success", 0), counts.get("auth_failed", 0)
    return {
        "events_by_type": counts,
        "authentication": {
            "success": ok,
            "failed": failed,
            "success_rate": f"{(ok / (ok + failed) * 100):.2f}%" if (ok + failed) else "0%",
        },
    }


@router.get("/risk/dashboard")
def risk_dashboard(db: DBSession = Depends(get_db)):
    since = datetime.utcnow() - timedelta(days=7)
    summary = db.query(func.count(RiskEvaluation.id), func.avg(RiskEvaluation.risk_score)).filter(
        RiskEvaluation.evaluated_at >= since
    ).first()
    decisions = db.query(RiskEvaluation.decision, func.count(RiskEvaluation.id)).group_by(RiskEvaluation.decision).all()
    high_risk_users = (
        db.query(User.email, func.avg(RiskEvaluation.risk_score))
        .join(RiskEvaluation, User.id == RiskEvaluation.user_id)
        .group_by(User.email)
        .order_by(func.avg(RiskEvaluation.risk_score).desc())
        .limit(10)
        .all()
    )
    return {
        "summary": {
            "total_evaluations": summary[0] if summary else 0,
            "average_risk_score": float(summary[1]) if summary and summary[1] is not None else 0,
        },
        "decisions": {d: c for d, c in decisions},
        "high_risk_users": [{"email": e, "avg_risk": float(r)} for e, r in high_risk_users],
    }
