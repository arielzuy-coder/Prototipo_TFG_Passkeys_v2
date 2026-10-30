"""
Registro de auditoría a prueba de alteraciones (RNF-S4).

Cada evento lleva un número de secuencia y un sello HMAC-SHA256 calculado sobre su
contenido y el sello del evento anterior. Si alguien modifica, borra o intercala un
registro directamente en la base, la cadena deja de cerrar en ese punto y la
verificación lo señala.

- La clave del HMAC sale de SECRET_KEY, que no está en la base: quien solo tiene
  acceso a la base no puede recalcular la cadena.
- Borrar los últimos eventos no rompe la cadena. Para detectarlo, se compara contra
  un "ancla" (el último número y sello informados por una verificación anterior).
- Además, un trigger en PostgreSQL impide UPDATE y DELETE sobre eventos ya sellados.
"""
import hashlib
import hmac
import json
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session as DBSession

from config import settings
from models import AuditEvent

GENESIS = "0" * 64
_LOCK_ID = 724_100  # pg_advisory_xact_lock: serializa el agregado de eventos a la cadena


def _key() -> bytes:
    return hashlib.sha256(b"audit-chain:" + settings.SECRET_KEY.encode()).digest()


def _id(value) -> Optional[str]:
    return str(value) if value is not None else None


def canonical(ev: AuditEvent) -> bytes:
    """Representación estable del evento: lo que queda sellado."""
    body = {
        "seq": ev.chain_seq,
        "id": _id(ev.id),
        "ts": ev.timestamp.isoformat(timespec="microseconds"),
        "type": ev.event_type,
        "user": _id(ev.user_id),
        "session": _id(ev.session_id),
        "ip": ev.ip_address,
        "ua": ev.user_agent,
        "data": ev.event_data or {},
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def seal(prev_hash: str, ev: AuditEvent) -> str:
    return hmac.new(_key(), prev_hash.encode() + b"|" + canonical(ev), hashlib.sha256).hexdigest()


def _lock(db: DBSession) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_ID})


def _last(db: DBSession):
    return (db.query(AuditEvent.chain_seq, AuditEvent.event_hash)
            .filter(AuditEvent.chain_seq.isnot(None))
            .order_by(AuditEvent.chain_seq.desc())
            .first())


def append(db: DBSession, ev: AuditEvent) -> AuditEvent:
    """Sella el evento como el siguiente de la cadena. Se agrega a la sesión; el commit es del llamador."""
    _lock(db)
    last = _last(db)
    ev.id = ev.id or uuid.uuid4()
    ev.timestamp = ev.timestamp or datetime.utcnow()
    ev.chain_seq = (last.chain_seq + 1) if last else 1
    ev.prev_hash = last.event_hash if last else GENESIS
    ev.event_hash = seal(ev.prev_hash, ev)
    db.add(ev)
    return ev


def seal_pending(db: DBSession) -> int:
    """Sella, en orden cronológico, los eventos anteriores a la cadena (migración desde la v1/v2)."""
    _lock(db)
    pending = (db.query(AuditEvent)
               .filter(AuditEvent.chain_seq.is_(None))
               .order_by(AuditEvent.timestamp, AuditEvent.id)
               .all())
    last = _last(db)
    seq, prev = (last.chain_seq, last.event_hash) if last else (0, GENESIS)
    for ev in pending:
        seq += 1
        ev.timestamp = ev.timestamp or datetime.utcnow()
        ev.chain_seq, ev.prev_hash = seq, prev
        ev.event_hash = seal(prev, ev)
        prev = ev.event_hash
    db.commit()
    return len(pending)


def verify(db: DBSession) -> Dict[str, Any]:
    """Recorre la cadena completa y devuelve el primer punto donde no cierra."""
    prev, expected, checked = GENESIS, 1, 0
    for ev in (db.query(AuditEvent)
               .filter(AuditEvent.chain_seq.isnot(None))
               .order_by(AuditEvent.chain_seq)
               .yield_per(1000)):
        problem = None
        if ev.chain_seq != expected:
            problem = f"Faltan eventos: se esperaba el n.º {expected} y sigue el n.º {ev.chain_seq}"
        elif ev.prev_hash != prev:
            problem = "El enlace con el evento anterior no coincide"
        elif not hmac.compare_digest(seal(prev, ev), ev.event_hash or ""):
            problem = "El contenido del evento fue modificado"
        if problem:
            return {
                "intact": False,
                "checked": checked,
                "broken_at": {
                    "seq": ev.chain_seq,
                    "id": str(ev.id),
                    "timestamp": ev.timestamp.isoformat() + "Z" if ev.timestamp else None,
                    "event_type": ev.event_type,
                    "reason": problem,
                },
            }
        prev, expected, checked = ev.event_hash, expected + 1, checked + 1

    unsealed = db.query(AuditEvent).filter(AuditEvent.chain_seq.is_(None)).count()
    return {
        "intact": unsealed == 0,
        "checked": checked,
        "unsealed": unsealed,
        "anchor": {"seq": expected - 1, "hash": prev},
        "verified_at": datetime.utcnow().isoformat() + "Z",
    }


GUARD_SQL = [
    """
    CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'audit_events es de solo agregado: no se pueden borrar eventos';
      END IF;
      IF OLD.chain_seq IS NOT NULL THEN
        RAISE EXCEPTION 'audit_events es de solo agregado: el evento % ya está sellado', OLD.chain_seq;
      END IF;
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql
    """,
    "DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events",
    """
    CREATE TRIGGER audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only()
    """,
]


def install_guard(conn) -> None:
    """Trigger de PostgreSQL que rechaza UPDATE/DELETE de eventos ya sellados."""
    for stmt in GUARD_SQL:
        conn.execute(text(stmt))
