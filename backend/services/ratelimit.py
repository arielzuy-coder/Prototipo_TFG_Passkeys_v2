"""
Límite de intentos con contadores de ventana fija en PostgreSQL.

Se guarda en la base (no en memoria) para que funcione con varias instancias o workers.
Las claves con email se guardan hasheadas para no dejar datos personales en la tabla.
"""
import hashlib
import math
import random
from datetime import datetime, timedelta

from fastapi import HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.orm import Session as DBSession

from config import settings
from services.common import client_ip

_UPSERT = text("""
    INSERT INTO rate_limits (key, window_start, count) VALUES (:key, :now, 1)
    ON CONFLICT (key) DO UPDATE SET
        count = CASE WHEN rate_limits.window_start < :cutoff THEN 1 ELSE rate_limits.count + 1 END,
        window_start = CASE WHEN rate_limits.window_start < :cutoff THEN :now ELSE rate_limits.window_start END
    RETURNING count, window_start
""")

# (límite, ventana en segundos) por operación y dimensión
LIMITS = {
    "login:ip": (30, 300),
    "login:account": (10, 300),
    "login_failed:ip": (10, 300),
    "invitation:ip": (30, 300),
    "register:ip": (20, 3600),
    "stepup:ip": (30, 300),
    "refresh:ip": (60, 300),
    "reauth:account": (20, 300),
    "sus:ip": (10, 3600),
}


def _hash(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()[:32]


def hit(db: DBSession, bucket: str, identity: str) -> None:
    """Cuenta un intento; si se supera el límite responde 429 con Retry-After."""
    if not settings.RATE_LIMIT_ENABLED:
        return
    limit, window = LIMITS[bucket]
    now = datetime.utcnow()
    key = f"{bucket}:{_hash(identity)}"
    count, window_start = db.execute(
        _UPSERT, {"key": key, "now": now, "cutoff": now - timedelta(seconds=window)}
    ).one()
    db.commit()
    if random.random() < 0.01:  # limpieza ocasional de ventanas viejas
        db.execute(text("DELETE FROM rate_limits WHERE window_start < :old"),
                   {"old": now - timedelta(days=1)})
        db.commit()
    if count > limit:
        retry = max(1, math.ceil((window_start + timedelta(seconds=window) - now).total_seconds()))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Demasiados intentos. Probá de nuevo en {math.ceil(retry / 60)} min.",
            headers={"Retry-After": str(retry)},
        )


def by_ip(db: DBSession, request: Request, operation: str) -> None:
    hit(db, f"{operation}:ip", client_ip(request))


def by_account(db: DBSession, operation: str, account: str) -> None:
    hit(db, f"{operation}:account", account)
