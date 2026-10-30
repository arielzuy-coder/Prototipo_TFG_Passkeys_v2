"""RNF-S4: registro de auditoría encadenado, a prueba de alteraciones."""
import pytest
from sqlalchemy import text

from database import SessionLocal, engine
from models import AuditEvent
from services import audit_chain
from services.common import audit
from tests.conftest import bearer


def _add_events(n):
    db = SessionLocal()
    try:
        for i in range(n):
            audit(db, "test_event", data={"i": i, "score": 41.25, "texto": "ubicación"})
    finally:
        db.close()


def _raw(sql, **params):
    """Simula a alguien con acceso directo a la base (sin pasar por la aplicación)."""
    with engine.begin() as conn:
        conn.execute(text(sql), params)


def _verify():
    db = SessionLocal()
    try:
        return audit_chain.verify(db)
    finally:
        db.close()


def test_chain_is_built_and_verifies():
    _add_events(5)
    result = _verify()
    assert result["intact"] is True and result["checked"] == 5
    assert result["anchor"]["seq"] == 5 and len(result["anchor"]["hash"]) == 64

    db = SessionLocal()
    events = db.query(AuditEvent).order_by(AuditEvent.chain_seq).all()
    assert [e.chain_seq for e in events] == [1, 2, 3, 4, 5]
    assert events[0].prev_hash == audit_chain.GENESIS
    assert all(b.prev_hash == a.event_hash for a, b in zip(events, events[1:]))
    db.close()


def test_modified_event_is_detected():
    _add_events(5)
    _raw("UPDATE audit_events SET event_data = '{\"i\": 99}' WHERE chain_seq = 3")
    result = _verify()
    assert result["intact"] is False
    assert result["broken_at"]["seq"] == 3
    assert "modificado" in result["broken_at"]["reason"]


def test_deleted_event_is_detected():
    _add_events(5)
    _raw("DELETE FROM audit_events WHERE chain_seq = 2")
    result = _verify()
    assert result["intact"] is False
    assert result["broken_at"]["seq"] == 3
    assert "Faltan eventos" in result["broken_at"]["reason"]


def test_recomputing_without_the_key_does_not_help():
    """Un atacante que reescribe el evento y recalcula un hash sin la clave del servidor queda expuesto."""
    import hashlib
    _add_events(3)
    forged = hashlib.sha256(b"falso").hexdigest()
    _raw("UPDATE audit_events SET event_type = 'auth_success', event_hash = :h WHERE chain_seq = 2", h=forged)
    result = _verify()
    assert result["intact"] is False and result["broken_at"]["seq"] == 2


def test_legacy_events_are_sealed_on_migration():
    _raw("INSERT INTO audit_events (id, event_type, event_data, timestamp) "
         "VALUES (gen_random_uuid(), 'legacy', '{}', now() - interval '1 day')")
    _add_events(2)
    assert _verify()["unsealed"] == 1
    db = SessionLocal()
    assert audit_chain.seal_pending(db) == 1
    db.close()
    result = _verify()
    assert result["intact"] is True and result["checked"] == 3


def test_database_guard_blocks_update_and_delete():
    with engine.begin() as conn:
        audit_chain.install_guard(conn)
    _add_events(2)
    with pytest.raises(Exception):
        _raw("UPDATE audit_events SET event_type = 'x' WHERE chain_seq = 1")
    with pytest.raises(Exception):
        _raw("DELETE FROM audit_events WHERE chain_seq = 1")
    assert _verify()["intact"] is True


def test_integrity_endpoint_requires_audit_role(client, make_user):
    _, admin = make_user("admin@empresa.com", "admin")
    _, user = make_user("ana@empresa.com", "user")
    assert client.get("/api/audit/integrity", headers=bearer(user["access_token"])).status_code == 403
    r = client.get("/api/audit/integrity", headers=bearer(admin["access_token"]))
    assert r.status_code == 200 and r.json()["intact"] is True and r.json()["checked"] >= 1
