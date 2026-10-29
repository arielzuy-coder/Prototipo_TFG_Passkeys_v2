"""Fase 3: IP del cliente, límites de intentos, dispositivos, verificación continua y re-autenticación."""
from datetime import datetime, timedelta

import jwt
import pytest
from starlette.requests import Request

from config import settings
from database import SessionLocal
from models import AuditEvent, Device, Session as SessionModel, User
from tests.conftest import bearer, enroll, login, new_invitation

UA_A = "Mozilla/5.0 (X11; Linux x86_64) Chrome/150 Navegador-A"
UA_B = "Mozilla/5.0 (Windows NT 10.0) Firefox/140 Navegador-B"


def session_of(tokens):
    sid = jwt.decode(tokens["access_token"], options={"verify_signature": False})["session_id"]
    db = SessionLocal()
    s = db.query(SessionModel).filter(SessionModel.id == sid).one()
    db.expunge(s)
    db.close()
    return s


def update_session(tokens, **fields):
    sid = jwt.decode(tokens["access_token"], options={"verify_signature": False})["session_id"]
    db = SessionLocal()
    db.query(SessionModel).filter(SessionModel.id == sid).update(fields)
    db.commit()
    db.close()


def reauth(client, authn, headers):
    opts = client.post("/auth/reauth/begin", headers=headers)
    assert opts.status_code == 200, opts.text
    return client.post("/auth/reauth/complete", headers=headers, json={"credential": authn.get(opts.json())})


def fake_request(peer="10.0.0.5", headers=None):
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "headers": raw, "client": (peer, 1234), "method": "GET", "path": "/"})


@pytest.fixture
def geo_map(monkeypatch):
    """Geolocalización falsa por IP para los tests de verificación continua."""
    table = {}

    def lookup(ip):
        cc = table.get(ip, "AR")
        return {"country": cc, "country_name": cc, "city": "X", "display": f"Ciudad {cc}"}

    from auth import continuous
    from routers import auth_routes
    monkeypatch.setattr(continuous.geo, "lookup", lookup)
    monkeypatch.setattr(auth_routes.geo, "lookup", lookup)
    monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 1)
    return table


# ============================================================================
# H9: IP del cliente
# ============================================================================
def test_H9_client_ip_ignores_forwarded_for_without_trusted_proxy(monkeypatch):
    from services.common import client_ip
    monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 0)
    assert client_ip(fake_request(headers={"X-Forwarded-For": "6.6.6.6"})) == "10.0.0.5"


def test_H9_client_ip_uses_only_trusted_hops(monkeypatch):
    from services.common import client_ip
    monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 1)
    # El cliente inventa "6.6.6.6"; el proxy agrega la IP real al final
    req = fake_request(headers={"X-Forwarded-For": "6.6.6.6, 200.1.2.3"})
    assert client_ip(req) == "200.1.2.3"
    monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 2)
    req = fake_request(headers={"X-Forwarded-For": "6.6.6.6, 200.1.2.3, 10.1.1.1"})
    assert client_ip(req) == "200.1.2.3"
    # Basura en el header: se usa la IP de la conexión
    assert client_ip(fake_request(headers={"X-Forwarded-For": "no-es-ip"})) == "10.0.0.5"


def test_H9_client_ip_header(monkeypatch):
    from services.common import client_ip
    monkeypatch.setattr(settings, "CLIENT_IP_HEADER", "true-client-ip")
    assert client_ip(fake_request(headers={"True-Client-IP": "181.2.3.4"})) == "181.2.3.4"


def test_H9_private_ips_are_not_assumed_argentina(monkeypatch):
    from risk import geo
    monkeypatch.setattr(settings, "LOCAL_IP_COUNTRY", None)
    assert geo.lookup("10.20.30.40")["country"] == "Unknown"
    assert geo.lookup("127.0.0.1")["country"] == "Unknown"
    monkeypatch.setattr(settings, "LOCAL_IP_COUNTRY", "AR")
    assert geo.lookup("192.168.1.10")["country"] == "AR"


def test_H9_geolocation_can_be_disabled(monkeypatch):
    from risk import geo
    monkeypatch.setattr(settings, "GEOIP_PROVIDER", "none")
    monkeypatch.setattr(geo.requests, "get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no debe llamar")))
    assert geo.lookup("8.8.8.8")["country"] == "Unknown"


# ============================================================================
# H11: límites de intentos
# ============================================================================
def test_H11_login_rate_limit_per_account(client):
    enroll(client, new_invitation("ana@empresa.com"))
    codes = [client.post("/auth/login/begin", json={"email": "ana@empresa.com"}).status_code for _ in range(11)]
    assert codes[:10] == [200] * 10
    assert codes[10] == 429
    r = client.post("/auth/login/begin", json={"email": "ana@empresa.com"})
    assert int(r.headers["retry-after"]) > 0


def test_H11_login_failed_is_rate_limited_and_not_counted_as_failure(client):
    from risk.risk_engine import RiskEngine
    enroll(client, new_invitation("ana@empresa.com"))
    codes = [client.post("/auth/login/failed", json={"email": "ana@empresa.com", "reason": "x"}).status_code
             for _ in range(11)]
    assert codes[-1] == 429
    db = SessionLocal()
    user = db.query(User).filter(User.email == "ana@empresa.com").one()
    assert db.query(AuditEvent).filter(AuditEvent.event_type == "auth_aborted").count() == 10
    # Un tercero no puede inflar el riesgo de la cuenta informando fallos falsos
    assert RiskEngine()._evaluate_failed_attempts(user, db)["count"] == 0
    db.close()


def test_failed_attempts_window_is_one_hour_in_utc(client):
    from risk.risk_engine import RiskEngine
    enroll(client, new_invitation("ana@empresa.com"))
    db = SessionLocal()
    user = db.query(User).filter(User.email == "ana@empresa.com").one()
    db.add(AuditEvent(user_id=user.id, event_type="auth_failed", timestamp=datetime.utcnow() - timedelta(hours=2)))
    db.add(AuditEvent(user_id=user.id, event_type="auth_failed", timestamp=datetime.utcnow() - timedelta(minutes=10)))
    db.commit()
    assert RiskEngine()._evaluate_failed_attempts(user, db)["count"] == 1  # el de hace 2 h queda afuera
    db.close()


# ============================================================================
# H7: dispositivo atado a la passkey
# ============================================================================
def test_H7_known_fingerprint_with_unseen_passkey_is_not_trusted(client):
    from risk.risk_engine import RiskEngine
    from services.common import device_fingerprint
    enroll(client, new_invitation("ana@empresa.com"))
    db = SessionLocal()
    user = db.query(User).filter(User.email == "ana@empresa.com").one()
    device = db.query(Device).filter(Device.user_id == user.id).one()
    enrolled_cred = device.credential_ids[0]
    ua = "testclient"
    base = {"browser": "Other", "os": "Other", "user_agent": ua, "user_id": user.id}
    assert device.device_fingerprint == device_fingerprint(ua)
    engine = RiskEngine()
    assert engine._evaluate_device_risk({**base, "credential_id": enrolled_cred}, db)["known"] is True
    # Misma huella (User-Agent copiado) pero con una passkey que nunca se usó desde ahí
    assert engine._evaluate_device_risk({**base, "credential_id": "otra-passkey"}, db)["known"] is False
    db.close()


# ============================================================================
# UC-03: verificación continua
# ============================================================================
def test_token_from_another_browser_revokes_session(client, make_user):
    _, tokens = make_user("ana@empresa.com")
    h = bearer(tokens["access_token"])
    assert client.get("/auth/me", headers=h).status_code == 200
    stolen = client.get("/auth/me", headers={**h, "User-Agent": UA_B})
    assert stolen.status_code == 401
    # La sesión quedó revocada también para el navegador original
    assert client.get("/auth/me", headers=h).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_refresh_token_from_another_browser_is_rejected(client, make_user):
    _, tokens = make_user("ana@empresa.com")
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}, headers={"User-Agent": UA_B})
    assert r.status_code == 401
    assert session_of(tokens).revoked is True


def test_ip_change_same_country_continues(client, make_user, geo_map):
    _, tokens = make_user("ana@empresa.com")
    h = {**bearer(tokens["access_token"]), "X-Forwarded-For": "181.1.1.1"}
    assert client.get("/auth/me", headers=h).status_code == 200
    assert session_of(tokens).ip_address == "181.1.1.1"


def test_ip_change_to_another_country_requires_reauth(client, make_user, geo_map):
    authn, tokens = make_user("ana@empresa.com")
    update_session(tokens, country="AR")
    geo_map["5.5.5.5"] = "RU"
    h = {**bearer(tokens["access_token"]), "X-Forwarded-For": "5.5.5.5"}
    r = client.get("/passkeys", headers=h)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    assert reauth(client, authn, h).status_code == 200
    assert client.get("/passkeys", headers=h).status_code == 200
    assert session_of(tokens).country == "RU"


def test_periodic_reevaluation_stepup_requires_reauth(client, make_user, risk):
    authn, tokens = make_user("ana@empresa.com")
    h = bearer(tokens["access_token"])
    update_session(tokens, last_evaluated_at=datetime.utcnow() - timedelta(hours=1))
    risk.action = "stepup"
    r = client.get("/passkeys", headers=h)
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "policy_stepup"
    assert reauth(client, authn, h).status_code == 200
    assert client.get("/passkeys", headers=h).status_code == 200  # recién reevaluada


def test_periodic_reevaluation_deny_revokes(client, make_user, risk):
    _, tokens = make_user("ana@empresa.com")
    update_session(tokens, last_evaluated_at=datetime.utcnow() - timedelta(hours=1))
    risk.action = "deny"
    assert client.get("/passkeys", headers=bearer(tokens["access_token"])).status_code == 401
    assert session_of(tokens).revoked is True


def test_reauth_rejects_bad_signature(client, make_user):
    authn, tokens = make_user("ana@empresa.com")
    h = bearer(tokens["access_token"])
    opts = client.post("/auth/reauth/begin", headers=h).json()
    r = client.post("/auth/reauth/complete", headers=h, json={"credential": authn.get(opts, tamper_signature=True)})
    assert r.status_code == 401


# ============================================================================
# Operaciones sensibles del administrador
# ============================================================================
def test_admin_changes_require_recent_strong_auth(client, make_user):
    authn, admin = make_user("admin@empresa.com", "admin")
    h = bearer(admin["access_token"])
    update_session(admin, strong_auth_at=datetime.utcnow() - timedelta(hours=1))
    # Leer sigue permitido
    assert client.get("/admin/users", headers=h).status_code == 200
    # Modificar exige confirmar identidad
    r = client.post("/admin/users", headers=h, json={"email": "x@empresa.com"})
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "sensitive_operation"
    assert reauth(client, authn, h).status_code == 200
    assert client.post("/admin/users", headers=h, json={"email": "x@empresa.com"}).status_code == 200


# ============================================================================
# Sesiones propias
# ============================================================================
def test_list_and_revoke_own_sessions(client, make_user):
    authn, t1 = make_user("ana@empresa.com")
    t2 = login(client, "ana@empresa.com", authn).json()["tokens"]
    sessions = client.get("/me/sessions", headers=bearer(t1["access_token"])).json()["sessions"]
    assert len(sessions) == 2 and sum(s["current"] for s in sessions) == 1
    other = next(s for s in sessions if not s["current"])
    assert client.delete(f"/me/sessions/{other['id']}", headers=bearer(t1["access_token"])).status_code == 200
    assert client.get("/auth/me", headers=bearer(t2["access_token"])).status_code == 401
    assert client.get("/auth/me", headers=bearer(t1["access_token"])).status_code == 200
