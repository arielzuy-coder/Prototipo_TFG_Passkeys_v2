"""
Tests de seguridad. Cada ataque de la revisión (docs/REVISION_SEGURIDAD.md) tiene
un test que lo reproduce y verifica que hoy falla.
"""
import base64
import json

from tests.conftest import (
    ORIGIN, RP_ID, bearer, enroll, login, new_invitation,
)
from tests.softauthn import SoftAuthenticator, b64url, unb64url


# ============================================================================
# Flujo legítimo
# ============================================================================
def test_enroll_and_login_happy_path(client):
    authn, r = enroll(client, new_invitation("ana@empresa.com"))
    assert r.status_code == 200, r.text
    r = login(client, "ana@empresa.com", authn)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["requires_stepup"] is False
    assert "refresh_jti" not in body["tokens"]
    me = client.get("/auth/me", headers=bearer(body["tokens"]["access_token"]))
    assert me.status_code == 200 and me.json()["email"] == "ana@empresa.com"


def test_sign_counter_is_taken_from_authenticator(client):
    authn, _ = enroll(client, new_invitation("ana@empresa.com"))
    for _ in range(3):
        assert login(client, "ana@empresa.com", authn).status_code == 200
    from database import SessionLocal
    from models import Passkey
    db = SessionLocal()
    assert db.query(Passkey).one().counter == 3
    db.close()


# ============================================================================
# H1 / H2: verificación WebAuthn real
# ============================================================================
def test_H1_garbage_signature_rejected(client):
    """PoC original: firma 'basura' sin autenticador."""
    authn, _ = enroll(client, new_invitation("victima@empresa.com"))
    opts = client.post("/auth/login/begin", json={"email": "victima@empresa.com"}).json()
    cred_id = opts["allowCredentials"][0]["id"]
    forged = {
        "id": cred_id, "rawId": cred_id, "type": "public-key", "clientExtensionResults": {},
        "response": {
            "clientDataJSON": b64url(json.dumps({"type": "webauthn.get", "challenge": opts["challenge"],
                                                 "origin": ORIGIN}).encode()),
            "authenticatorData": b64url(b"basura" * 7),
            "signature": b64url(b"basura"),
        },
    }
    r = client.post("/auth/login/complete", json={"email": "victima@empresa.com", "credential": forged})
    assert r.status_code == 401
    assert "tokens" not in r.text


def test_H1_tampered_signature_rejected(client):
    authn, _ = enroll(client, new_invitation("ana@empresa.com"))
    r = login(client, "ana@empresa.com", authn, tamper_signature=True)
    assert r.status_code == 401


def test_H1_other_users_key_rejected(client):
    """Una passkey válida de otro usuario no sirve para entrar a esta cuenta."""
    victim, _ = enroll(client, new_invitation("victima@empresa.com"))
    attacker, _ = enroll(client, new_invitation("atacante@empresa.com"))
    opts = client.post("/auth/login/begin", json={"email": "victima@empresa.com"}).json()
    attacker_cred = next(iter(attacker.credentials))
    cred = attacker.get({**opts, "allowCredentials": [{"id": b64url(attacker_cred)}]}, cred_id=attacker_cred)
    r = client.post("/auth/login/complete", json={"email": "victima@empresa.com", "credential": cred})
    assert r.status_code == 401


def test_H2_replayed_assertion_rejected(client):
    authn, _ = enroll(client, new_invitation("ana@empresa.com"))
    opts = client.post("/auth/login/begin", json={"email": "ana@empresa.com"}).json()
    cred = authn.get(opts)
    first = client.post("/auth/login/complete", json={"email": "ana@empresa.com", "credential": cred})
    assert first.status_code == 200
    replay = client.post("/auth/login/complete", json={"email": "ana@empresa.com", "credential": cred})
    assert replay.status_code == 401


def test_H2_self_chosen_challenge_rejected(client):
    """El atacante firma un challenge inventado por él (no emitido por el servidor)."""
    authn, _ = enroll(client, new_invitation("ana@empresa.com"))
    opts = client.post("/auth/login/begin", json={"email": "ana@empresa.com"}).json()
    cred = authn.get({**opts, "challenge": b64url(b"challenge-del-atacante-123456789")})
    r = client.post("/auth/login/complete", json={"email": "ana@empresa.com", "credential": cred})
    assert r.status_code == 401


def test_H2_wrong_origin_rejected(client):
    """Phishing: la misma passkey usada desde otro origen."""
    authn, _ = enroll(client, new_invitation("ana@empresa.com"))
    r = login(client, "ana@empresa.com", authn, origin="https://phishing.example")
    assert r.status_code == 401


def test_user_verification_required(client):
    authn = SoftAuthenticator(RP_ID, ORIGIN, user_verification=False)
    _, r = enroll(client, new_invitation("ana@empresa.com"), authn=authn)
    assert r.status_code == 400


# ============================================================================
# H3: enrolamiento solo con invitación
# ============================================================================
def test_H3_register_without_invitation_rejected(client):
    assert client.post("/auth/register/begin", json={"email": "x@empresa.com"}).status_code == 422
    assert client.post("/auth/register/begin", json={"invitation_token": "inventado"}).status_code == 401


def test_H3_invitation_is_single_use(client):
    token = new_invitation("ana@empresa.com")
    _, r = enroll(client, token)
    assert r.status_code == 200
    # Con la misma invitación, un tercero intenta agregar su passkey a la cuenta
    r = client.post("/auth/register/begin", json={"invitation_token": token})
    assert r.status_code == 401


def test_H3_cannot_add_passkey_to_active_account_without_session(client):
    authn, _ = enroll(client, new_invitation("victima@empresa.com"))
    r = client.post("/passkeys/register/begin")
    assert r.status_code == 401


def test_self_service_passkey_limit_and_last_passkey(client, make_user):
    authn, tokens = make_user("ana@empresa.com")
    h = bearer(tokens["access_token"])
    for i in range(4):
        opts = client.post("/passkeys/register/begin", headers=h)
        assert opts.status_code == 200, opts.text
        extra = SoftAuthenticator(RP_ID, ORIGIN)
        r = client.post("/passkeys/register/complete", headers=h,
                        json={"credential": extra.create(opts.json()), "device_name": f"extra {i}"})
        assert r.status_code == 200, r.text
    assert client.post("/passkeys/register/begin", headers=h).status_code == 409  # máximo 5

    passkeys = client.get("/passkeys", headers=h).json()["passkeys"]
    assert len(passkeys) == 5
    for pk in passkeys[1:]:
        assert client.delete(f"/passkeys/{pk['id']}", headers=h).status_code == 200
    assert client.delete(f"/passkeys/{passkeys[0]['id']}", headers=h).status_code == 409  # la última no


def test_cannot_revoke_other_users_passkey(client, make_user):
    _, victim_tokens = make_user("victima@empresa.com")
    _, attacker_tokens = make_user("atacante@empresa.com")
    victim_pk = client.get("/passkeys", headers=bearer(victim_tokens["access_token"])).json()["passkeys"][0]
    r = client.delete(f"/passkeys/{victim_pk['id']}", headers=bearer(attacker_tokens["access_token"]))
    assert r.status_code == 404


# ============================================================================
# H4 / H6: control de acceso
# ============================================================================
PROTECTED = [
    ("get", "/admin/policies"), ("get", "/admin/users"), ("get", "/passkeys"), ("get", "/me/events"),
    ("get", "/audit/events"), ("get", "/audit/stats"), ("get", "/risk/dashboard"),
    ("get", "/api/audit/statistics/summary"),
]


def test_H4_no_token_is_401(client):
    for method, path in PROTECTED:
        assert getattr(client, method)(path).status_code == 401, path


def test_H6_invalid_tokens_are_401_not_500(client):
    for token in ("a.b.c", "basura", ""):
        r = client.get("/auth/me", headers=bearer(token))
        assert r.status_code == 401, token


def test_H4_rbac_matrix(client, make_user):
    _, user = make_user("user@empresa.com", "user")
    _, auditor = make_user("auditor@empresa.com", "auditor")
    _, admin = make_user("admin@empresa.com", "admin")
    u, a, ad = (bearer(t["access_token"]) for t in (user, auditor, admin))

    # Usuario estándar: sin auditoría general ni administración
    for path in ("/audit/events", "/risk/dashboard", "/admin/policies", "/admin/users",
                 "/api/audit/statistics/summary"):
        assert client.get(path, headers=u).status_code == 403, path
    assert client.get("/me/events", headers=u).status_code == 200

    # Auditor: lectura de auditoría, sin configuración ni usuarios
    for path in ("/audit/events", "/audit/stats", "/risk/dashboard", "/api/audit/statistics/summary"):
        assert client.get(path, headers=a).status_code == 200, path
    assert client.get("/admin/policies", headers=a).status_code == 403
    assert client.post("/admin/users", headers=a, json={"email": "x@empresa.com"}).status_code == 403

    # Administrador
    assert client.get("/admin/policies", headers=ad).status_code == 200
    assert client.get("/audit/events", headers=ad).status_code == 200


def test_role_change_applies_immediately(client, make_user):
    _, admin = make_user("admin@empresa.com", "admin")
    _, user = make_user("user@empresa.com", "user")
    uid = client.get("/auth/me", headers=bearer(user["access_token"])).json()["id"]
    r = client.put(f"/admin/users/{uid}/role", headers=bearer(admin["access_token"]), json={"role": "auditor"})
    assert r.status_code == 200
    assert client.get("/audit/events", headers=bearer(user["access_token"])).status_code == 200


# ============================================================================
# H5 / H11: step-up
# ============================================================================
def test_H5_stepup_response_has_no_otp_and_passkey_stepup_works(client, risk):
    authn, _ = enroll(client, new_invitation("ana@empresa.com"))
    risk.action, risk.score = "stepup", 55.0
    r = login(client, "ana@empresa.com", authn)
    assert r.status_code == 200
    body = r.json()
    assert body["requires_stepup"] is True and "tokens" not in body
    assert "otp" not in json.dumps(body).lower().replace("verification_methods", "")
    assert "otp" not in body["verification_methods"]  # SMTP no configurado
    # La pantalla de step-up explica la decisión: puntaje, umbrales y política aplicada
    assessment = body["risk_assessment"]
    assert assessment["computed_score"] == 55.0
    assert assessment["thresholds"] == {"low": 40, "high": 75}
    assert assessment["policy"]["name"] == "test_stepup"

    token = body["stepup_token"]
    opts = client.post("/auth/stepup/passkey/begin", json={"stepup_token": token})
    assert opts.status_code == 200
    r = client.post("/auth/stepup/verify", json={"stepup_token": token, "verification_type": "passkey",
                                                 "credential": authn.get(opts.json())})
    assert r.status_code == 200, r.text
    assert "access_token" in r.json()["tokens"]
    # El token de step-up no se puede reutilizar
    r = client.post("/auth/stepup/passkey/begin", json={"stepup_token": token})
    assert r.status_code == 401


def test_stepup_cannot_use_login_challenge(client, risk):
    authn, _ = enroll(client, new_invitation("ana@empresa.com"))
    risk.action = "stepup"
    token = login(client, "ana@empresa.com", authn).json()["stepup_token"]
    login_opts = client.post("/auth/login/begin", json={"email": "ana@empresa.com"}).json()
    r = client.post("/auth/stepup/verify", json={"stepup_token": token, "verification_type": "passkey",
                                                 "credential": authn.get(login_opts)})
    assert r.status_code == 401


def test_old_biometric_and_pin_bypass_rejected(client, risk):
    """La v1 aceptaba 'biometric' sin verificar y cualquier PIN de 4 dígitos."""
    authn, _ = enroll(client, new_invitation("ana@empresa.com"))
    risk.action = "stepup"
    token = login(client, "ana@empresa.com", authn).json()["stepup_token"]
    for vt, data in (("biometric", {}), ("pin", {"pin": "1234"})):
        r = client.post("/auth/stepup/verify", json={"stepup_token": token, "verification_type": vt,
                                                     "verification_data": data})
        assert r.status_code == 400


def test_H11_stepup_locks_after_max_attempts(client, risk):
    authn, _ = enroll(client, new_invitation("ana@empresa.com"))
    risk.action = "stepup"
    token = login(client, "ana@empresa.com", authn).json()["stepup_token"]
    for _ in range(5):
        opts = client.post("/auth/stepup/passkey/begin", json={"stepup_token": token}).json()
        r = client.post("/auth/stepup/verify", json={"stepup_token": token, "verification_type": "passkey",
                                                     "credential": authn.get(opts, tamper_signature=True)})
        assert r.status_code == 401
    # Bloqueado: ni siquiera una verificación correcta lo destraba
    assert client.post("/auth/stepup/passkey/begin", json={"stepup_token": token}).status_code == 401


def test_supervisor_approval_flow(client, risk, make_user):
    _, admin = make_user("admin@empresa.com", "admin")
    authn, _ = enroll(client, new_invitation("ana@empresa.com"))
    risk.action = "stepup"
    token = login(client, "ana@empresa.com", authn).json()["stepup_token"]

    assert client.post("/auth/stepup/supervisor/request", json={"stepup_token": token}).status_code == 200
    pending = client.post("/auth/stepup/verify", json={"stepup_token": token, "verification_type": "supervisor"})
    assert pending.status_code == 202

    reqs = client.get("/admin/stepup/pending", headers=bearer(admin["access_token"])).json()["requests"]
    assert len(reqs) == 1
    r = client.post(f"/admin/stepup/{reqs[0]['id']}/approve", headers=bearer(admin["access_token"]))
    assert r.status_code == 200
    r = client.post("/auth/stepup/verify", json={"stepup_token": token, "verification_type": "supervisor"})
    assert r.status_code == 200 and "access_token" in r.json()["tokens"]


def test_supervisor_denial_and_self_approval(client, risk, make_user):
    admin_authn, admin = make_user("admin@empresa.com", "admin")
    risk.action = "stepup"
    token = login(client, "admin@empresa.com", admin_authn).json()["stepup_token"]
    client.post("/auth/stepup/supervisor/request", json={"stepup_token": token})
    req = client.get("/admin/stepup/pending", headers=bearer(admin["access_token"])).json()["requests"][0]
    # No puede aprobar su propio acceso
    assert client.post(f"/admin/stepup/{req['id']}/approve", headers=bearer(admin["access_token"])).status_code == 403


# ============================================================================
# Tokens: rotación de refresh, logout, suspensión
# ============================================================================
def test_refresh_rotation_and_reuse_detection(client, make_user):
    _, tokens = make_user("ana@empresa.com")
    r1 = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r1.status_code == 200
    new = r1.json()
    assert new["refresh_token"] != tokens["refresh_token"] and "refresh_jti" not in new
    # Reuso del refresh anterior: se revoca la sesión completa
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": new["refresh_token"]}).status_code == 401
    assert client.get("/auth/me", headers=bearer(new["access_token"])).status_code == 401


def test_access_token_not_accepted_as_refresh(client, make_user):
    _, tokens = make_user("ana@empresa.com")
    assert client.post("/auth/refresh", json={"refresh_token": tokens["access_token"]}).status_code == 401


def test_logout_revokes_session(client, make_user):
    _, tokens = make_user("ana@empresa.com")
    h = bearer(tokens["access_token"])
    assert client.post("/auth/logout", headers=h).status_code == 200
    assert client.get("/auth/me", headers=h).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_suspension_cuts_access_immediately(client, make_user):
    _, admin = make_user("admin@empresa.com", "admin")
    authn, user = make_user("ana@empresa.com")
    uid = client.get("/auth/me", headers=bearer(user["access_token"])).json()["id"]
    assert client.post(f"/admin/users/{uid}/suspend", headers=bearer(admin["access_token"])).status_code == 200
    assert client.get("/auth/me", headers=bearer(user["access_token"])).status_code == 401
    assert login(client, "ana@empresa.com", authn).status_code == 401


# ============================================================================
# Alta y recuperación por el administrador
# ============================================================================
def test_admin_invites_user_end_to_end(client, make_user):
    _, admin = make_user("admin@empresa.com", "admin")
    r = client.post("/admin/users", headers=bearer(admin["access_token"]),
                    json={"email": "Nuevo@Empresa.com", "role": "auditor"})
    assert r.status_code == 200, r.text
    inv = r.json()["invitation"]
    assert inv["url"].startswith(f"{ORIGIN}/enroll?invite=")
    info = client.get(f"/auth/invitations/{inv['token']}")
    assert info.status_code == 200 and info.json()["email"] == "nuevo@empresa.com"
    authn, r = enroll(client, inv["token"])
    assert r.status_code == 200
    assert login(client, "nuevo@empresa.com", authn).status_code == 200


def test_recovery_revokes_old_passkeys(client, make_user):
    _, admin = make_user("admin@empresa.com", "admin")
    old_authn, user = make_user("ana@empresa.com")
    uid = client.get("/auth/me", headers=bearer(user["access_token"])).json()["id"]
    r = client.post(f"/admin/users/{uid}/recovery", headers=bearer(admin["access_token"]))
    assert r.status_code == 200
    token = r.json()["invitation"]["token"]
    # La sesión y la passkey anteriores ya no sirven
    assert client.get("/auth/me", headers=bearer(user["access_token"])).status_code == 401
    assert login(client, "ana@empresa.com", old_authn).status_code == 401
    # Re-enrolamiento con un dispositivo nuevo
    new_authn, r = enroll(client, token)
    assert r.status_code == 200
    assert login(client, "ana@empresa.com", new_authn).status_code == 200


def test_admin_cannot_act_on_self(client, make_user):
    _, admin = make_user("admin@empresa.com", "admin")
    h = bearer(admin["access_token"])
    uid = client.get("/auth/me", headers=h).json()["id"]
    assert client.post(f"/admin/users/{uid}/suspend", headers=h).status_code == 400
    assert client.put(f"/admin/users/{uid}/role", headers=h, json={"role": "user"}).status_code == 400


# ============================================================================
# H8: CORS
# ============================================================================
def test_H8_cors_rejects_foreign_onrender_origin(client):
    evil = client.options("/auth/login/begin", headers={
        "Origin": "https://sitio-del-atacante.onrender.com", "Access-Control-Request-Method": "POST"})
    assert evil.headers.get("access-control-allow-origin") is None
    good = client.options("/auth/login/begin", headers={
        "Origin": ORIGIN, "Access-Control-Request-Method": "POST"})
    assert good.headers.get("access-control-allow-origin") == ORIGIN


# ============================================================================
# H7: dispositivos por usuario
# ============================================================================
def test_H7_same_browser_two_users_each_get_their_device(client, monkeypatch):
    from database import SessionLocal
    from models import Device
    enroll(client, new_invitation("ana@empresa.com"))
    enroll(client, new_invitation("bruno@empresa.com"))  # mismo User-Agent del TestClient
    db = SessionLocal()
    owners = {d.user_id for d in db.query(Device).all()}
    db.close()
    assert len(owners) == 2
