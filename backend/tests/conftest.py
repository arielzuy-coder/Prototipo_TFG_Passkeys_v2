"""
Configuración de tests. Requiere PostgreSQL (TEST_DATABASE_URL); la base se recrea en cada test.

    TEST_DATABASE_URL=postgresql://postgres@localhost/auth_test pytest -q
"""
import os
import sys

import pytest

TEST_DB = os.environ.get("TEST_DATABASE_URL", "postgresql://postgres@localhost:5432/auth_test")
os.environ.update({
    "DATABASE_URL": TEST_DB,
    "SECRET_KEY": "test-secret",
    "JWT_SECRET": "test-jwt-secret",
    "RP_ID": "localhost",
    "RP_NAME": "TFG Test",
    "ORIGIN": "http://localhost:3000",
})
for var in ("SMTP_HOST", "SMTP_FROM", "BOOTSTRAP_ADMIN_EMAIL", "CORS_ORIGINS"):
    os.environ.pop(var, None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

import app as app_module  # noqa: E402
from database import SessionLocal, engine  # noqa: E402
from models import Base, User  # noqa: E402
from routers import auth_routes  # noqa: E402
from services.common import create_invitation  # noqa: E402
from tests.softauthn import SoftAuthenticator  # noqa: E402

RP_ID, ORIGIN = "localhost", "http://localhost:3000"


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


class RiskStub:
    """Fija la decisión del motor de riesgo para aislar los tests de autenticación."""

    def __init__(self):
        self.action = "allow"
        self.score = 10.0

    def evaluate_risk(self, user, ip_address, user_agent, db, credential_id=None):
        level = "low" if self.score < 40 else "medium" if self.score < 75 else "high"
        return {"score": self.score, "level": level, "factors": {},
                "context": {"location": {"display": "Test", "country": "AR"}, "user_id": user.id}}

    def evaluate_policies(self, user, risk_score, context, db):
        return {"action": self.action, "policy_name": f"test_{self.action}"}


@pytest.fixture(autouse=True)
def risk(monkeypatch):
    stub = RiskStub()
    monkeypatch.setattr(auth_routes.risk_engine, "evaluate_risk", stub.evaluate_risk)
    monkeypatch.setattr(auth_routes.risk_engine, "_get_location_from_ip", lambda ip: {"display": "Test"})
    monkeypatch.setattr(auth_routes.policy_engine, "evaluate_policies", stub.evaluate_policies)
    return stub


@pytest.fixture
def client():
    return TestClient(app_module.app)


def new_invitation(email: str, role: str = "user") -> str:
    db = SessionLocal()
    try:
        user = User(email=email, display_name=email.split("@")[0], role=role, status="pending")
        db.add(user)
        db.commit()
        db.refresh(user)
        return create_invitation(db, user, "enroll")["token"]
    finally:
        db.close()


def enroll(client, token: str, authn: SoftAuthenticator = None, device="Test device"):
    authn = authn or SoftAuthenticator(RP_ID, ORIGIN)
    opts = client.post("/auth/register/begin", json={"invitation_token": token})
    assert opts.status_code == 200, opts.text
    cred = authn.create(opts.json())
    r = client.post("/auth/register/complete",
                    json={"invitation_token": token, "credential": cred, "device_name": device})
    return authn, r


def login(client, email: str, authn: SoftAuthenticator, **get_kwargs):
    opts = client.post("/auth/login/begin", json={"email": email})
    if opts.status_code != 200:
        return opts
    cred = authn.get(opts.json(), **get_kwargs)
    return client.post("/auth/login/complete", json={"email": email, "credential": cred})


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def make_user(client):
    """Crea un usuario enrolado y logueado. Devuelve (authenticator, tokens)."""

    def _make(email: str, role: str = "user"):
        authn, r = enroll(client, new_invitation(email, role))
        assert r.status_code == 200, r.text
        r = login(client, email, authn)
        assert r.status_code == 200, r.text
        return authn, r.json()["tokens"]

    return _make
