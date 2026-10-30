"""RNF-U2: cuestionario SUS anónimo y resultados para auditoría."""
from routers.sus_routes import sus_score
from tests.conftest import bearer

BEST = [5, 1, 5, 1, 5, 1, 5, 1, 5, 1]
WORST = [1, 5, 1, 5, 1, 5, 1, 5, 1, 5]
NEUTRAL = [3] * 10


def test_scoring_follows_brooke():
    assert sus_score(BEST) == 100
    assert sus_score(WORST) == 0
    assert sus_score(NEUTRAL) == 50
    assert sus_score([4, 2, 4, 2, 4, 2, 4, 2, 4, 2]) == 75


def test_submit_is_anonymous_and_validated(client):
    r = client.post("/sus", json={"answers": BEST, "profile": "usuario", "comment": "Muy simple"})
    assert r.status_code == 200 and r.json()["score"] == 100
    assert client.post("/sus", json={"answers": [3] * 9}).status_code == 422
    assert client.post("/sus", json={"answers": [0] + [3] * 9}).status_code == 422


def test_results_only_for_audit_roles(client, make_user):
    _, admin = make_user("admin@empresa.com", "admin")
    _, user = make_user("ana@empresa.com", "user")
    for answers in (BEST, NEUTRAL, [4, 2, 4, 2, 4, 2, 4, 2, 4, 2]):
        client.post("/sus", json={"answers": answers})
    assert client.get("/api/audit/sus", headers=bearer(user["access_token"])).status_code == 403
    data = client.get("/api/audit/sus", headers=bearer(admin["access_token"])).json()
    assert data["count"] == 3 and data["mean"] == 75.0 and data["median"] == 75.0
    assert data["meets_target"] is True and len(data["item_means"]) == 10
