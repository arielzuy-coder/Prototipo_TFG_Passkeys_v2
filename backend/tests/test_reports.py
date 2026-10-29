"""Reportes de auditoría (UC-06): nombres de eventos reales y exportación."""
from tests.conftest import bearer, login


def test_report_counts_real_events_and_export_never_crashes(client, make_user, risk):
    authn, admin = make_user("admin@empresa.com", "admin")
    risk.action = "stepup"
    login(client, "admin@empresa.com", authn)  # genera stepup_requested
    h = bearer(admin["access_token"])

    summary = client.get("/api/audit/statistics/summary", headers=h).json()
    assert summary["successful_logins"] >= 1

    report = client.post("/api/audit/reports/aggregated", headers=h, json={}).json()
    assert report["total_logins"] >= 1
    assert report["stepup_challenges"] >= 1
    assert sum(x["count"] for x in report["hourly_distribution"]) == report["total_events"]

    for fmt in ("csv", "json"):
        r = client.post("/api/audit/export", headers=h, json={"format": fmt})
        assert r.status_code == 200 and "auth_success" in r.text
        # Filtro sin resultados: archivo vacío, no error 500
        r = client.post("/api/audit/export", headers=h,
                        json={"format": fmt, "filters": {"event_types": ["no_existe"]}})
        assert r.status_code == 200

    assert client.post("/api/audit/export", headers=h, json={"format": "xml"}).status_code == 400
    r = client.post("/api/audit/export", headers=h,
                    json={"format": "csv", "filters": {"sort_by": "__class__"}})
    assert r.status_code == 200
