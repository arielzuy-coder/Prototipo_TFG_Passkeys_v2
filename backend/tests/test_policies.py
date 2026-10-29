"""Motor de políticas: condiciones de contexto y comportamiento por defecto."""
from types import SimpleNamespace

from risk.policies import PolicyEngine


def P(name, conditions, action, priority):
    return SimpleNamespace(name=name, description="", conditions=conditions, action=action, priority=priority)


DEFAULTS = [
    P("high_risk_deny", {"min_risk_score": 75}, "deny", 1),
    P("medium_risk_stepup", {"min_risk_score": 40, "max_risk_score": 74}, "stepup", 2),
    P("new_device_stepup", {"new_device": True}, "stepup", 3),
    P("unusual_location_stepup", {"unusual_location": True}, "stepup", 4),
    P("low_risk_allow", {"max_risk_score": 39}, "allow", 5),
]


def decide(score, **ctx):
    engine = PolicyEngine()
    for p in DEFAULTS:
        if engine._policy_matches(p, score, ctx):
            return p.name
    return "default"


def test_known_device_and_location_low_risk_is_allowed():
    assert decide(5, new_device=False, unusual_location=False) == "low_risk_allow"


def test_new_device_triggers_stepup():
    assert decide(5, new_device=True, unusual_location=False) == "new_device_stepup"


def test_unusual_location_triggers_stepup():
    assert decide(5, new_device=False, unusual_location=True) == "unusual_location_stepup"


def test_missing_context_is_treated_as_risky():
    assert decide(5) == "new_device_stepup"


def test_scores_still_drive_decision():
    assert decide(80, new_device=False, unusual_location=False) == "high_risk_deny"
    assert decide(50, new_device=False, unusual_location=False) == "medium_risk_stepup"


def test_risk_engine_reports_points_per_factor(monkeypatch):
    """Cada factor informa su peso y su aporte; la suma de aportes es el puntaje total."""
    from datetime import datetime
    from risk.risk_engine import RiskEngine

    engine = RiskEngine()
    monkeypatch.setattr(engine, "_build_context", lambda *a, **k: {
        "user_id": 1, "location": {}, "timestamp": datetime(2026, 10, 29, 21, 0)})
    monkeypatch.setattr(engine, "_evaluate_device_risk", lambda c, db: {"score": 0, "known": True, "message": "ok"})
    monkeypatch.setattr(engine, "_evaluate_location_risk", lambda c, u, db: {"score": 5, "known": True, "message": "AR"})
    monkeypatch.setattr(engine, "_evaluate_time_risk", lambda c: {"score": 200, "message": "Fuera de horario laboral"})
    monkeypatch.setattr(engine, "_evaluate_failed_attempts", lambda u, db: {"score": 0, "message": "-"})
    monkeypatch.setattr(engine, "_evaluate_velocity_risk", lambda u, db: {"score": 0, "message": "-"})

    result = engine.evaluate_risk(SimpleNamespace(id=1, email="a@b.c"), "190.0.0.1", "UA", db=None)
    factors = result["factors"]
    assert factors["time"]["weight"] == 0.20 and factors["time"]["points"] == 40.0
    assert factors["location"]["points"] == 1.25
    assert float(result["score"]) == sum(f["points"] for f in factors.values()) == 41.25
    assert result["level"] == "medium"
