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
