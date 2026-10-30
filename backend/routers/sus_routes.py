"""
Medición de usabilidad con el System Usability Scale (SUS), RNF-U2: meta ≥ 70/100.

- POST /sus: respuesta anónima, sin sesión (la completa quien probó el sistema).
- GET /api/audit/sus: resultados agregados, solo auditor y administrador.

Puntaje SUS (Brooke, 1996): ítems impares aportan (respuesta − 1), pares (5 − respuesta);
la suma (0–40) se multiplica por 2,5.
"""
import statistics
from decimal import Decimal
from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session as DBSession

from auth.deps import require_audit_reader
from database import get_db
from models import SusResponse
from services import ratelimit

router = APIRouter(tags=["Usabilidad (SUS)"])

PROFILES = {"usuario", "auditor", "administrador", "otro"}
TARGET = 70


def sus_score(answers: List[int]) -> float:
    total = sum((a - 1) if i % 2 == 0 else (5 - a) for i, a in enumerate(answers))
    return total * 2.5


class SusIn(BaseModel):
    answers: List[int] = Field(min_length=10, max_length=10)
    profile: Optional[str] = None
    comment: Optional[str] = Field(default=None, max_length=500)

    @field_validator("answers")
    @classmethod
    def _range(cls, v):
        if any(a not in (1, 2, 3, 4, 5) for a in v):
            raise ValueError("cada respuesta va de 1 a 5")
        return v

    @field_validator("profile")
    @classmethod
    def _profile(cls, v):
        return v if v in PROFILES else None


@router.post("/sus")
def submit_sus(request: Request, data: SusIn, db: DBSession = Depends(get_db)):
    ratelimit.by_ip(db, request, "sus")
    score = sus_score(data.answers)
    db.add(SusResponse(answers=data.answers, score=Decimal(str(score)), profile=data.profile,
                       comment=(data.comment or "").strip() or None))
    db.commit()
    return {"score": score}


@router.get("/api/audit/sus", dependencies=[Depends(require_audit_reader)])
def sus_results(db: DBSession = Depends(get_db)):
    rows = db.query(SusResponse).order_by(SusResponse.created_at.desc()).all()
    scores = [float(r.score) for r in rows]
    n = len(scores)
    item_means = [round(statistics.mean(r.answers[i] for r in rows), 2) for i in range(10)] if n else []
    return {
        "target": TARGET,
        "count": n,
        "mean": round(statistics.mean(scores), 1) if n else None,
        "median": round(statistics.median(scores), 1) if n else None,
        "stdev": round(statistics.stdev(scores), 1) if n > 1 else None,
        "min": min(scores) if n else None,
        "max": max(scores) if n else None,
        "meets_target": (statistics.mean(scores) >= TARGET) if n else None,
        "item_means": item_means,
        "responses": [
            {"score": float(r.score), "profile": r.profile, "comment": r.comment,
             "created_at": r.created_at.isoformat() + "Z"}
            for r in rows
        ],
    }
