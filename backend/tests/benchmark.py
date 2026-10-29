"""
Medición de rendimiento de la autenticación passwordless (RNF-R1 y RNF-R2 de la tesis).

Cada usuario virtual tiene su propia passkey (autenticador FIDO2 por software con firma ES256 real),
su propio navegador (User-Agent) y su propia IP (vía X-Forwarded-For, con TRUSTED_PROXY_HOPS=1).
Una autenticación = POST /auth/login/begin + firma del autenticador + POST /auth/login/complete,
incluyendo la verificación criptográfica, el motor de riesgo, las políticas y la emisión de tokens.

Uso (backend levantado con TRUSTED_PROXY_HOPS=1, base vacía):
    python tests/benchmark.py --users 50 --rounds 4 --out resultados.json
"""
import argparse
import asyncio
import json
import os
import platform
import statistics
import sys
import time

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.softauthn import SoftAuthenticator  # noqa: E402

API = os.environ.get("BENCH_API", "http://localhost:8000")
RP_ID = os.environ.get("RP_ID", "localhost")
ORIGIN = os.environ.get("ORIGIN", "http://localhost:3000")


def percentile(values, p):
    ordered = sorted(values)
    k = (len(ordered) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


class VirtualUser:
    def __init__(self, n: int):
        self.email = f"usuario{n:03d}@empresa.com"
        self.headers = {
            "User-Agent": f"Mozilla/5.0 (Benchmark) Chrome/150 usuario-{n:03d}",
            "X-Forwarded-For": f"10.50.{n // 250}.{n % 250 + 1}",
        }
        self.authn = SoftAuthenticator(RP_ID, ORIGIN)

    async def enroll(self, client: httpx.AsyncClient, token: str):
        opts = await client.post("/auth/register/begin", json={"invitation_token": token}, headers=self.headers)
        opts.raise_for_status()
        cred = self.authn.create(opts.json())
        r = await client.post("/auth/register/complete", headers=self.headers,
                              json={"invitation_token": token, "credential": cred, "device_name": "bench"})
        r.raise_for_status()

    async def login(self, client: httpx.AsyncClient) -> dict:
        t0 = time.perf_counter()
        try:
            opts = await client.post("/auth/login/begin", json={"email": self.email}, headers=self.headers)
            if opts.status_code != 200:
                return {"ok": False, "ms": (time.perf_counter() - t0) * 1000, "status": opts.status_code}
            cred = self.authn.get(opts.json())
            r = await client.post("/auth/login/complete", json={"email": self.email, "credential": cred},
                                  headers=self.headers)
            ms = (time.perf_counter() - t0) * 1000
            body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            ok = r.status_code == 200 and "tokens" in body
            return {"ok": ok, "ms": ms, "status": r.status_code, "stepup": bool(body.get("requires_stepup"))}
        except Exception as e:  # timeouts o errores de red cuentan como fallo
            return {"ok": False, "ms": (time.perf_counter() - t0) * 1000, "status": type(e).__name__}


def create_invitations(n_users: int):
    from database import SessionLocal
    from models import User
    from services.common import create_invitation
    db = SessionLocal()
    tokens = []
    try:
        for i in range(n_users):
            email = f"usuario{i:03d}@empresa.com"
            user = User(email=email, display_name=email.split("@")[0], role="user", status="pending")
            db.add(user)
            db.commit()
            db.refresh(user)
            tokens.append(create_invitation(db, user, "enroll")["token"])
    finally:
        db.close()
    return tokens


async def main(n_users: int, rounds: int, out: str):
    users = [VirtualUser(i) for i in range(n_users)]
    tokens = create_invitations(n_users)
    limits = httpx.Limits(max_connections=n_users, max_keepalive_connections=n_users)
    async with httpx.AsyncClient(base_url=API, timeout=30, limits=limits) as client:
        for u, t in zip(users, tokens):
            await u.enroll(client, t)

        # Línea base: un usuario a la vez (sin concurrencia)
        baseline = [await users[i].login(client) for i in range(min(n_users, 20))]

        # Carga: todos los usuarios autentican al mismo tiempo, en varias rondas
        concurrent, round_times = [], []
        for _ in range(rounds):
            t0 = time.perf_counter()
            results = await asyncio.gather(*(u.login(client) for u in users))
            round_times.append((time.perf_counter() - t0) * 1000)
            concurrent.extend(results)

    def summary(rs):
        ms = [r["ms"] for r in rs if r["ok"]]
        return {
            "attempts": len(rs),
            "successes": len(ms),
            "success_rate": round(100 * len(ms) / len(rs), 2),
            "stepups": sum(1 for r in rs if r.get("stepup")),
            "failures_by_status": {str(s): sum(1 for r in rs if not r["ok"] and r["status"] == s)
                                   for s in {r["status"] for r in rs if not r["ok"]}},
            "mean_ms": round(statistics.mean(ms), 1),
            "p50_ms": round(percentile(ms, 50), 1),
            "p95_ms": round(percentile(ms, 95), 1),
            "p99_ms": round(percentile(ms, 99), 1),
            "max_ms": round(max(ms), 1),
            "latencies_ms": [round(x, 1) for x in ms],
        }

    report = {
        "environment": {
            "python": platform.python_version(),
            "os": platform.platform(),
            "cpus": os.cpu_count(),
            "api": API,
            "date_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        },
        "config": {"users": n_users, "rounds": rounds},
        "baseline_sequential": summary(baseline),
        "concurrent": {**summary(concurrent), "round_wall_ms": [round(x, 1) for x in round_times]},
    }
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    for k in ("baseline_sequential", "concurrent"):
        s = report[k]
        print(f"{k}: {s['successes']}/{s['attempts']} ok ({s['success_rate']}%), "
              f"media {s['mean_ms']} ms, p50 {s['p50_ms']}, p95 {s['p95_ms']}, p99 {s['p99_ms']}, max {s['max_ms']}, "
              f"step-up {s['stepups']}, fallos {s['failures_by_status']}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--users", type=int, default=50)
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--out", default="benchmark_results.json")
    args = ap.parse_args()
    asyncio.run(main(args.users, args.rounds, args.out))
