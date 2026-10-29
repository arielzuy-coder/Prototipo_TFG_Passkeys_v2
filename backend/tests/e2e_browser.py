"""
Prueba de punta a punta en Chromium con autenticador WebAuthn virtual (CDP).

Requiere el backend en :8000 y el build del frontend en :3000 (ORIGIN=http://localhost:3000, RP_ID=localhost).
    E2E_PSQL="psql -h ... -d auth_passkeys" python tests/e2e_browser.py <link_invitacion_admin> <carpeta_capturas>
E2E_PSQL (opcional) permite envejecer la autenticación del admin para probar el diálogo de re-autenticación.
"""
import json
import os
import subprocess
import sys

import httpx
from playwright.sync_api import expect, sync_playwright

API, WEB = "http://localhost:8000", "http://localhost:3000"
ADMIN_INVITE, SHOTS = sys.argv[1], sys.argv[2]


def new_context(browser):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    cdp = ctx.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True,
    }})
    return ctx, page


def shot(page, name):
    page.screenshot(path=f"{SHOTS}/{name}.png", full_page=True)
    print("  captura:", name)


def enroll(page, url, device):
    page.goto(url)
    expect(page.locator("#email")).not_to_have_value("", timeout=10000)
    page.fill("#deviceName", device)
    page.click("button[type=submit]")
    expect(page.locator(".message.success")).to_be_visible(timeout=10000)
    page.wait_for_url("**/login", timeout=10000)


def login(page, email):
    page.goto(f"{WEB}/login")
    page.fill("#email", email)
    page.click("button[type=submit]")


def token_of(page):
    return page.evaluate("localStorage.getItem('access_token')")


def api_headers(page):
    """Token del navegador + su User-Agent: la sesión solo vale desde ese navegador."""
    return {"Authorization": f"Bearer {token_of(page)}", "User-Agent": page.evaluate("navigator.userAgent")}


with sync_playwright() as p:
    browser = p.chromium.launch()

    print("1. Admin enrola su passkey con la invitación inicial")
    admin_ctx, admin = new_context(browser)
    admin.goto(ADMIN_INVITE)
    expect(admin.locator("#email")).to_have_value("admin@empresa.com", timeout=10000)
    shot(admin, "01_enrolamiento_invitacion")
    enroll(admin, ADMIN_INVITE, "Notebook admin")

    print("2. Admin inicia sesión (riesgo bajo, sin step-up)")
    login(admin, "admin@empresa.com")
    admin.wait_for_url("**/dashboard", timeout=15000)
    expect(admin.get_by_text("Panel Admin")).to_be_visible()
    shot(admin, "02_dashboard_admin")

    print("3. Reusar la invitación ya usada falla")
    probe_ctx, probe = new_context(browser)
    probe.goto(ADMIN_INVITE)
    expect(probe.locator(".message.error")).to_be_visible(timeout=10000)
    probe_ctx.close()

    print("4. Admin da de alta a un usuario desde el panel")
    psql = os.environ.get("E2E_PSQL")
    if psql:
        # Autenticación de hace 1 h: la operación sensible debe pedir confirmar identidad
        subprocess.run(psql.split() + ["-c", "UPDATE sessions SET strong_auth_at = now() - interval '1 hour'"],
                       check=True, capture_output=True)
    admin.goto(f"{WEB}/admin")
    admin.get_by_role("button", name="Usuarios y Aprobaciones").click()
    admin.locator("form.policy-form input[type=email]").fill("bruno@empresa.com")
    admin.locator("form.policy-form input[type=text]").fill("Bruno")
    admin.get_by_role("button", name="Crear e invitar").click()
    if psql:
        dialog = admin.get_by_role("dialog")
        expect(dialog).to_be_visible(timeout=10000)
        shot(admin, "03a_reauth_operacion_sensible")
        dialog.get_by_role("button", name="Confirmar con Passkey").click()
        print("  re-autenticación del admin confirmada; la operación se reintentó sola")
    invite_input = admin.locator(".info-box input[readonly]")
    expect(invite_input).to_be_visible(timeout=10000)
    bruno_invite = invite_input.input_value()
    shot(admin, "03_alta_usuario_invitacion")

    print("5. Bruno enrola su passkey en otro navegador y entra")
    bruno_ctx, bruno = new_context(browser)
    enroll(bruno, bruno_invite, "Celular Bruno")
    login(bruno, "bruno@empresa.com")
    bruno.wait_for_url("**/dashboard", timeout=15000)
    expect(bruno.get_by_text("Panel Admin")).to_have_count(0)  # usuario estándar
    shot(bruno, "04_dashboard_usuario")
    bruno.get_by_role("button", name="Sesiones activas").click()
    expect(bruno.get_by_text("Esta sesión")).to_be_visible()
    shot(bruno, "04a_sesiones_activas")
    # Un usuario estándar no puede abrir el panel ni la API de administración
    bruno.goto(f"{WEB}/admin")
    bruno.wait_for_url("**/dashboard", timeout=10000)
    r = httpx.get(f"{API}/admin/users", headers=api_headers(bruno))
    assert r.status_code == 403, r.status_code
    bruno.get_by_role("button", name="Cerrar Sesión").click()
    bruno.wait_for_url("**/login", timeout=10000)

    print("6. Política temporal que fuerza step-up -> Bruno verifica con passkey")
    admin_h = api_headers(admin)
    r = httpx.post(f"{API}/admin/policies", headers=admin_h, json={
        "name": "e2e_forzar_stepup", "description": "test", "conditions": {"min_risk_score": 0},
        "action": "stepup", "priority": 0})
    assert r.status_code == 200, r.text
    policy_id = r.json()["policy"]["id"]

    login(bruno, "bruno@empresa.com")
    expect(bruno.get_by_text("Verificación adicional requerida")).to_be_visible(timeout=15000)
    assert "otp_code" not in bruno.content()
    shot(bruno, "05_stepup_metodos")
    bruno.get_by_role("button", name="Verificar con Passkey").click()
    bruno.wait_for_url("**/dashboard", timeout=15000)
    bruno.get_by_role("button", name="Cerrar Sesión").click()
    bruno.wait_for_url("**/login", timeout=10000)

    print("7. Step-up por aprobación de supervisor")
    login(bruno, "bruno@empresa.com")
    expect(bruno.get_by_text("Verificación adicional requerida")).to_be_visible(timeout=15000)
    bruno.get_by_role("button", name="Aprobación de supervisor").click()
    bruno.get_by_role("button", name="Solicitar aprobación").click()
    expect(bruno.get_by_text("Esperando aprobación")).to_be_visible(timeout=10000)
    shot(bruno, "06_esperando_supervisor")

    admin.reload()
    admin.get_by_role("button", name="Usuarios y Aprobaciones").click()
    approve = admin.get_by_role("button", name="✓ Aprobar")
    expect(approve).to_be_visible(timeout=15000)
    shot(admin, "07_admin_aprueba")
    approve.click()
    bruno.wait_for_url("**/dashboard", timeout=20000)
    print("  Bruno entró tras la aprobación")

    print("8. Recuperación: el admin revoca las passkeys de Bruno")
    httpx.delete(f"{API}/admin/policies/{policy_id}", headers=admin_h)
    bruno_id = next(u["id"] for u in httpx.get(f"{API}/admin/users", headers=admin_h).json()["users"]
                    if u["email"] == "bruno@empresa.com")
    r = httpx.post(f"{API}/admin/users/{bruno_id}/recovery", headers=admin_h)
    assert r.status_code == 200
    # Su sesión actual queda invalidada
    bruno.reload()
    bruno.wait_for_url("**/login", timeout=15000)
    login(bruno, "bruno@empresa.com")
    expect(bruno.locator(".message.error")).to_be_visible(timeout=10000)
    shot(bruno, "08_login_tras_recuperacion")

    print("9. Un token usado desde otro navegador revoca la sesión")
    stolen = httpx.get(f"{API}/auth/me", headers={**admin_h, "User-Agent": "curl/8.0 atacante"})
    assert stolen.status_code == 401, stolen.status_code
    assert httpx.get(f"{API}/auth/me", headers=admin_h).status_code == 401
    admin.reload()
    admin.wait_for_url("**/login", timeout=15000)

    login(admin, "admin@empresa.com")
    admin.wait_for_url("**/dashboard", timeout=15000)
    admin_h = api_headers(admin)
    events = httpx.get(f"{API}/audit/events", headers=admin_h, params={"limit": 200}).json()["events"]
    assert "session_revoked" in {e["event_type"] for e in events}
    print("Eventos de auditoría:", json.dumps(sorted({e["event_type"] for e in events}), ensure_ascii=False))
    browser.close()
    print("OK: flujo completo verificado")
