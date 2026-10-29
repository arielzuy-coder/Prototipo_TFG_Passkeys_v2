import React, { useCallback, useEffect, useState } from 'react';
import api, { errorMessage } from '../services/api';
import { useNotifier } from './Notifier';
import '../styles/Security_v2.css';

const ROLE_LABELS = { user: 'Usuario estándar', auditor: 'Auditor de seguridad', admin: 'Administrador' };
const STATUS_LABELS = { active: 'Activo', pending: 'Pendiente de enrolar', suspended: 'Suspendido' };

/**
 * Ciclo de vida de usuarios: alta por invitación, cambio de rol, suspensión,
 * recuperación (revoca passkeys y emite invitación de re-enrolamiento) y
 * aprobación manual de step-up por supervisor.
 */
function AdminUsers({ currentUser }) {
  const { confirm } = useNotifier();
  const [users, setUsers] = useState([]);
  const [pending, setPending] = useState([]);
  const [form, setForm] = useState({ email: '', display_name: '', role: 'user' });
  const [invitation, setInvitation] = useState(null);
  const [message, setMessage] = useState({ type: '', text: '' });
  const [busy, setBusy] = useState(false);
  const [diag, setDiag] = useState(null);

  const load = useCallback(async () => {
    try {
      const [{ data: u }, { data: p }] = await Promise.all([
        api.get('/admin/users'),
        api.get('/admin/stepup/pending')
      ]);
      setUsers(u.users || []);
      setPending(p.requests || []);
    } catch (error) {
      setMessage({ type: 'error', text: errorMessage(error, 'No se pudieron cargar los usuarios') });
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(() => {
      api.get('/admin/stepup/pending').then(({ data }) => setPending(data.requests || [])).catch(() => {});
    }, 5000);
    return () => clearInterval(timer);
  }, [load]);

  const run = async (fn, okText) => {
    setBusy(true);
    setMessage({ type: '', text: '' });
    try {
      const result = await fn();
      if (result?.invitation) setInvitation({ ...result.invitation, email: result.user?.email });
      if (okText) setMessage({ type: 'success', text: okText });
      await load();
    } catch (error) {
      setMessage({ type: 'error', text: errorMessage(error) });
    } finally {
      setBusy(false);
    }
  };

  const createUser = (e) => {
    e.preventDefault();
    run(async () => {
      const { data } = await api.post('/admin/users', form);
      setForm({ email: '', display_name: '', role: 'user' });
      return data;
    }, 'Usuario creado. Entregale el link de invitación por un canal seguro.');
  };

  const post = (path) => api.post(path).then((r) => r.data);

  const actions = {
    reinvite: (u) => run(() => post(`/admin/users/${u.id}/invitation`), 'Invitación reemitida'),
    recovery: async (u) => {
      const ok = await confirm({
        title: `Recuperación de ${u.email}`,
        message: 'Se revocan TODAS sus passkeys y sesiones y se emite una invitación de re-enrolamiento. '
          + 'Verificá antes la identidad del titular por un canal independiente.',
        confirmLabel: 'Iniciar recuperación',
        danger: true
      });
      if (!ok) return;
      run(() => post(`/admin/users/${u.id}/recovery`), 'Passkeys revocadas. Entregá el link de recuperación.');
    },
    suspend: async (u) => {
      const ok = await confirm({
        title: `¿Suspender a ${u.email}?`,
        message: 'Se cierran todas sus sesiones y no podrá iniciar sesión hasta que lo reactives.',
        confirmLabel: 'Suspender',
        danger: true
      });
      if (!ok) return;
      run(() => post(`/admin/users/${u.id}/suspend`), 'Usuario suspendido');
    },
    reactivate: (u) => run(() => post(`/admin/users/${u.id}/reactivate`), 'Usuario reactivado'),
    role: (u, role) => run(() => api.put(`/admin/users/${u.id}/role`, { role }).then((r) => r.data), 'Rol actualizado'),
    approve: (req) => run(() => post(`/admin/stepup/${req.id}/approve`), `Acceso de ${req.user.email} aprobado`),
    deny: (req) => run(() => post(`/admin/stepup/${req.id}/deny`), `Acceso de ${req.user.email} rechazado`)
  };

  const runDiagnostics = async () => {
    try {
      const { data } = await api.get('/admin/diagnostics/client-ip');
      setDiag(data);
    } catch (error) {
      setMessage({ type: 'error', text: errorMessage(error, 'No se pudo obtener el diagnóstico') });
    }
  };

  const copy = (text) => navigator.clipboard?.writeText(text).then(
    () => setMessage({ type: 'success', text: 'Link copiado' }),
    () => {}
  );

  return (
    <div className="policies-content">
      {message.text && <div className={`message ${message.type}`}>{message.text}</div>}

      <section className="au-section">
        <h3>Solicitudes de aprobación (step-up)</h3>
        <p className="au-hint">Accesos que pidieron aprobación manual. Revisá el contexto antes de aprobar.</p>
        {pending.length === 0 ? (
          <p className="au-hint">No hay accesos esperando aprobación.</p>
        ) : (
          <div className="au-list">
            {pending.map((req) => (
              <div key={req.id} className="au-card au-pending">
                <div className="au-card-header">
                  <h4>{req.user.display_name} <small>({req.user.email})</small></h4>
                  <span className="au-badge risk">Riesgo {req.context.risk_score}/100</span>
                </div>
                <p className="au-meta">
                  IP {req.context.ip_address} · {req.context.location} · política «{req.context.policy}»
                </p>
                <p className="au-ua">{req.context.user_agent}</p>
                <div className="au-actions">
                  <button className="btn-primary" disabled={busy || req.user.id === currentUser?.id}
                    onClick={() => actions.approve(req)}>✓ Aprobar</button>
                  <button className="btn-danger" disabled={busy} onClick={() => actions.deny(req)}>✕ Rechazar</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="au-section">
        <h3>Alta de usuario</h3>
        <p className="au-hint">
          Se crea pendiente y se genera un link de invitación de un solo uso para enrolar su primera passkey.
        </p>
        <form className="policy-form au-form" onSubmit={createUser}>
          <div className="form-row">
            <div className="form-group">
              <label>Email corporativo</label>
              <input type="email" required value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })} />
            </div>
            <div className="form-group">
              <label>Nombre</label>
              <input type="text" maxLength={100} value={form.display_name}
                onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
            </div>
            <div className="form-group">
              <label>Perfil</label>
              <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                {Object.entries(ROLE_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </div>
          </div>
          <button type="submit" className="btn-primary" disabled={busy}>Crear e invitar</button>
        </form>

        {invitation && (
          <div className="info-box au-invite">
            <h4>Invitación {invitation.purpose === 'recovery' ? 'de recuperación' : 'de alta'} para {invitation.email}</h4>
            <p>
              Un solo uso, vence {new Date(invitation.expires_at).toLocaleString('es-AR')}. No se vuelve a mostrar:
              entregala por un canal seguro.
            </p>
            <input type="text" readOnly value={invitation.url} onFocus={(e) => e.target.select()} />
            <div className="au-actions">
              <button className="btn-secondary" onClick={() => copy(invitation.url)}>Copiar</button>
              <button className="btn-secondary" onClick={() => setInvitation(null)}>Ocultar</button>
            </div>
          </div>
        )}
      </section>

      <section className="au-section">
        <h3>Usuarios ({users.length})</h3>
        <div className="au-list">
          {users.map((u) => {
            const self = u.id === currentUser?.id;
            return (
              <div key={u.id} className="au-card">
                <div className="au-card-header">
                  <h4>{u.display_name} <small>({u.email}){self ? ' · vos' : ''}</small></h4>
                  <span className={`au-badge ${u.status}`}>{STATUS_LABELS[u.status] || u.status}</span>
                </div>
                <div className="au-meta">
                  <span>Perfil:</span>
                  <select value={u.role} disabled={busy || self} onChange={(e) => actions.role(u, e.target.value)}>
                    {Object.entries(ROLE_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                  </select>
                  <span>· Passkeys: {u.passkeys}</span>
                </div>
                {!self && (
                  <div className="au-actions">
                    {u.status === 'pending' && (
                      <button className="btn-secondary" disabled={busy} onClick={() => actions.reinvite(u)}>Reemitir invitación</button>
                    )}
                    {u.status !== 'suspended' && (
                      <button className="btn-secondary" disabled={busy} onClick={() => actions.recovery(u)}>Recuperación</button>
                    )}
                    {u.status === 'suspended' ? (
                      <button className="btn-secondary" disabled={busy} onClick={() => actions.reactivate(u)}>Reactivar</button>
                    ) : (
                      <button className="btn-danger" disabled={busy} onClick={() => actions.suspend(u)}>Suspender</button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      <section className="au-section">
        <h3>Diagnóstico de red</h3>
        <p className="au-hint">
          Verifica que el servidor vea tu IP pública real detrás del proxy (configuración TRUSTED_PROXY_HOPS).
        </p>
        <button className="btn-secondary" onClick={runDiagnostics}>Ver qué IP detecta el servidor</button>
        {diag && (
          <div className="au-card" style={{ marginTop: 12 }}>
            <p className="au-meta"><strong>IP detectada:</strong> {diag.resolved_client_ip}
              {' '}· {diag.geolocation?.display}</p>
            <p className="au-ua">
              Conexión: {diag.connection_ip} · X-Forwarded-For: {diag.x_forwarded_for || '(vacío)'}
              {' '}· Saltos de confianza: {diag.trusted_proxy_hops}
            </p>
            <p className="au-hint">{diag.hint}</p>
          </div>
        )}
      </section>
    </div>
  );
}

export default AdminUsers;
