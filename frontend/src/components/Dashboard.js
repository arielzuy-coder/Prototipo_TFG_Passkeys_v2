import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api, { errorMessage } from '../services/api';
import { useNotifier } from './Notifier';
import '../styles/Security_v2.css';

function Dashboard({ user }) {
  const navigate = useNavigate();
  const { notify, confirm } = useNotifier();
  const [passkeys, setPasskeys] = useState([]);
  const [auditEvents, setAuditEvents] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [stats, setStats] = useState(null);
  const [riskInfo, setRiskInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('passkeys');
  const [editingPasskey, setEditingPasskey] = useState(null);
  const [newName, setNewName] = useState('');
  const canAudit = ['admin', 'auditor'].includes(user.role);

  useEffect(() => {
    loadDashboardData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadDashboardData = async () => {
    setLoading(true);
    
    try {
      const { data: passkeysData } = await api.get('/passkeys');
      setPasskeys(passkeysData.passkeys || []);
    } catch (error) {
      console.error('Error al cargar passkeys:', error);
    }

    try {
      const { data: sessionsData } = await api.get('/me/sessions');
      setSessions(sessionsData.sessions || []);
    } catch (error) {
      console.error('Error al cargar sesiones:', error);
    }

    try {
      const { data: eventsData } = await api.get('/me/events', { params: { limit: 20 } });
      setAuditEvents(eventsData.events || []);
    } catch (error) {
      console.error('Error al cargar eventos:', error);
    }

    // Métricas globales: solo administradores y auditores (Tabla 4 de la tesis)
    if (!canAudit) {
      setLoading(false);
      return;
    }

    try {
      const { data: statsData } = await api.get('/audit/stats');
      setStats(statsData);
    } catch (error) {
      console.error('Error al cargar estadísticas:', error);
    }

    try {
      const { data: riskData } = await api.get('/risk/dashboard');
      setRiskInfo(riskData);
    } catch (error) {
      console.error('Error al cargar info de riesgo:', error);
    }

    setLoading(false);
  };

  const handleRevokePasskey = async (passkey) => {
    const ok = await confirm({
      title: `¿Revocar la passkey "${passkey.device_name}"?`,
      message: 'Dejará de servir para iniciar sesión en este sistema. Esta acción no se puede deshacer.',
      confirmLabel: 'Revocar',
      danger: true
    });
    if (!ok) return;

    try {
      await api.delete(`/passkeys/${passkey.id}`);
      notify(`Passkey "${passkey.device_name}" revocada`, 'success');
      loadDashboardData();
    } catch (error) {
      notify(errorMessage(error), 'error');
    }
  };

  const handleRevokeSession = async (sessionId) => {
    const ok = await confirm({
      title: '¿Cerrar esa sesión?',
      message: 'El dispositivo tendrá que volver a iniciar sesión.',
      confirmLabel: 'Cerrar sesión',
      danger: true
    });
    if (!ok) return;
    try {
      await api.delete(`/me/sessions/${sessionId}`);
      setSessions(sessions.filter((s) => s.id !== sessionId));
      notify('Sesión cerrada', 'success');
    } catch (error) {
      notify(errorMessage(error), 'error');
    }
  };

  const handleRenamePasskey = (passkey) => {
    setEditingPasskey(passkey.id);
    setNewName(passkey.device_name);
  };

  const savePasskeyName = async (passkeyId) => {
    try {
      await api.put(`/passkeys/${passkeyId}`, { device_name: newName });
      setPasskeys(passkeys.map(pk =>
        pk.id === passkeyId ? { ...pk, device_name: newName } : pk
      ));
      setEditingPasskey(null);
      setNewName('');
      notify('Nombre actualizado', 'success');
    } catch (error) {
      notify(errorMessage(error), 'error');
    }
  };

  const cancelEdit = () => {
    setEditingPasskey(null);
    setNewName('');
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Nunca';
    const date = new Date(dateString);
    return date.toLocaleString('es-AR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getTimeAgo = (dateString) => {
    if (!dateString) return 'Nunca';
    
    const date = new Date(dateString);
    
    // Validación: Verificar que la fecha es válida
    if (isNaN(date.getTime())) {
      console.error('Fecha inválida:', dateString);
      return 'Fecha inválida';
    }
    
    const now = new Date();
    const diffMs = now - date;
    
    // Verificación: Si la diferencia es negativa, es una fecha futura (error de sincronización)
    if (diffMs < 0) {
      console.warn('Fecha en el futuro detectada:', dateString, 'Diferencia:', diffMs);
      return 'Justo ahora';
    }
    
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffSecs < 10) return 'Justo ahora';
    if (diffSecs < 60) return 'Hace un momento';
    if (diffMins < 60) return `Hace ${diffMins} min`;
    if (diffHours < 24) return `Hace ${diffHours} hora${diffHours > 1 ? 's' : ''}`;
    if (diffDays < 7) return `Hace ${diffDays} día${diffDays > 1 ? 's' : ''}`;
    if (diffDays < 30) return `Hace ${Math.floor(diffDays / 7)} semana${Math.floor(diffDays / 7) > 1 ? 's' : ''}`;
    
    return formatDate(dateString);
  };

  const getEventIcon = (type) => {
    const icons = {
      'auth_success': '',
      'auth_failed': '',
      'passkey_enrolled': '',
      'passkey_revoked': '',
      'user_created': '',
      'access_denied': '',
      'policy_changed': ''
    };
    return icons[type] || '';
  };

  const getEventLabel = (type) => {
    const labels = {
      'auth_success': 'Autenticación exitosa',
      'auth_failed': 'Autenticación fallida',
      'passkey_enrolled': 'Passkey enrolada',
      'passkey_revoked': 'Passkey revocada',
      'user_created': 'Usuario creado',
      'access_denied': 'Acceso denegado',
      'policy_changed': 'Política modificada',
      'logout': 'Cierre de sesión',
      'session_revoked': 'Sesión revocada',
      'session_ip_changed': 'Cambio de IP en la sesión',
      'stepup_requested': 'Verificación adicional solicitada',
      'stepup_success': 'Verificación adicional superada',
      'stepup_failed': 'Verificación adicional fallida',
      'stepup_approval_requested': 'Aprobación de supervisor solicitada',
      'stepup_approved': 'Acceso aprobado por supervisor',
      'stepup_denied': 'Acceso rechazado por supervisor',
      'reauth_success': 'Identidad reconfirmada',
      'auth_aborted': 'Inicio de sesión cancelado',
      'account_recovery_started': 'Recuperación de cuenta iniciada'
    };
    return labels[type] || type;
  };

  const getRiskLevel = (score) => {
    if (score < 40) return { label: 'BAJO', class: 'low', color: '#28a745' };
    if (score < 75) return { label: 'MEDIO', class: 'medium', color: '#ffc107' };
    return { label: 'ALTO', class: 'high', color: '#dc3545' };
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
        <p>Cargando dashboard...</p>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div className="user-info">
          <h2>Mi cuenta</h2>
          <p className="user-email">{user.display_name ? `${user.display_name}, ${user.email}` : user.email}</p>
        </div>
      </div>

      {riskInfo && (
        <div className="risk-summary">
          <div className="risk-card">
            <h4>Riesgo promedio de los accesos (7 días)</h4>
            <div className="risk-score">
              <span className={`risk-badge ${getRiskLevel(riskInfo.summary?.average_risk_score || 0).class}`}>
                {getRiskLevel(riskInfo.summary?.average_risk_score || 0).label}
              </span>
              <span className="risk-number">{(riskInfo.summary?.average_risk_score || 0).toFixed(1)}/100</span>
            </div>
          </div>
          <div className="risk-card">
            <h4>Evaluaciones de riesgo (7 días)</h4>
            <div className="risk-number">{riskInfo.summary?.total_evaluations || 0}</div>
          </div>
        </div>
      )}

      <div className="dashboard-tabs">
        <button 
          className={`tab ${activeTab === 'passkeys' ? 'active' : ''}`}
          onClick={() => setActiveTab('passkeys')}
        >
          Mis Passkeys ({passkeys.length})
        </button>
        <button 
          className={`tab ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
        >
          Historial de Acceso
        </button>
        <button
          className={`tab ${activeTab === 'sessions' ? 'active' : ''}`}
          onClick={() => setActiveTab('sessions')}
        >
          Sesiones activas ({sessions.length})
        </button>
        {canAudit && (
          <button
            className={`tab ${activeTab === 'stats' ? 'active' : ''}`}
            onClick={() => setActiveTab('stats')}
          >
            Estadísticas del Sistema
          </button>
        )}
      </div>

      <div className="dashboard-content">
        {activeTab === 'passkeys' && (
          <div className="passkeys-section">
            <div className="section-header">
              <h3>Tus Credenciales de Seguridad</h3>
              <p className="section-subtitle">
                Gestiona tus passkeys biométricas para acceso sin contraseña
              </p>
            </div>

            {passkeys.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon"></div>
                <h4>No tienes Passkeys enroladas</h4>
                <p>Crea tu primera passkey para acceder de forma segura sin contraseñas</p>
                <button className="btn-primary" onClick={() => navigate('/enroll')}>
                  Enrolar Nueva Passkey
                </button>
              </div>
            ) : (
              <>
                <div className="passkeys-stats">
                  <div className="stat-item">
                    <span className="stat-icon"></span>
                    <div>
                      <div className="stat-number">{passkeys.length}</div>
                      <div className="stat-label">Passkeys activas</div>
                    </div>
                  </div>
                  <div className="stat-item">
                    <span className="stat-icon"></span>
                    <div>
                      <div className="stat-number">
                        {passkeys.filter(pk => pk.device_type === 'multi_device').length}
                      </div>
                      <div className="stat-label">Sincronizadas</div>
                    </div>
                  </div>
                  <div className="stat-item">
                    <span className="stat-icon"></span>
                    <div>
                      <div className="stat-number">
                        {passkeys.filter(pk => pk.device_type !== 'multi_device').length}
                      </div>
                      <div className="stat-label">Ligadas al dispositivo</div>
                    </div>
                  </div>
                </div>

                <div className="passkeys-grid">
                  {passkeys.map((passkey) => (
                    <div key={passkey.id} className="passkey-card-enhanced">
                      <div className="passkey-card-header">
                        <div className="passkey-icon-large">
                          {passkey.device_type === 'multi_device' ? '' : ''}
                        </div>
                        <div className="passkey-status">
                          <span className="status-badge active">● Activa</span>
                        </div>
                      </div>

                      <div className="passkey-card-body">
                        {editingPasskey === passkey.id ? (
                          <div className="passkey-edit">
                            <input
                              type="text"
                              value={newName}
                              onChange={(e) => setNewName(e.target.value)}
                              className="passkey-name-input"
                              autoFocus
                            />
                            <div className="passkey-edit-actions">
                              <button 
                                className="btn-save-small"
                                onClick={() => savePasskeyName(passkey.id)}
                              >
                                ✓ Guardar
                              </button>
                              <button 
                                className="btn-cancel-small"
                                onClick={cancelEdit}
                              >
                                ✕ Cancelar
                              </button>
                            </div>
                          </div>
                        ) : (
                          <>
                            <h4 className="passkey-name">
                              {passkey.device_name}
                              <button 
                                className="btn-icon-edit"
                                onClick={() => handleRenamePasskey(passkey)}
                                title="Renombrar"
                              >
                                Renombrar
                              </button>
                            </h4>
                            <p className="passkey-type">
                              <span className="type-badge">
                                {passkey.device_type === 'multi_device' ?
                                  'Sincronizada (gestor de passkeys)' :
                                  'Ligada a un solo dispositivo'}
                              </span>
                            </p>
                          </>
                        )}

                        <div className="passkey-dates">
                          <div className="date-item">
                            <span className="date-icon"></span>
                            <div>
                              <div className="date-label">Creada</div>
                              <div className="date-value">{formatDate(passkey.created_at)}</div>
                            </div>
                          </div>
                          <div className="date-item">
                            <span className="date-icon"></span>
                            <div>
                              <div className="date-label">Último uso</div>
                              <div className="date-value">
                                {passkey.last_used_at ? (
                                  <>
                                    <strong>{getTimeAgo(passkey.last_used_at)}</strong>
                                    <br />
                                    <small>{formatDate(passkey.last_used_at)}</small>
                                  </>
                                ) : (
                                  'Nunca usada'
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="passkey-card-footer">
                        <button
                          className="btn-revoke"
                          onClick={() => handleRevokePasskey(passkey)}
                          disabled={passkeys.length <= 1}
                          title={passkeys.length <= 1 ? 'Es tu única passkey: agregá otra antes de revocarla' : ''}
                        >
                          Revocar Passkey
                        </button>
                        {passkeys.length <= 1 && (
                          <p className="revoke-hint">
                            Es tu única passkey. Agregá otra antes de revocarla para no perder el acceso.
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                <div className="passkeys-actions">
                  <button
                    className="btn-secondary"
                    onClick={() => navigate('/enroll')}
                    disabled={passkeys.length >= 5}
                    title={passkeys.length >= 5 ? 'Máximo 5 passkeys por usuario' : ''}
                  >
                    Agregar Nueva Passkey {passkeys.length >= 5 ? '(máximo alcanzado)' : ''}
                  </button>
                </div>
              </>
            )}
          </div>
        )}

        {activeTab === 'sessions' && (
          <div className="passkeys-section sessions-list">
            <div className="section-header">
              <h3>Sesiones activas</h3>
              <p className="section-subtitle">
                Cada sesión queda atada al navegador donde se inició y se reevalúa continuamente.
              </p>
            </div>
            <div className="au-list">
              {sessions.map((s) => (
                <div key={s.id} className={`au-card ${s.current ? 'current' : ''}`}>
                  <div className="au-card-header">
                    <h4>{s.location || 'Ubicación desconocida'} <small>· IP {s.ip_address}</small></h4>
                    {s.current && <span className="au-badge active">Esta sesión</span>}
                  </div>
                  <p className="au-ua">{s.user_agent}</p>
                  <p className="au-meta">Iniciada {formatDate(s.created_at)} · vence {formatDate(s.expires_at)}</p>
                  {!s.current && (
                    <div className="au-actions">
                      <button className="btn-danger" onClick={() => handleRevokeSession(s.id)}>Cerrar sesión</button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'audit' && (
          <div className="audit-section">
            <div className="section-header">
              <h3>Historial de Eventos de Seguridad</h3>
              <p className="section-subtitle">
                Registro completo de todas las acciones en tu cuenta
              </p>
            </div>

            {auditEvents.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon"></div>
                <h4>No hay eventos registrados</h4>
                <p>Los eventos de seguridad aparecerán aquí</p>
              </div>
            ) : (
              <div className="audit-list">
                <table className="audit-table">
                  <thead>
                    <tr>
                      <th>Fecha/Hora</th>
                      <th>Evento</th>
                      <th>IP</th>
                      <th>Detalles</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditEvents.map((event) => (
                      <tr key={event.id}>
                        <td className="date-cell">
                          <div>{formatDate(event.timestamp)}</div>
                          <small>{getTimeAgo(event.timestamp)}</small>
                        </td>
                        <td>
                          <span className={`event-badge ${event.event_type}`}>
                            {getEventIcon(event.event_type)} {getEventLabel(event.event_type)}
                          </span>
                        </td>
                        <td className="ip-cell">{event.ip_address}</td>
                        <td className="details-cell">
                          {event.event_data && Object.keys(event.event_data).length > 0 ? (
                            <details>
                              <summary>Ver detalles</summary>
                              <pre>{JSON.stringify(event.event_data, null, 2)}</pre>
                            </details>
                          ) : (
                            '-'
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === 'stats' && stats && (
          <div className="stats-section">
            <div className="section-header">
              <h3>Estadísticas del Sistema</h3>
              <p className="section-subtitle">Métricas generales de autenticación</p>
            </div>

            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-icon-big"></div>
                <div className="stat-info">
                  <div className="stat-big-number">{stats.authentication?.success || 0}</div>
                  <div className="stat-big-label">Autenticaciones exitosas</div>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-icon-big"></div>
                <div className="stat-info">
                  <div className="stat-big-number">{stats.authentication?.failed || 0}</div>
                  <div className="stat-big-label">Intentos fallidos</div>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-icon-big"></div>
                <div className="stat-info">
                  <div className="stat-big-number">{stats.authentication?.success_rate || '0%'}</div>
                  <div className="stat-big-label">Tasa de éxito</div>
                </div>
              </div>
            </div>

            {stats.events_by_type && (
              <div className="events-breakdown">
                <h4>Eventos por Tipo</h4>
                <div className="events-list">
                  {Object.entries(stats.events_by_type).map(([type, count]) => (
                    <div key={type} className="event-stat">
                      <span className="event-type">
                        {getEventIcon(type)} {getEventLabel(type)}
                      </span>
                      <span className="event-count">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default Dashboard;
