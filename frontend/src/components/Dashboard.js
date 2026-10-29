import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';

function Dashboard({ user, onLogout }) {
  const navigate = useNavigate();
  const [passkeys, setPasskeys] = useState([]);
  const [auditEvents, setAuditEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [riskInfo, setRiskInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('passkeys');
  const [editingPasskey, setEditingPasskey] = useState(null);
  const [newName, setNewName] = useState('');

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setLoading(true);
    
    try {
      const { data: passkeysData } = await api.get(`/passkeys/${user.email}`);
      setPasskeys(passkeysData.passkeys || []);
    } catch (error) {
      console.error('Error al cargar passkeys:', error);
    }

    try {
      const { data: eventsData } = await api.get('/audit/events', {
        params: { user_email: user.email, limit: 20 }
      });
      setAuditEvents(eventsData.events || []);
    } catch (error) {
      console.error('Error al cargar eventos:', error);
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

  const handleRevokePasskey = async (passkeyId) => {
    if (!window.confirm('¿Estás seguro de revocar esta Passkey? Esta acción no se puede deshacer.')) {
      return;
    }

    try {
      await api.delete(`/passkeys/${passkeyId}`);
      alert('✅ Passkey revocada exitosamente');
      loadDashboardData();
    } catch (error) {
      alert(`❌ Error: ${error.response?.data?.detail || error.message}`);
    }
  };

  const handleRenamePasskey = (passkey) => {
    setEditingPasskey(passkey.id);
    setNewName(passkey.device_name);
  };

  const savePasskeyName = async (passkeyId) => {
    // Nota: Este endpoint no existe en el backend actual
    // Se puede implementar si se necesita
    try {
      // await api.put(`/passkeys/${passkeyId}`, { device_name: newName });
      // Por ahora solo actualizamos localmente
      setPasskeys(passkeys.map(pk => 
        pk.id === passkeyId ? { ...pk, device_name: newName } : pk
      ));
      setEditingPasskey(null);
      setNewName('');
      alert('✅ Nombre actualizado (simulado - no persiste en BD)');
    } catch (error) {
      alert(`❌ Error: ${error.message}`);
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
      'auth_success': '✅',
      'auth_failed': '❌',
      'passkey_enrolled': '🔑',
      'passkey_revoked': '🗑️',
      'user_created': '👤',
      'access_denied': '🚫',
      'policy_changed': '⚙️'
    };
    return icons[type] || '📝';
  };

  const getEventLabel = (type) => {
    const labels = {
      'auth_success': 'Autenticación exitosa',
      'auth_failed': 'Autenticación fallida',
      'passkey_enrolled': 'Passkey enrolada',
      'passkey_revoked': 'Passkey revocada',
      'user_created': 'Usuario creado',
      'access_denied': 'Acceso denegado',
      'policy_changed': 'Política modificada'
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
          <h2>👤 {user.display_name || user.email}</h2>
          <p className="user-email">{user.email}</p>
        </div>
        <div className="header-actions">
          <button onClick={() => navigate('/admin')} className="btn-admin">
            ⚙️ Panel Admin
          </button>
          <button onClick={onLogout} className="btn-logout">
            🚪 Cerrar Sesión
          </button>
        </div>
      </div>

      {riskInfo && (
        <div className="risk-summary">
          <div className="risk-card">
            <h4>📊 Nivel de Riesgo Actual</h4>
            <div className="risk-score">
              <span className={`risk-badge ${getRiskLevel(riskInfo.summary?.average_risk_score || 0).class}`}>
                {getRiskLevel(riskInfo.summary?.average_risk_score || 0).label}
              </span>
              <span className="risk-number">{(riskInfo.summary?.average_risk_score || 0).toFixed(1)}/100</span>
            </div>
          </div>
          <div className="risk-card">
            <h4>🔍 Evaluaciones (7 días)</h4>
            <div className="risk-number">{riskInfo.summary?.total_evaluations || 0}</div>
          </div>
        </div>
      )}

      <div className="dashboard-tabs">
        <button 
          className={`tab ${activeTab === 'passkeys' ? 'active' : ''}`}
          onClick={() => setActiveTab('passkeys')}
        >
          🔑 Mis Passkeys ({passkeys.length})
        </button>
        <button 
          className={`tab ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
        >
          📋 Historial de Acceso
        </button>
        <button 
          className={`tab ${activeTab === 'stats' ? 'active' : ''}`}
          onClick={() => setActiveTab('stats')}
        >
          📊 Estadísticas del Sistema
        </button>
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
                <div className="empty-icon">🔑</div>
                <h4>No tienes Passkeys enroladas</h4>
                <p>Crea tu primera passkey para acceder de forma segura sin contraseñas</p>
                <button className="btn-primary" onClick={() => navigate('/enroll')}>
                  ➕ Enrolar Nueva Passkey
                </button>
              </div>
            ) : (
              <>
                <div className="passkeys-stats">
                  <div className="stat-item">
                    <span className="stat-icon">🔑</span>
                    <div>
                      <div className="stat-number">{passkeys.length}</div>
                      <div className="stat-label">Passkeys activas</div>
                    </div>
                  </div>
                  <div className="stat-item">
                    <span className="stat-icon">💻</span>
                    <div>
                      <div className="stat-number">
                        {passkeys.filter(pk => pk.device_type === 'platform').length}
                      </div>
                      <div className="stat-label">Biométricas</div>
                    </div>
                  </div>
                  <div className="stat-item">
                    <span className="stat-icon">🔐</span>
                    <div>
                      <div className="stat-number">
                        {passkeys.filter(pk => pk.device_type !== 'platform').length}
                      </div>
                      <div className="stat-label">Hardware (USB)</div>
                    </div>
                  </div>
                </div>

                <div className="passkeys-grid">
                  {passkeys.map((passkey) => (
                    <div key={passkey.id} className="passkey-card-enhanced">
                      <div className="passkey-card-header">
                        <div className="passkey-icon-large">
                          {passkey.device_type === 'platform' ? '💻' : '🔑'}
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
                                ✏️
                              </button>
                            </h4>
                            <p className="passkey-type">
                              <span className="type-badge">
                                {passkey.device_type === 'platform' ? 
                                  '💻 Biométrica (Huella/Face ID)' : 
                                  '🔐 Hardware (USB/NFC)'}
                              </span>
                            </p>
                          </>
                        )}

                        <div className="passkey-dates">
                          <div className="date-item">
                            <span className="date-icon">📅</span>
                            <div>
                              <div className="date-label">Creada</div>
                              <div className="date-value">{formatDate(passkey.created_at)}</div>
                            </div>
                          </div>
                          <div className="date-item">
                            <span className="date-icon">⏱️</span>
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
                          onClick={() => handleRevokePasskey(passkey.id)}
                        >
                          🗑️ Revocar Passkey
                        </button>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="passkeys-actions">
                  <button className="btn-secondary" onClick={() => navigate('/enroll')}>
                    ➕ Agregar Nueva Passkey
                  </button>
                </div>
              </>
            )}
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
                <div className="empty-icon">📋</div>
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
                <div className="stat-icon-big">✅</div>
                <div className="stat-info">
                  <div className="stat-big-number">{stats.authentication?.success || 0}</div>
                  <div className="stat-big-label">Autenticaciones exitosas</div>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-icon-big">❌</div>
                <div className="stat-info">
                  <div className="stat-big-number">{stats.authentication?.failed || 0}</div>
                  <div className="stat-big-label">Intentos fallidos</div>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-icon-big">📊</div>
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
