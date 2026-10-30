import React, { useState, useEffect } from 'react';
import '../styles/AuditReports.css';
import api from '../services/api';
import AuditIntegrity from './AuditIntegrity';
import SusResults from './SusResults';

// El input datetime-local está en hora local del navegador: se envía con zona (UTC) al backend
const toUtcIso = (value) => (value ? new Date(value).toISOString() : null);

const AuditReports = () => {
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Filtros
  const [filters, setFilters] = useState({
    start_date: '',
    end_date: '',
    event_types: [],
    limit: 100
  });
  
  // Estado para estadísticas rápidas
  const [stats, setStats] = useState(null);
  
  // Cargar estadísticas iniciales
  useEffect(() => {
    loadStats();
  }, []);
  
  const loadStats = async () => {
    try {
      const { data } = await api.get('/api/audit/statistics/summary', { params: { days: 30 } });
      setStats(data);
    } catch (err) {
      console.error('Error cargando estadísticas:', err);
    }
  };
  
  const handleGenerateReport = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const { data } = await api.post('/api/audit/reports/aggregated', {
        start_date: toUtcIso(filters.start_date),
        end_date: toUtcIso(filters.end_date),
        event_types: filters.event_types.length > 0 ? filters.event_types : null,
        limit: filters.limit
      });
      setReportData(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };
  
  const handleExport = async (format) => {
    setLoading(true);
    setError(null);
    
    try {
      const exportRequest = {
        format: format,
        filters: {
          start_date: toUtcIso(filters.start_date),
          end_date: toUtcIso(filters.end_date),
          event_types: filters.event_types.length > 0 ? filters.event_types : null,
          limit: filters.limit
        }
      };
      
      const { data: blob } = await api.post('/api/audit/export', exportRequest, { responseType: 'blob' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit_export_${Date.now()}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };
  
  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters(prev => ({
      ...prev,
      [name]: value
    }));
  };
  
  const handleEventTypeToggle = (eventType) => {
    setFilters(prev => {
      const types = prev.event_types.includes(eventType)
        ? prev.event_types.filter(t => t !== eventType)
        : [...prev.event_types, eventType];
      return { ...prev, event_types: types };
    });
  };
  
  // Tipos de evento que registra el backend (services/common.audit)
  const EVENT_LABELS = {
    auth_success: 'Login exitoso',
    auth_failed: 'Login fallido (verificado)',
    auth_aborted: 'Login cancelado por el usuario',
    stepup_requested: 'Step-up solicitado',
    stepup_success: 'Step-up superado',
    stepup_failed: 'Step-up fallido',
    stepup_approval_requested: 'Aprobación de supervisor pedida',
    stepup_approved: 'Step-up aprobado por supervisor',
    stepup_denied: 'Step-up rechazado por supervisor',
    access_denied: 'Acceso denegado',
    passkey_enrolled: 'Passkey enrolada',
    passkey_revoked: 'Passkey revocada',
    reauth_success: 'Re-autenticación',
    session_reevaluated: 'Sesión reevaluada',
    session_revoked: 'Sesión revocada',
    session_ip_changed: 'Cambio de IP en sesión',
    logout: 'Cierre de sesión',
    user_created: 'Usuario creado',
    user_suspended: 'Usuario suspendido',
    account_recovery_started: 'Recuperación de cuenta',
    policy_created: 'Política creada',
    policy_updated: 'Política modificada',
    policy_toggled: 'Política activada/desactivada',
    policy_deleted: 'Política eliminada'
  };
  const labelOf = (type) => EVENT_LABELS[type] || type.replace(/_/g, ' ');
  const eventTypes = [
    'auth_success', 'auth_failed', 'auth_aborted', 'stepup_requested', 'stepup_success',
    'stepup_failed', 'access_denied', 'passkey_enrolled', 'passkey_revoked', 'session_revoked',
    'reauth_success', 'user_created'
  ];
  
  return (
    <div className="audit-reports-container">
      <h2>Auditoría y Reportes</h2>
      
      {/* Estadísticas Rápidas */}
      {stats && (
        <div className="stats-summary">
          <h3>Resumen de Últimos 30 Días</h3>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value">{stats.total_events}</div>
              <div className="stat-label">Total Eventos</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{stats.active_users}</div>
              <div className="stat-label">Usuarios Activos</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{stats.successful_logins}</div>
              <div className="stat-label">Logins Exitosos</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{stats.failed_logins}</div>
              <div className="stat-label">Logins Fallidos</div>
            </div>
            <div className="stat-card success-rate">
              <div className="stat-value">{stats.success_rate}%</div>
              <div className="stat-label">Tasa de Éxito</div>
            </div>
          </div>
        </div>
      )}

      <AuditIntegrity />

      <SusResults />
      
      {/* Filtros Avanzados */}
      <div className="filters-section">
        <h3>Filtros Avanzados</h3>
        <div className="filters-grid">
          <div className="filter-group">
            <label>Fecha Inicio:</label>
            <input
              type="datetime-local"
              name="start_date"
              value={filters.start_date}
              onChange={handleFilterChange}
            />
          </div>
          
          <div className="filter-group">
            <label>Fecha Fin:</label>
            <input
              type="datetime-local"
              name="end_date"
              value={filters.end_date}
              onChange={handleFilterChange}
            />
          </div>
          
          <div className="filter-group">
            <label>Límite de Registros:</label>
            <input
              type="number"
              name="limit"
              value={filters.limit}
              onChange={handleFilterChange}
              min="1"
              max="10000"
            />
          </div>
        </div>
        
        <div className="event-types-filter">
          <label>Tipos de Evento:</label>
          <div className="event-types-grid">
            {eventTypes.map(type => (
              <label key={type} className="checkbox-label">
                <input
                  type="checkbox"
                  checked={filters.event_types.includes(type)}
                  onChange={() => handleEventTypeToggle(type)}
                />
                {labelOf(type)}
              </label>
            ))}
          </div>
        </div>
      </div>
      
      {/* Botones de Acción */}
      <div className="actions-section">
        <button 
          onClick={handleGenerateReport}
          disabled={loading}
          className="btn-primary"
        >
          {loading ? 'Generando...' : 'Generar Reporte Agregado'}
        </button>
        
        <button 
          onClick={() => handleExport('csv')}
          disabled={loading}
          className="btn-export"
        >
          Exportar CSV
        </button>
        
        <button 
          onClick={() => handleExport('json')}
          disabled={loading}
          className="btn-export"
        >
          Exportar JSON
        </button>
      </div>
      
      {/* Error */}
      {error && (
        <div className="error-message">
          {error}
        </div>
      )}
      
      {/* Reporte Agregado */}
      {reportData && (
        <div className="report-section">
          <h3>Reporte Agregado</h3>
          
          <div className="report-period">
            <strong>Período:</strong> {reportData.period}
          </div>
          
          <div className="report-metrics">
            <div className="metric-row">
              <div className="metric-item">
                <span className="metric-label">Total Eventos:</span>
                <span className="metric-value">{reportData.total_events}</span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Usuarios Únicos:</span>
                <span className="metric-value">{reportData.unique_users}</span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Logins Totales:</span>
                <span className="metric-value">{reportData.total_logins}</span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Logins Fallidos:</span>
                <span className="metric-value">{reportData.failed_logins}</span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Desafíos Step-Up:</span>
                <span className="metric-value">{reportData.stepup_challenges}</span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Eventos Alto Riesgo:</span>
                <span className="metric-value">{reportData.high_risk_events}</span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Score Promedio Riesgo:</span>
                <span className="metric-value">{reportData.avg_risk_score.toFixed(2)}</span>
              </div>
            </div>
          </div>
          
          {/* Desglose por Tipo de Evento */}
          <div className="event-breakdown">
            <h4>Desglose por Tipo de Evento</h4>
            <div className="breakdown-grid">
              {Object.entries(reportData.event_type_breakdown).map(([type, count]) => (
                <div key={type} className="breakdown-item">
                  <span className="breakdown-type">{labelOf(type)}</span>
                  <span className="breakdown-count">{count}</span>
                </div>
              ))}
            </div>
          </div>
          
          {/* Top IPs */}
          {reportData.top_ips && reportData.top_ips.length > 0 && (
            <div className="top-ips">
              <h4>Top 10 IPs</h4>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Cantidad de Accesos</th>
                  </tr>
                </thead>
                <tbody>
                  {reportData.top_ips.map((item, idx) => (
                    <tr key={idx}>
                      <td>{item.ip}</td>
                      <td>{item.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          
          {/* Distribución por Hora */}
          {reportData.hourly_distribution && reportData.hourly_distribution.length > 0 && (
            <div className="hourly-distribution">
              <h4>Distribución por Hora del Día (hora de Buenos Aires)</h4>
              <div className="chart-container">
                {(() => {
                  // Las 24 horas, con cero donde no hubo eventos, para ver en qué franja se concentra la actividad
                  const counts = Object.fromEntries(reportData.hourly_distribution.map(h => [h.hour, h.count]));
                  const max = Math.max(1, ...reportData.hourly_distribution.map(h => h.count));
                  return Array.from({ length: 24 }, (_, hour) => {
                    const count = counts[hour] || 0;
                    return (
                      <div key={hour} className="chart-bar" title={`${hour}:00 – ${count} eventos`}>
                        <div className="bar-count">{count > 0 ? count : ''}</div>
                        <div
                          className={`bar ${count === 0 ? 'empty' : ''}`}
                          style={{ height: `${Math.round((count / max) * 140)}px` }}
                        />
                        <div className="bar-label">{hour % 3 === 0 ? `${hour}h` : ''}</div>
                      </div>
                    );
                  });
                })()}
              </div>
            </div>
          )}
        </div>
      )}
      
      {/* Botón Volver al Dashboard */}
      <div className="back-button-container">
        <button 
          onClick={() => window.location.href = '/dashboard'}
          className="back-button"
        >
          ← Volver al Dashboard
        </button>
      </div>
    </div>
  );
};

export default AuditReports;
