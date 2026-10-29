import React, { useState, useEffect } from 'react';
import '../styles/AuditReports.css';

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
      const response = await fetch(`${process.env.REACT_APP_API_URL}/api/audit/statistics/summary?days=30`, {
        credentials: 'include'
      });
      
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Error cargando estadísticas:', err);
    }
  };
  
  const handleGenerateReport = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL}/api/audit/reports/aggregated`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          start_date: filters.start_date || null,
          end_date: filters.end_date || null,
          event_types: filters.event_types.length > 0 ? filters.event_types : null,
          limit: filters.limit
        })
      });
      
      if (!response.ok) {
        throw new Error('Error al generar reporte');
      }
      
      const data = await response.json();
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
          start_date: filters.start_date || null,
          end_date: filters.end_date || null,
          event_types: filters.event_types.length > 0 ? filters.event_types : null,
          limit: filters.limit
        }
      };
      
      const response = await fetch(`${process.env.REACT_APP_API_URL}/api/audit/export`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(exportRequest)
      });
      
      if (!response.ok) {
        throw new Error('Error al exportar datos');
      }
      
      // Descargar el archivo
      const blob = await response.blob();
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
  
  const eventTypes = [
    'login_success',
    'login_failed',
    'passkey_registered',
    'stepup_required',
    'stepup_completed',
    'access_granted',
    'access_denied',
    'session_created',
    'session_expired'
  ];
  
  return (
    <div className="audit-reports-container">
      <h2>📊 Auditoría y Reportes</h2>
      
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
      
      {/* Filtros Avanzados */}
      <div className="filters-section">
        <h3>🔍 Filtros Avanzados</h3>
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
                {type.replace(/_/g, ' ')}
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
          {loading ? '⏳ Generando...' : '📈 Generar Reporte Agregado'}
        </button>
        
        <button 
          onClick={() => handleExport('csv')}
          disabled={loading}
          className="btn-export"
        >
          📄 Exportar CSV
        </button>
        
        <button 
          onClick={() => handleExport('json')}
          disabled={loading}
          className="btn-export"
        >
          📋 Exportar JSON
        </button>
      </div>
      
      {/* Error */}
      {error && (
        <div className="error-message">
          ❌ {error}
        </div>
      )}
      
      {/* Reporte Agregado */}
      {reportData && (
        <div className="report-section">
          <h3>📊 Reporte Agregado</h3>
          
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
                  <span className="breakdown-type">{type.replace(/_/g, ' ')}</span>
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
              <h4>Distribución por Hora del Día</h4>
              <div className="chart-container">
                {reportData.hourly_distribution.map(item => (
                  <div key={item.hour} className="chart-bar">
                    <div 
                      className="bar" 
                      style={{ 
                        height: `${(item.count / Math.max(...reportData.hourly_distribution.map(h => h.count))) * 100}%` 
                      }}
                      title={`${item.hour}:00 - ${item.count} eventos`}
                    />
                    <div className="bar-label">{item.hour}h</div>
                  </div>
                ))}
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
