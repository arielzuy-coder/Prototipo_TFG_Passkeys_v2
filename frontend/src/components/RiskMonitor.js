import React, { useState, useEffect } from 'react';
import api from '../services/api';

function RiskMonitor({ user }) {
  const [riskData, setRiskData] = useState(null);
  const [riskHistory, setRiskHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  useEffect(() => {
    loadRiskData();
    
    let interval;
    if (autoRefresh) {
      interval = setInterval(loadRiskData, 30000); // Refresh cada 30 segundos
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh]);

  const loadRiskData = async () => {
    try {
      const { data } = await api.get('/risk/dashboard');
      setRiskData(data);
      
      // Agregar al historial (máximo 10 evaluaciones)
      if (data.latest_evaluation) {
        setRiskHistory(prev => {
          const newHistory = [data.latest_evaluation, ...prev];
          return newHistory.slice(0, 10);
        });
      }
      
      setLoading(false);
    } catch (error) {
      console.error('Error al cargar datos de riesgo:', error);
      setLoading(false);
    }
  };

  const getRiskLevel = (score) => {
    if (score < 40) return { label: 'BAJO', class: 'low', color: '#28a745', icon: '' };
    if (score < 75) return { label: 'MEDIO', class: 'medium', color: '#ffc107', icon: '' };
    return { label: 'ALTO', class: 'high', color: '#dc3545', icon: '' };
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString('es-AR', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getTimeAgo = (dateString) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Ahora mismo';
    if (diffMins < 60) return `Hace ${diffMins} min`;
    return formatDate(dateString);
  };

  if (loading) {
    return (
      <div className="risk-monitor loading">
        <div className="spinner"></div>
        <p>Cargando evaluación de riesgo...</p>
      </div>
    );
  }

  if (!riskData) {
    return (
      <div className="risk-monitor empty">
        <p>No hay datos de riesgo disponibles</p>
      </div>
    );
  }

  const currentRisk = riskData.latest_evaluation || {};
  const riskLevel = getRiskLevel(currentRisk.risk_score || 0);

  return (
    <div className="risk-monitor-container">
      <div className="risk-monitor-header">
        <h3>Evaluación de Riesgo en Tiempo Real</h3>
        <div className="risk-monitor-controls">
          <label className="auto-refresh-toggle">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Auto-refresh (30s)
          </label>
          <button 
            className="btn-refresh"
            onClick={loadRiskData}
            title="Actualizar ahora"
          >
            Actualizar
          </button>
        </div>
      </div>

      {/* Panel principal de riesgo */}
      <div className="risk-main-panel">
        <div className="risk-gauge-container">
          <svg className="risk-gauge" viewBox="0 0 200 120">
            {/* Arco de fondo */}
            <path
              d="M 20 100 A 80 80 0 0 1 180 100"
              fill="none"
              stroke="#e9ecef"
              strokeWidth="20"
              strokeLinecap="round"
            />
            
            {/* Arco de progreso */}
            <path
              d="M 20 100 A 80 80 0 0 1 180 100"
              fill="none"
              stroke={riskLevel.color}
              strokeWidth="20"
              strokeLinecap="round"
              strokeDasharray={`${(currentRisk.risk_score || 0) * 2.51} 251`}
              style={{ transition: 'stroke-dasharray 1s ease' }}
            />
            
            {/* Texto central */}
            <text x="100" y="80" textAnchor="middle" fontSize="36" fontWeight="700" fill={riskLevel.color}>
              {(currentRisk.risk_score || 0).toFixed(0)}
            </text>
            <text x="100" y="100" textAnchor="middle" fontSize="14" fill="#666">
              / 100
            </text>
          </svg>
          
          <div className="risk-level-badge">
            <span className={`risk-badge-large ${riskLevel.class}`}>
              {riskLevel.icon} {riskLevel.label}
            </span>
          </div>
        </div>

        <div className="risk-details">
          <div className="risk-detail-item">
            <span className="risk-detail-icon"></span>
            <div>
              <div className="risk-detail-label">Última evaluación</div>
              <div className="risk-detail-value">
                {currentRisk.timestamp ? getTimeAgo(currentRisk.timestamp) : 'Nunca'}
              </div>
            </div>
          </div>

          <div className="risk-detail-item">
            <span className="risk-detail-icon"></span>
            <div>
              <div className="risk-detail-label">Ubicación actual</div>
              <div className="risk-detail-value">
                {currentRisk.context?.location || 'Desconocida'}
              </div>
            </div>
          </div>

          <div className="risk-detail-item">
            <span className="risk-detail-icon"></span>
            <div>
              <div className="risk-detail-label">Dispositivo</div>
              <div className="risk-detail-value">
                {currentRisk.context?.device_fingerprint ? 'Conocido' : 'Desconocido'}
              </div>
            </div>
          </div>

          <div className="risk-detail-item">
            <span className="risk-detail-icon"></span>
            <div>
              <div className="risk-detail-label">Horario</div>
              <div className="risk-detail-value">
                {currentRisk.context?.is_business_hours ? 'Laboral' : 'Fuera de horario'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Factores de riesgo detectados */}
      {currentRisk.risk_factors && Object.keys(currentRisk.risk_factors).length > 0 && (
        <div className="risk-factors-panel">
          <h4>Factores de Riesgo Detectados</h4>
          <div className="risk-factors-grid">
            {Object.entries(currentRisk.risk_factors).map(([factor, score]) => (
              <div key={factor} className="risk-factor-item">
                <div className="risk-factor-header">
                  <span className="risk-factor-name">{formatFactorName(factor)}</span>
                  <span className={`risk-factor-score ${getFactorClass(score)}`}>
                    +{score}
                  </span>
                </div>
                <div className="risk-factor-bar">
                  <div 
                    className={`risk-factor-fill ${getFactorClass(score)}`}
                    style={{ width: `${(score / 30) * 100}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Historial de evaluaciones */}
      <div className="risk-history-panel">
        <h4>Historial de Evaluaciones (últimas 10)</h4>
        {riskHistory.length === 0 ? (
          <p className="empty-text">No hay historial disponible</p>
        ) : (
          <div className="risk-history-timeline">
            {riskHistory.map((evaluation, index) => {
              const level = getRiskLevel(evaluation.risk_score);
              return (
                <div key={index} className="risk-history-item">
                  <div className="risk-history-time">
                    {formatDate(evaluation.timestamp)}
                  </div>
                  <div className="risk-history-dot" style={{ background: level.color }}></div>
                  <div className="risk-history-content">
                    <div className="risk-history-score">
                      <span className={`risk-badge-small ${level.class}`}>
                        {level.icon} {evaluation.risk_score.toFixed(0)}
                      </span>
                    </div>
                    <div className="risk-history-location">
                      {evaluation.context?.location || 'Ubicación desconocida'}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Resumen de estadísticas */}
      {riskData.summary && (
        <div className="risk-summary-stats">
          <div className="risk-stat-card">
            <div className="risk-stat-icon"></div>
            <div className="risk-stat-info">
              <div className="risk-stat-number">{riskData.summary.total_evaluations}</div>
              <div className="risk-stat-label">Evaluaciones totales</div>
            </div>
          </div>
          <div className="risk-stat-card">
            <div className="risk-stat-icon"></div>
            <div className="risk-stat-info">
              <div className="risk-stat-number">{riskData.summary.average_risk_score.toFixed(1)}</div>
              <div className="risk-stat-label">Score promedio</div>
            </div>
          </div>
          <div className="risk-stat-card">
            <div className="risk-stat-icon"></div>
            <div className="risk-stat-info">
              <div className="risk-stat-number">{riskData.summary.high_risk_count ?? 0}</div>
              <div className="risk-stat-label">Alertas de riesgo alto</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Funciones auxiliares
function formatFactorName(factor) {
  const names = {
    'new_location': 'Nueva ubicación',
    'new_device': 'Nuevo dispositivo',
    'unusual_time': 'Horario inusual',
    'failed_attempts': 'Intentos fallidos',
    'suspicious_pattern': 'Patrón sospechoso',
    'velocity_check': 'Velocidad de acceso',
    'device_mismatch': 'Dispositivo no coincide'
  };
  return names[factor] || factor;
}

function getFactorClass(score) {
  if (score < 10) return 'factor-low';
  if (score < 20) return 'factor-medium';
  return 'factor-high';
}

export default RiskMonitor;
