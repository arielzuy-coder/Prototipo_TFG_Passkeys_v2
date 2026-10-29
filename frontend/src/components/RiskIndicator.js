import React from 'react';

function RiskIndicator({ assessment }) {
  if (!assessment) return null;

  const { score, level, factors } = assessment;

  const getRiskColor = (level) => {
    switch (level) {
      case 'low':
        return '#28a745';
      case 'medium':
        return '#ffc107';
      case 'high':
        return '#dc3545';
      default:
        return '#6c757d';
    }
  };

  const getRiskIcon = (level) => {
    switch (level) {
      case 'low':
        return '✅';
      case 'medium':
        return '⚠️';
      case 'high':
        return '🚨';
      default:
        return 'ℹ️';
    }
  };

  const getRiskLabel = (level) => {
    switch (level) {
      case 'low':
        return 'Riesgo Bajo';
      case 'medium':
        return 'Riesgo Medio';
      case 'high':
        return 'Riesgo Alto';
      default:
        return 'Riesgo Desconocido';
    }
  };

  return (
    <div className="risk-indicator" style={{ borderColor: getRiskColor(level) }}>
      <div className="risk-header">
        <span className="risk-icon">{getRiskIcon(level)}</span>
        <div className="risk-info">
          <h4>{getRiskLabel(level)}</h4>
          <div className="risk-score">
            Score: <strong>{score}/100</strong>
          </div>
        </div>
      </div>

      <div className="risk-progress">
        <div 
          className="risk-progress-bar" 
          style={{ 
            width: `${score}%`,
            backgroundColor: getRiskColor(level)
          }}
        />
      </div>

      <div className="risk-factors">
        <h5>Factores Evaluados:</h5>
        <ul>
          {factors.device && (
            <li>
              <span className="factor-label">Dispositivo:</span>
              <span className={`factor-value ${factors.device.known ? 'good' : 'warning'}`}>
                {factors.device.message}
              </span>
            </li>
          )}
          {factors.location && (
            <li>
              <span className="factor-label">Ubicación:</span>
              <span className={`factor-value ${factors.location.known ? 'good' : 'warning'}`}>
                {factors.location.message}
              </span>
            </li>
          )}
          {factors.time && (
            <li>
              <span className="factor-label">Horario:</span>
              <span className={`factor-value ${factors.time.is_business_hours ? 'good' : 'warning'}`}>
                {factors.time.message}
              </span>
            </li>
          )}
          {factors.failed_attempts && (
            <li>
              <span className="factor-label">Intentos fallidos:</span>
              <span className={`factor-value ${factors.failed_attempts.count === 0 ? 'good' : 'warning'}`}>
                {factors.failed_attempts.message}
              </span>
            </li>
          )}
        </ul>
      </div>
    </div>
  );
}

export default RiskIndicator;