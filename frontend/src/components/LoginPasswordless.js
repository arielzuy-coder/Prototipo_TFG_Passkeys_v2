import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { startAuthentication } from '@simplewebauthn/browser';
import api from '../services/api';
import RiskIndicator from './RiskIndicator';
import StepUpChallenge from './StepUpChallenge';

function LoginPasswordless({ onLogin }) {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });
  const [riskAssessment, setRiskAssessment] = useState(null);
  const [requiresStepUp, setRequiresStepUp] = useState(false);
  const [stepupData, setStepupData] = useState(null);
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    
    if (!email) {
      setMessage({ type: 'error', text: 'Por favor ingresa tu email' });
      return;
    }

    setLoading(true);
    setMessage({ type: '', text: '' });
    setRiskAssessment(null);
    setRequiresStepUp(false);
    setStepupData(null);

    try {
      const { data: options } = await api.post('/auth/login/begin', { email });

      let asseResp;
      try {
        asseResp = await startAuthentication(options);
      } catch (error) {
        // Notificar al backend sobre el fallo de autenticación
        try {
          await api.post('/auth/login/failed', { 
            email,
            reason: error.name === 'NotAllowedError' ? 'user_cancelled' : 'authentication_error',
            error_message: error.message
          });
        } catch (notifyError) {
          console.error('Error al notificar fallo:', notifyError);
        }
        
        if (error.name === 'NotAllowedError') {
          throw new Error('Operación cancelada por el usuario');
        }
        throw new Error('Error en la autenticación biométrica');
      }

      const { data: result } = await api.post('/auth/login/complete', {
        email,
        credential: asseResp
      });

      if (result.success) {
        setRiskAssessment(result.risk_assessment);

        if (result.requires_stepup) {
          // Guardar todos los datos necesarios para el step-up
          setStepupData(result);
          setRequiresStepUp(true);
          setMessage({ 
            type: 'warning', 
            text: '⚠️ Se requiere verificación adicional debido al nivel de riesgo detectado' 
          });
        } else {
          setMessage({ 
            type: 'success', 
            text: '✅ Autenticación exitosa. Accediendo al sistema...' 
          });
          
          setTimeout(() => {
            onLogin(result.user, result.tokens);
          }, 1500);
        }
      }

    } catch (error) {
      console.error('Error en login:', error);
      
      if (error.response?.status === 403) {
        setMessage({ 
          type: 'error', 
          text: '🚫 Acceso denegado: ' + (error.response.data.detail?.message || 'Riesgo demasiado alto')
        });
        if (error.response.data.detail?.risk_score) {
          setRiskAssessment({
            score: error.response.data.detail.risk_score,
            level: 'high',
            factors: error.response.data.detail.factors || {}
          });
        }
      } else {
        setMessage({ 
          type: 'error', 
          text: error.response?.data?.detail || error.message || 'Error al iniciar sesión'
        });
      }
    } finally {
      setLoading(false);
    }
  };

  const handleStepUpSuccess = (user, tokens) => {
    setMessage({ 
      type: 'success', 
      text: '✅ Verificación exitosa. Accediendo al sistema...' 
    });
    setTimeout(() => {
      onLogin(user, tokens);
    }, 1500);
  };

  const handleStepUpCancel = () => {
    setRequiresStepUp(false);
    setStepupData(null);
    setMessage({ 
      type: 'info', 
      text: 'Verificación cancelada. Por favor, inicia sesión nuevamente cuando estés listo.' 
    });
  };

  // Si se requiere step-up, mostrar el componente de verificación
  if (requiresStepUp && stepupData) {
    return (
      <StepUpChallenge 
        stepupData={stepupData}
        onSuccess={handleStepUpSuccess}
        onCancel={handleStepUpCancel}
      />
    );
  }

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h2>🔐 Inicio de Sesión</h2>
        <p className="auth-subtitle">
          Autenticación passwordless con evaluación de riesgo Zero Trust
        </p>

        <form onSubmit={handleLogin} className="auth-form">
          <div className="form-group">
            <label htmlFor="email">📧 Email</label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="usuario@empresa.com"
              required
              disabled={loading}
            />
          </div>

          {message.text && (
            <div className={`message ${message.type}`}>
              {message.text}
            </div>
          )}

          {riskAssessment && !requiresStepUp && (
            <RiskIndicator assessment={riskAssessment} />
          )}

          <button 
            type="submit" 
            className="btn-primary" 
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner-small"></span>
                Autenticando...
              </>
            ) : (
              '🔑 Iniciar Sesión'
            )}
          </button>
        </form>

        <div className="auth-links">
          <button 
            onClick={() => navigate('/enroll')} 
            className="link-button"
            disabled={loading}
          >
            ¿Primera vez? Enrolar Passkey →
          </button>
        </div>

        <div className="info-box">
          <h4>🛡️ Seguridad Zero Trust Activada</h4>
          <p>
            Este sistema evalúa continuamente el contexto de tu acceso:
          </p>
          <ul>
            <li>✅ Dispositivo utilizado</li>
            <li>✅ Ubicación geográfica</li>
            <li>✅ Horario de acceso</li>
            <li>✅ Comportamiento histórico</li>
          </ul>
          <p className="note">
            Si detectamos actividad inusual, solicitaremos verificación adicional.
          </p>
        </div>
      </div>
    </div>
  );
}

export default LoginPasswordless;
