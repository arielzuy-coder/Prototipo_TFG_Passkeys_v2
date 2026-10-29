import React, { useState, useEffect } from 'react';
import api from '../services/api';

function StepUpChallenge({ stepupData, onSuccess, onCancel }) {
  const [verificationType, setVerificationType] = useState('otp');
  const [otpCode, setOtpCode] = useState('');
  const [pin, setPin] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });
  const [timeLeft, setTimeLeft] = useState(900); // 15 minutos en segundos

  // Countdown timer
  useEffect(() => {
    if (timeLeft <= 0) {
      setMessage({ type: 'error', text: 'El tiempo ha expirado. Por favor, inicia sesión nuevamente.' });
      return;
    }

    const timer = setInterval(() => {
      setTimeLeft(prev => prev - 1);
    }, 1000);

    return () => clearInterval(timer);
  }, [timeLeft]);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const handleVerify = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage({ type: '', text: '' });

    try {
      let verificationData = {};

      if (verificationType === 'otp') {
        if (!otpCode || otpCode.length !== 6) {
          setMessage({ type: 'error', text: 'Por favor ingresa un código OTP de 6 dígitos' });
          setLoading(false);
          return;
        }
        verificationData = { otp: otpCode };
      } else if (verificationType === 'pin') {
        if (!pin || pin.length < 4) {
          setMessage({ type: 'error', text: 'Por favor ingresa un PIN de al menos 4 dígitos' });
          setLoading(false);
          return;
        }
        verificationData = { pin: pin };
      }

      const { data } = await api.post('/auth/stepup/verify', {
        stepup_token: stepupData.stepup_token,
        verification_type: verificationType,
        verification_data: verificationData
      });

      if (data.success) {
        setMessage({ type: 'success', text: '✅ Verificación exitosa. Accediendo al sistema...' });
        setTimeout(() => {
          onSuccess(data.user, data.tokens);
        }, 1500);
      }

    } catch (error) {
      console.error('Error en step-up:', error);
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || 'Error en la verificación. Intenta nuevamente.' 
      });
    } finally {
      setLoading(false);
    }
  };

  const riskScore = stepupData.risk_assessment?.score || 0;
  const riskLevel = stepupData.risk_assessment?.level || 'medium';

  // Determinar el mensaje contextual según los factores de riesgo
  const getContextualMessage = () => {
    const factors = stepupData.risk_assessment?.factors;
    
    if (!factors) {
      return "Por tu seguridad, necesitamos que completes una verificación adicional.";
    }

    // Prioridad 1: Nueva ubicación/país
    if (factors.location && !factors.location.known) {
      const locationMsg = factors.location.message || '';
      if (locationMsg.includes('Nueva ubicación')) {
        return "Hemos detectado un acceso desde una ubicación diferente a la habitual. Por tu seguridad, necesitamos verificar tu identidad.";
      }
    }

    // Prioridad 2: Dispositivo desconocido
    if (factors.device && !factors.device.known) {
      return "Hemos detectado un nuevo dispositivo intentando acceder a tu cuenta. Por tu seguridad, necesitamos verificar tu identidad.";
    }

    // Prioridad 3: Intentos fallidos recientes
    if (factors.failed_attempts && factors.failed_attempts.count > 0) {
      return "Detectamos intentos de acceso fallidos recientes. Por precaución, necesitamos verificar tu identidad.";
    }

    // Prioridad 4: Horario inusual
    if (factors.time && !factors.time.is_business_hours && riskScore < 40) {
      return "Detectamos un acceso fuera del horario habitual. Por tu seguridad, necesitamos verificar tu identidad.";
    }

    // Prioridad 5: Riesgo alto
    if (riskLevel === 'high' || riskScore >= 75) {
      return "Hemos detectado condiciones de riesgo elevado en tu intento de acceso. Por tu seguridad, necesitamos verificar tu identidad.";
    }

    // Prioridad 6: Riesgo medio
    if (riskLevel === 'medium' || riskScore >= 40) {
      return "Detectamos algunas condiciones inusuales en tu intento de acceso. Por precaución, necesitamos verificar tu identidad.";
    }

    // Default
    return "Por tu seguridad, necesitamos que completes una verificación adicional.";
  };

  return (
    <div className="stepup-container">
      <div className="stepup-card">
        <div className="stepup-header">
          <h2>🔐 Verificación Adicional Requerida</h2>
          <div className={`risk-badge risk-${riskLevel}`}>
            Nivel de Riesgo: {riskLevel.toUpperCase()} ({riskScore}/100)
          </div>
        </div>

        <div className="stepup-info">
          <p>
            {getContextualMessage()}
          </p>

          {stepupData.risk_assessment?.factors && (
            <div className="risk-factors">
              <h4>Factores detectados:</h4>
              <ul>
                {Object.entries(stepupData.risk_assessment.factors).map(([key, value]) => (
                  <li key={key}>
                    {value.message || `${key}: ${value.value}`}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div className="timer-display">
          ⏱️ Tiempo restante: <strong>{formatTime(timeLeft)}</strong>
        </div>

        <form onSubmit={handleVerify} className="stepup-form">
          <div className="verification-method-selector">
            <label>Selecciona el método de verificación:</label>
            <div className="method-buttons">
              <button
                type="button"
                className={`method-btn ${verificationType === 'otp' ? 'active' : ''}`}
                onClick={() => setVerificationType('otp')}
              >
                📱 Código OTP
              </button>
              <button
                type="button"
                className={`method-btn ${verificationType === 'pin' ? 'active' : ''}`}
                onClick={() => setVerificationType('pin')}
              >
                🔢 PIN
              </button>
              <button
                type="button"
                className={`method-btn ${verificationType === 'biometric' ? 'active' : ''}`}
                onClick={() => setVerificationType('biometric')}
              >
                👆 Biometría
              </button>
            </div>
          </div>

          {verificationType === 'otp' && (
            <div className="verification-input">
              <label htmlFor="otp">Código OTP (6 dígitos)</label>
              <div className="otp-hint">
                💡 Código generado: <strong>{stepupData.otp_code}</strong>
                <br />
                <small>(En producción, este código se enviaría por email/SMS)</small>
              </div>
              <input
                type="text"
                id="otp"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="123456"
                maxLength="6"
                autoFocus
                disabled={loading}
              />
            </div>
          )}

          {verificationType === 'pin' && (
            <div className="verification-input">
              <label htmlFor="pin">PIN de Seguridad</label>
              <small>Ingresa tu PIN personal de 4-6 dígitos</small>
              <input
                type="password"
                id="pin"
                value={pin}
                onChange={(e) => setPin(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="••••"
                maxLength="6"
                autoFocus
                disabled={loading}
              />
            </div>
          )}

          {verificationType === 'biometric' && (
            <div className="verification-input biometric-info">
              <p>
                👆 La verificación biométrica adicional utiliza el mismo dispositivo
                de autenticación (huella, Face ID, etc.)
              </p>
              <p>
                <strong>Nota:</strong> En este prototipo, la biometría se acepta automáticamente
                ya que WebAuthn ya validó tu identidad en el paso anterior.
              </p>
            </div>
          )}

          {message.text && (
            <div className={`message ${message.type}`}>
              {message.text}
            </div>
          )}

          <div className="stepup-actions">
            <button 
              type="submit" 
              className="btn-primary" 
              disabled={loading || timeLeft <= 0}
            >
              {loading ? (
                <>
                  <span className="spinner-small"></span>
                  Verificando...
                </>
              ) : (
                '✓ Verificar Identidad'
              )}
            </button>

            <button 
              type="button" 
              className="btn-secondary" 
              onClick={onCancel}
              disabled={loading}
            >
              ✕ Cancelar
            </button>
          </div>
        </form>

        <div className="stepup-footer">
          <p className="security-note">
            🔒 Esta verificación adicional protege tu cuenta contra accesos no autorizados.
          </p>
        </div>
      </div>
    </div>
  );
}

export default StepUpChallenge;
