import React, { useEffect, useRef, useState } from 'react';
import api, { errorMessage } from '../services/api';
import { stepUpWithPasskey } from '../services/webauthn';
import '../styles/Security_v2.css';

const METHOD_LABELS = {
  passkey: '👆 Passkey (biometría / PIN)',
  otp: '📧 Código por email',
  supervisor: '🧑‍💼 Aprobación de supervisor'
};

/**
 * UC-04 Desafío adaptativo por riesgo (step-up).
 * Métodos según la tesis: re-autenticación biométrica, OTP o aprobación manual por supervisor.
 */
function StepUpChallenge({ stepupData, onSuccess, onCancel }) {
  const methods = stepupData.verification_methods || ['passkey'];
  const token = stepupData.stepup_token;

  const [method, setMethod] = useState(methods[0]);
  const [otpCode, setOtpCode] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [waitingApproval, setWaitingApproval] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });
  const [timeLeft, setTimeLeft] = useState(() => {
    const ms = new Date(stepupData.expires_at) - new Date();
    return Number.isFinite(ms) ? Math.max(0, Math.floor(ms / 1000)) : 600;
  });
  const pollRef = useRef(null);

  useEffect(() => {
    if (timeLeft <= 0) {
      setMessage({ type: 'error', text: 'El tiempo expiró. Iniciá sesión nuevamente.' });
      return undefined;
    }
    const timer = setInterval(() => setTimeLeft((t) => t - 1), 1000);
    return () => clearInterval(timer);
  }, [timeLeft]);

  useEffect(() => () => clearInterval(pollRef.current), []);

  const formatTime = (seconds) => `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;

  const finish = (data) => {
    clearInterval(pollRef.current);
    setMessage({ type: 'success', text: '✅ Verificación exitosa. Accediendo al sistema...' });
    setTimeout(() => onSuccess(data.user, data.tokens), 1200);
  };

  const handlePasskey = async () => {
    setLoading(true);
    setMessage({ type: '', text: '' });
    try {
      finish(await stepUpWithPasskey(token));
    } catch (error) {
      setMessage({ type: 'error', text: errorMessage(error, 'Verificación fallida') });
    } finally {
      setLoading(false);
    }
  };

  const handleSendOtp = async () => {
    setLoading(true);
    setMessage({ type: '', text: '' });
    try {
      await api.post('/auth/stepup/otp/send', { stepup_token: token });
      setOtpSent(true);
      setMessage({ type: 'info', text: 'Te enviamos un código de 6 dígitos a tu email registrado.' });
    } catch (error) {
      setMessage({ type: 'error', text: errorMessage(error, 'No se pudo enviar el código') });
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    if (otpCode.length !== 6) {
      setMessage({ type: 'error', text: 'Ingresá el código de 6 dígitos' });
      return;
    }
    setLoading(true);
    try {
      const { data } = await api.post('/auth/stepup/verify', {
        stepup_token: token, verification_type: 'otp', otp: otpCode
      });
      finish(data);
    } catch (error) {
      setMessage({ type: 'error', text: errorMessage(error, 'Código incorrecto') });
    } finally {
      setLoading(false);
    }
  };

  const pollApproval = async () => {
    try {
      const res = await api.post('/auth/stepup/verify', { stepup_token: token, verification_type: 'supervisor' });
      if (res.status === 200) finish(res.data);
    } catch (error) {
      clearInterval(pollRef.current);
      setWaitingApproval(false);
      setMessage({ type: 'error', text: 'La solicitud fue rechazada o venció. Iniciá sesión nuevamente.' });
    }
  };

  const handleRequestApproval = async () => {
    setLoading(true);
    setMessage({ type: '', text: '' });
    try {
      await api.post('/auth/stepup/supervisor/request', { stepup_token: token });
      setWaitingApproval(true);
      setMessage({ type: 'info', text: 'Solicitud enviada. Esperando que un supervisor la apruebe...' });
      pollRef.current = setInterval(pollApproval, 4000);
    } catch (error) {
      setMessage({ type: 'error', text: errorMessage(error, 'No se pudo enviar la solicitud') });
    } finally {
      setLoading(false);
    }
  };

  const riskScore = stepupData.risk_assessment?.score ?? 0;
  const riskLevel = stepupData.risk_assessment?.level || 'medium';
  const factors = stepupData.risk_assessment?.factors || {};
  const expired = timeLeft <= 0;

  return (
    <div className="stepup-container">
      <div className="stepup-card">
        <div className="stepup-header">
          <h2>🔐 Verificación adicional requerida</h2>
          <div className={`risk-badge risk-${riskLevel}`}>
            Nivel de riesgo: {riskLevel.toUpperCase()} ({riskScore}/100)
          </div>
        </div>

        <div className="stepup-info">
          <p>Detectamos condiciones inusuales en este acceso. Por tu seguridad, confirmá tu identidad.</p>
          {Object.keys(factors).length > 0 && (
            <div className="risk-factors">
              <h4>Factores detectados:</h4>
              <ul>
                {Object.entries(factors).map(([key, value]) => (
                  <li key={key}>{value?.message || key}</li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div className="timer-display">⏱️ Tiempo restante: <strong>{formatTime(Math.max(0, timeLeft))}</strong></div>

        {methods.length > 1 && (
          <div className="verification-method-selector">
            <label>Método de verificación:</label>
            <div className="method-buttons">
              {methods.map((m) => (
                <button
                  key={m}
                  type="button"
                  className={`method-btn ${method === m ? 'active' : ''}`}
                  onClick={() => { setMethod(m); setMessage({ type: '', text: '' }); }}
                  disabled={loading || waitingApproval}
                >
                  {METHOD_LABELS[m] || m}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="stepup-form">
          {method === 'passkey' && (
            <div className="verification-input biometric-info">
              <p>Volvé a confirmar con tu passkey (huella, rostro o PIN del dispositivo).</p>
              <button type="button" className="btn-primary" onClick={handlePasskey} disabled={loading || expired}>
                {loading ? 'Verificando...' : '👆 Verificar con Passkey'}
              </button>
            </div>
          )}

          {method === 'otp' && (
            <form onSubmit={handleVerifyOtp} className="verification-input">
              {!otpSent ? (
                <button type="button" className="btn-primary" onClick={handleSendOtp} disabled={loading || expired}>
                  📧 Enviar código a mi email
                </button>
              ) : (
                <>
                  <label htmlFor="otp">Código (6 dígitos)</label>
                  <input
                    type="text"
                    id="otp"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    placeholder="123456"
                    maxLength="6"
                    autoFocus
                    disabled={loading}
                  />
                  <button type="submit" className="btn-primary" disabled={loading || expired}>✓ Verificar código</button>
                </>
              )}
            </form>
          )}

          {method === 'supervisor' && (
            <div className="verification-input">
              <p>Un administrador revisa el contexto del acceso y lo aprueba o rechaza.</p>
              <button
                type="button"
                className="btn-primary"
                onClick={handleRequestApproval}
                disabled={loading || waitingApproval || expired}
              >
                {waitingApproval ? '⏳ Esperando aprobación...' : '🧑‍💼 Solicitar aprobación'}
              </button>
            </div>
          )}

          {message.text && <div className={`message ${message.type}`}>{message.text}</div>}

          <div className="stepup-actions">
            <button type="button" className="btn-secondary" onClick={onCancel} disabled={loading}>✕ Cancelar</button>
          </div>
        </div>

        <div className="stepup-footer">
          <p className="security-note">🔒 Esta verificación protege tu cuenta contra accesos no autorizados.</p>
        </div>
      </div>
    </div>
  );
}

export default StepUpChallenge;
