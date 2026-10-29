import React, { useEffect, useRef, useState } from 'react';
import api, { errorMessage } from '../services/api';
import { stepUpWithPasskey } from '../services/webauthn';
import '../styles/Security_v2.css';

const FACTOR_LABELS = {
  device: 'Dispositivo',
  location: 'Ubicación',
  time: 'Horario',
  failed_attempts: 'Intentos fallidos',
  velocity: 'Frecuencia de accesos'
};

const LEVEL_LABELS = { low: 'BAJO', medium: 'MEDIO', high: 'ALTO' };

const fmtPts = (n) => (Number.isFinite(n) ? n.toLocaleString('es-AR', { maximumFractionDigits: 1 }) : '–');

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
  const assessment = stepupData.risk_assessment || {};
  const factors = assessment.factors || {};
  const thresholds = assessment.thresholds || { low: 40, high: 75 };
  const factorRows = Object.entries(factors)
    .map(([key, value]) => ({
      key,
      label: FACTOR_LABELS[key] || key,
      message: value?.message || '',
      points: typeof value?.points === 'number' ? value.points : null
    }))
    .sort((a, b) => (b.points ?? 0) - (a.points ?? 0));
  const computedScore = typeof assessment.computed_score === 'number'
    ? assessment.computed_score
    : factorRows.reduce((sum, f) => sum + (f.points ?? 0), 0);
  const policyText = assessment.policy?.description || assessment.policy?.name;
  // Se muestra el puntaje calculado por el motor; el nivel sale de ese puntaje y los umbrales.
  // Si el puntaje es bajo y aun así se pide step-up, lo explica la política aplicada.
  const shownScore = factorRows.length ? computedScore : riskScore;
  const shownLevel = factorRows.length
    ? (shownScore >= thresholds.high ? 'high' : shownScore >= thresholds.low ? 'medium' : 'low')
    : riskLevel;
  const expired = timeLeft <= 0;

  return (
    <div className="stepup-container">
      <div className="stepup-card">
        <div className="stepup-header">
          <h2>🔐 Verificación adicional requerida</h2>
          <div className={`risk-badge risk-${shownLevel}`}>
            Nivel de riesgo: {LEVEL_LABELS[shownLevel] || shownLevel.toUpperCase()} ({fmtPts(shownScore)}/100)
          </div>
        </div>

        <div className="stepup-info">
          <p>Tu passkey es válida, pero el contexto de este acceso requiere una verificación más.</p>
          {factorRows.length > 0 && (
            <div className="risk-factors">
              <h4>¿Por qué se pide? Evaluación del motor de riesgo</h4>
              <table className="risk-breakdown">
                <thead>
                  <tr><th>Factor</th><th>Detalle</th><th className="pts">Puntos</th></tr>
                </thead>
                <tbody>
                  {factorRows.map((f) => (
                    <tr key={f.key} className={f.points > 0 ? 'hit' : ''}>
                      <td>{f.label}</td>
                      <td>{f.message}</td>
                      <td className="pts">{f.points === null ? '–' : `+${fmtPts(f.points)}`}</td>
                    </tr>
                  ))}
                  <tr className="total">
                    <td colSpan="2">Puntaje de riesgo</td>
                    <td className="pts">{fmtPts(computedScore)}/100</td>
                  </tr>
                </tbody>
              </table>
              <p className="risk-scale">
                Escala: bajo &lt; {thresholds.low} · medio {thresholds.low}–{thresholds.high - 1} · alto ≥ {thresholds.high}
              </p>
              {policyText && <p className="risk-policy">Política aplicada: <strong>{policyText}</strong></p>}
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
