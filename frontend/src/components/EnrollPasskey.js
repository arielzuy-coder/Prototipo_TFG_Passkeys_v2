import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import api, { errorMessage } from '../services/api';
import { addPasskey, enrollWithInvitation } from '../services/webauthn';

/**
 * UC-01 Enrolar Passkey. Dos modos:
 *  - con invitación (?invite=...): alta o recuperación, sin sesión iniciada;
 *  - con sesión iniciada: agregar una passkey adicional (máx. 5).
 */
function EnrollPasskey({ user }) {
  const [params] = useSearchParams();
  const inviteToken = params.get('invite');
  const mode = inviteToken ? 'invite' : user ? 'add' : 'none';

  const [invitation, setInvitation] = useState(null);
  const [deviceName, setDeviceName] = useState('');
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(mode === 'invite');
  const [message, setMessage] = useState({ type: '', text: '' });
  const navigate = useNavigate();

  useEffect(() => {
    if (mode !== 'invite') return;
    api.get(`/auth/invitations/${encodeURIComponent(inviteToken)}`)
      .then(({ data }) => setInvitation(data))
      .catch((error) => setMessage({ type: 'error', text: errorMessage(error, 'Invitación inválida') }))
      .finally(() => setChecking(false));
  }, [mode, inviteToken]);

  const handleEnroll = async (e) => {
    e.preventDefault();
    if (!deviceName.trim()) {
      setMessage({ type: 'error', text: 'Poné un nombre para identificar este dispositivo' });
      return;
    }
    setLoading(true);
    setMessage({ type: '', text: '' });
    try {
      if (mode === 'invite') {
        await enrollWithInvitation(inviteToken, deviceName.trim());
        setMessage({ type: 'success', text: 'Passkey enrolada. Redirigiendo al inicio de sesión...' });
        setTimeout(() => navigate('/login', { replace: true }), 2000);
      } else {
        await addPasskey(deviceName.trim());
        setMessage({ type: 'success', text: 'Passkey agregada. Volviendo al panel...' });
        setTimeout(() => navigate('/dashboard', { replace: true }), 1500);
      }
    } catch (error) {
      setMessage({ type: 'error', text: errorMessage(error, 'Error al enrolar la passkey') });
    } finally {
      setLoading(false);
    }
  };

  if (mode === 'none') {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <h2>Enrolar Passkey</h2>
          <div className="message warning">
            Para enrolar tu primera passkey necesitás el link de invitación que te envía el administrador.
            Si perdiste tu dispositivo, pedí una recuperación de cuenta.
          </div>
          <div className="auth-links">
            <button onClick={() => navigate('/login')} className="link-button">← Volver al Login</button>
          </div>
        </div>
      </div>
    );
  }

  const title = mode === 'add' ? 'Agregar otra Passkey'
    : invitation?.purpose === 'recovery' ? 'Recuperar acceso' : 'Enrolar tu Passkey';
  const formDisabled = loading || checking || (mode === 'invite' && !invitation);

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h2>{title}</h2>
        <p className="auth-subtitle">
          {mode === 'add'
            ? 'Registrá otro dispositivo para poder iniciar sesión desde él'
            : 'Registrá este dispositivo para iniciar sesión sin contraseña'}
        </p>

        {checking && <p>Validando invitación...</p>}

        <form onSubmit={handleEnroll} className="auth-form">
          <div className="form-group">
            <label htmlFor="email">Cuenta</label>
            <input
              type="email"
              id="email"
              value={mode === 'add' ? user.email : invitation?.email || ''}
              readOnly
              disabled
            />
          </div>

          <div className="form-group">
            <label htmlFor="deviceName">Nombre del dispositivo</label>
            <input
              type="text"
              id="deviceName"
              value={deviceName}
              onChange={(e) => setDeviceName(e.target.value)}
              placeholder="Ej: Notebook trabajo, iPhone"
              maxLength={100}
              required
              disabled={formDisabled}
            />
          </div>

          {message.text && <div className={`message ${message.type}`}>{message.text}</div>}

          <button type="submit" className="btn-primary" disabled={formDisabled}>
            {loading ? (<><span className="spinner-small"></span> Enrolando...</>) : 'Enrolar Passkey'}
          </button>
        </form>

        <div className="auth-links">
          <button
            onClick={() => navigate(mode === 'add' ? '/dashboard' : '/login')}
            className="link-button"
            disabled={loading}
          >
            ← Volver
          </button>
        </div>

        <div className="info-box">
          <h4>¿Qué es una Passkey?</h4>
          <p>
            Una credencial criptográfica que reemplaza a la contraseña. La clave privada nunca sale de tu
            dispositivo y se desbloquea con tu huella, rostro o PIN.
          </p>
          <ul>
            <li>Sin contraseñas que recordar</li>
            <li>Resistente a phishing: solo funciona en este sitio</li>
            <li>Estándar FIDO2/WebAuthn</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default EnrollPasskey;
