import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { startRegistration } from '@simplewebauthn/browser';
import api from '../services/api';

function EnrollPasskey() {
  const [email, setEmail] = useState('');
  const [deviceName, setDeviceName] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });
  const navigate = useNavigate();

  const handleEnroll = async (e) => {
    e.preventDefault();
    
    if (!email || !deviceName) {
      setMessage({ type: 'error', text: 'Por favor completa todos los campos' });
      return;
    }

    setLoading(true);
    setMessage({ type: '', text: '' });

    try {
      const { data: options } = await api.post('/auth/register/begin', { email });
      
      let attResp;
      try {
        attResp = await startRegistration(options);
      } catch (error) {
        if (error.name === 'NotAllowedError') {
          throw new Error('Operación cancelada por el usuario');
        }
        throw new Error('Error en la autenticación biométrica');
      }

      const { data: result } = await api.post('/auth/register/complete', {
        email,
        credential: attResp,
        device_name: deviceName
      });

      if (result.success) {
        setMessage({ 
          type: 'success', 
          text: '✅ Passkey enrolada exitosamente. Redirigiendo al login...' 
        });
        
        setTimeout(() => {
          navigate('/login');
        }, 2000);
      }

    } catch (error) {
      console.error('Error en enrolamiento:', error);
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || error.message || 'Error al enrolar Passkey'
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h2>📱 Enrolar Nueva Passkey</h2>
        <p className="auth-subtitle">
          Registra tu dispositivo para autenticación sin contraseña
        </p>

        <form onSubmit={handleEnroll} className="auth-form">
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

          <div className="form-group">
            <label htmlFor="deviceName">💻 Nombre del Dispositivo</label>
            <input
              type="text"
              id="deviceName"
              value={deviceName}
              onChange={(e) => setDeviceName(e.target.value)}
              placeholder="Ej: Laptop Dell Trabajo"
              required
              disabled={loading}
            />
          </div>

          {message.text && (
            <div className={`message ${message.type}`}>
              {message.text}
            </div>
          )}

          <button 
            type="submit" 
            className="btn-primary" 
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner-small"></span>
                Enrolando...
              </>
            ) : (
              '🔑 Enrolar Passkey'
            )}
          </button>
        </form>

        <div className="auth-links">
          <button 
            onClick={() => navigate('/login')} 
            className="link-button"
            disabled={loading}
          >
            ← Volver al Login
          </button>
        </div>

        <div className="info-box">
          <h4>ℹ️ ¿Qué es una Passkey?</h4>
          <p>
            Las Passkeys son credenciales criptográficas que reemplazan las contraseñas tradicionales.
            Utilizan biometría (huella, Face ID) o PIN del dispositivo para autenticarte de forma segura.
          </p>
          <ul>
            <li>✅ Sin contraseñas que recordar</li>
            <li>✅ Resistente a phishing</li>
            <li>✅ Autenticación en segundos</li>
            <li>✅ Estándar FIDO2/WebAuthn</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default EnrollPasskey;