import React, { useEffect, useRef, useState } from 'react';
import { errorMessage, setReauthHandler } from '../services/api';
import { reauthenticate } from '../services/webauthn';
import '../styles/Security_v2.css';

const REASONS = {
  sensitive_operation: 'Esta operación es sensible y requiere confirmar tu identidad.',
  country_changed: 'Detectamos que tu sesión cambió de ubicación.',
  policy_stepup: 'La reevaluación periódica de tu sesión detectó condiciones de riesgo.'
};

/**
 * Diálogo de re-autenticación. Lo dispara el cliente HTTP cuando el backend responde
 * 403 reauth_required; al confirmar con la passkey, la operación original se reintenta sola.
 */
function ReauthPrompt() {
  const [request, setRequest] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const pending = useRef(null);

  useEffect(() => {
    setReauthHandler((detail) => new Promise((resolve, reject) => {
      pending.current = { resolve, reject };
      setError('');
      setRequest(detail);
    }));
    return () => setReauthHandler(null);
  }, []);

  if (!request) return null;

  const close = () => setRequest(null);

  const confirm = async () => {
    setBusy(true);
    setError('');
    try {
      await reauthenticate();
      pending.current?.resolve();
      close();
    } catch (e) {
      setError(errorMessage(e, 'No se pudo verificar la passkey'));
    } finally {
      setBusy(false);
    }
  };

  const cancel = () => {
    pending.current?.reject(new Error('Operación cancelada: no se confirmó la identidad'));
    close();
  };

  return (
    <div className="reauth-overlay" role="dialog" aria-modal="true" aria-labelledby="reauth-title">
      <div className="reauth-dialog">
        <h3 id="reauth-title">Confirmá tu identidad</h3>
        <p>{REASONS[request.reason] || request.message}</p>
        <p className="au-hint">Vas a usar tu passkey (huella, rostro o PIN del dispositivo).</p>
        {error && <div className="message error">{error}</div>}
        <div className="au-actions">
          <button className="btn-primary" onClick={confirm} disabled={busy}>
            {busy ? 'Verificando...' : 'Confirmar con Passkey'}
          </button>
          <button className="btn-secondary" onClick={cancel} disabled={busy}>Cancelar</button>
        </div>
      </div>
    </div>
  );
}

export default ReauthPrompt;
