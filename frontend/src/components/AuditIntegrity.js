import React, { useState } from 'react';
import api, { errorMessage } from '../services/api';

const ANCHOR_KEY = 'audit_anchor';

const readAnchor = () => {
  try { return JSON.parse(localStorage.getItem(ANCHOR_KEY)); } catch (e) { return null; }
};
const saveAnchor = (anchor) => {
  try { localStorage.setItem(ANCHOR_KEY, JSON.stringify(anchor)); } catch (e) { /* sin almacenamiento */ }
};

const fmt = (iso) => (iso ? new Date(iso).toLocaleString('es-AR', {
  day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
}) : '');
const eventos = (n) => (n === 1 ? '1 evento anterior está íntegro' : `${n} eventos anteriores están íntegros`);

/**
 * RNF-S4: verifica la cadena de sellos del registro de auditoría.
 * El ancla (último n.º y sello) se recuerda en este navegador para detectar
 * también eventos borrados al final de la cadena.
 */
function AuditIntegrity() {
  const [result, setResult] = useState(null);
  const [previous, setPrevious] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const run = async () => {
    setBusy(true);
    setError('');
    const before = readAnchor();
    try {
      const { data } = await api.get('/api/audit/integrity');
      setPrevious(before);
      setResult(data);
      if (data.intact && data.anchor) saveAnchor({ ...data.anchor, at: data.verified_at });
    } catch (e) {
      setError(errorMessage(e, 'No se pudo verificar el registro'));
    } finally {
      setBusy(false);
    }
  };

  const truncated = result?.intact && previous && result.anchor && previous.seq > result.anchor.seq;

  return (
    <div className="integrity-section">
      <div className="integrity-head">
        <div>
          <h3>Integridad del registro</h3>
          <p className="integrity-help">
            Cada evento queda sellado junto con el anterior (HMAC-SHA256). Si alguien modifica o borra
            un registro directamente en la base, la cadena deja de cerrar en ese punto.
          </p>
        </div>
        <button className="btn-primary" onClick={run} disabled={busy}>
          {busy ? 'Verificando...' : 'Verificar integridad'}
        </button>
      </div>

      {error && <div className="message error">{error}</div>}

      {result && !result.intact && result.broken_at && (
        <div className="integrity-result broken">
          <p className="integrity-title">Registro alterado en el evento n.º {result.broken_at.seq}</p>
          <p>{result.broken_at.reason}.</p>
          <p className="integrity-meta">
            Evento {result.broken_at.event_type} del {fmt(result.broken_at.timestamp)}.{' '}
            {result.checked === 0 ? 'Es el primer evento de la cadena.' : `${eventos(result.checked).replace(/^./, (c) => c.toUpperCase())}.`}
          </p>
        </div>
      )}

      {result && !result.intact && !result.broken_at && (
        <div className="integrity-result broken">
          <p className="integrity-title">Hay {result.unsealed} eventos sin sellar</p>
          <p>Se registraron por fuera de la aplicación. Los {result.checked} eventos sellados están íntegros.</p>
        </div>
      )}

      {truncated && (
        <div className="integrity-result broken">
          <p className="integrity-title">Faltan eventos al final del registro</p>
          <p>
            La verificación anterior en este navegador llegaba al evento n.º {previous.seq} ({fmt(previous.at)});
            ahora la cadena termina en el n.º {result.anchor.seq}.
          </p>
        </div>
      )}

      {result && result.intact && !truncated && (
        <div className="integrity-result ok">
          <p className="integrity-title">Registro íntegro: {result.checked} eventos verificados</p>
          <p className="integrity-meta">
            Ancla: evento n.º {result.anchor.seq}, sello{' '}
            <code>{result.anchor.hash.slice(0, 16)}…</code> · {fmt(result.verified_at)}
          </p>
        </div>
      )}
    </div>
  );
}

export default AuditIntegrity;
