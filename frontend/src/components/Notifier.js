import React, { createContext, useCallback, useContext, useRef, useState } from 'react';
import '../styles/Security_v2.css';

/**
 * Avisos y confirmaciones dentro de la aplicación (reemplazan a alert/confirm del navegador).
 *
 *   const { notify, confirm } = useNotifier();
 *   notify('Passkey revocada', 'success');
 *   if (await confirm({ title: '¿Revocar?', message: '...', confirmLabel: 'Revocar', danger: true })) { ... }
 */
const NotifierContext = createContext({
  notify: () => {},
  confirm: async () => false
});

export const useNotifier = () => useContext(NotifierContext);

const ICONS = { success: '', error: '', info: '' };

export function NotifierProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const [dialog, setDialog] = useState(null);
  const nextId = useRef(1);

  const dismiss = useCallback((id) => setToasts((list) => list.filter((t) => t.id !== id)), []);

  const notify = useCallback((text, type = 'info') => {
    const id = nextId.current++;
    setToasts((list) => [...list.slice(-3), { id, text, type }]);
    setTimeout(() => dismiss(id), type === 'error' ? 7000 : 4000);
  }, [dismiss]);

  const confirm = useCallback((options) => new Promise((resolve) => {
    setDialog({ ...options, resolve });
  }), []);

  const answer = (value) => {
    dialog?.resolve(value);
    setDialog(null);
  };

  return (
    <NotifierContext.Provider value={{ notify, confirm }}>
      {children}

      <div className="toast-stack" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.type}`}>
            <span className="toast-icon">{ICONS[t.type] || ICONS.info}</span>
            <span className="toast-text">{t.text}</span>
            <button className="toast-close" onClick={() => dismiss(t.id)} aria-label="Cerrar">×</button>
          </div>
        ))}
      </div>

      {dialog && (
        <div className="reauth-overlay" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
          <div className="reauth-dialog">
            <h3 id="confirm-title">{dialog.title || 'Confirmar'}</h3>
            {dialog.message && <p>{dialog.message}</p>}
            <div className="au-actions">
              <button
                className={dialog.danger ? 'btn-danger' : 'btn-primary'}
                onClick={() => answer(true)}
                autoFocus
              >
                {dialog.confirmLabel || 'Aceptar'}
              </button>
              <button className="btn-secondary" onClick={() => answer(false)}>Cancelar</button>
            </div>
          </div>
        </div>
      )}
    </NotifierContext.Provider>
  );
}
