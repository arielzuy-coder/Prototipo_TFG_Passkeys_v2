import React, { useState } from 'react';
import api, { errorMessage } from '../services/api';

// System Usability Scale (Brooke, 1996), versión en español
export const SUS_ITEMS = [
  'Creo que me gustaría usar este sistema con frecuencia.',
  'Encontré el sistema innecesariamente complejo.',
  'Pensé que el sistema era fácil de usar.',
  'Creo que necesitaría la ayuda de una persona técnica para poder usar este sistema.',
  'Encontré que las distintas funciones del sistema estaban bien integradas.',
  'Pensé que había demasiada inconsistencia en este sistema.',
  'Imagino que la mayoría de las personas aprendería a usar este sistema muy rápido.',
  'Encontré el sistema muy engorroso de usar.',
  'Me sentí muy seguro/a usando el sistema.',
  'Necesité aprender muchas cosas antes de poder empezar a usar este sistema.'
];

const SCALE = [1, 2, 3, 4, 5];

/** Encuesta SUS anónima (RNF-U2). No requiere sesión. */
function SusSurvey() {
  const [answers, setAnswers] = useState(Array(10).fill(null));
  const [profile, setProfile] = useState('');
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [score, setScore] = useState(null);

  const pending = answers.filter((a) => a === null).length;

  const choose = (item, value) => setAnswers((list) => list.map((a, i) => (i === item ? value : a)));

  const submit = async (e) => {
    e.preventDefault();
    if (pending) return;
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post('/sus', { answers, profile: profile || null, comment: comment || null });
      setScore(data.score);
    } catch (err) {
      setError(errorMessage(err, 'No se pudo enviar la encuesta'));
    } finally {
      setBusy(false);
    }
  };

  if (score !== null) {
    return (
      <div className="sus-container">
        <div className="sus-card">
          <h2>Gracias por responder</h2>
          <p className="sus-intro">Tu respuesta quedó registrada de forma anónima.</p>
          <p className="sus-score">Tu puntaje SUS: <strong>{score.toLocaleString('es-AR')}</strong> / 100</p>
        </div>
      </div>
    );
  }

  return (
    <div className="sus-container">
      <form className="sus-card" onSubmit={submit}>
        <h2>Encuesta de usabilidad</h2>
        <p className="sus-intro">
          Después de probar el sistema, indicá cuánto estás de acuerdo con cada frase.
          Respondé con tu primera impresión. Es anónima y lleva unos dos minutos.
        </p>

        <div className="sus-legend" aria-hidden="true">
          <span>1 = Totalmente en desacuerdo</span>
          <span>5 = Totalmente de acuerdo</span>
        </div>

        <ol className="sus-items">
          {SUS_ITEMS.map((text, i) => (
            <li key={i} className={`sus-item ${answers[i] !== null ? 'done' : ''}`}>
              <fieldset>
                <legend>{text}</legend>
                <div className="sus-scale">
                  {SCALE.map((v) => (
                    <label key={v} className={answers[i] === v ? 'checked' : ''}>
                      <input
                        type="radio"
                        name={`q${i}`}
                        value={v}
                        checked={answers[i] === v}
                        onChange={() => choose(i, v)}
                      />
                      <span>{v}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
            </li>
          ))}
        </ol>

        <div className="sus-extra">
          <div className="form-group">
            <label htmlFor="sus-profile">¿Con qué perfil probaste el sistema? (opcional)</label>
            <select id="sus-profile" value={profile} onChange={(e) => setProfile(e.target.value)}>
              <option value="">Prefiero no decirlo</option>
              <option value="usuario">Usuario</option>
              <option value="auditor">Auditor</option>
              <option value="administrador">Administrador</option>
              <option value="otro">Otro</option>
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="sus-comment">Comentario (opcional)</label>
            <textarea id="sus-comment" rows="3" maxLength="500" value={comment}
                      onChange={(e) => setComment(e.target.value)} />
          </div>
        </div>

        {error && <div className="message error">{error}</div>}

        <button type="submit" className="btn-primary" disabled={busy || pending > 0}>
          {busy ? 'Enviando...' : pending > 0 ? `Faltan ${pending} respuestas` : 'Enviar respuestas'}
        </button>
      </form>
    </div>
  );
}

export default SusSurvey;
