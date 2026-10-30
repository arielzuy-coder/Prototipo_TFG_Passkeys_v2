import React, { useEffect, useState } from 'react';
import api from '../services/api';
import { SUS_ITEMS } from './SusSurvey';

const fmt = (n) => (n === null || n === undefined ? '–' : Number(n).toLocaleString('es-AR', { maximumFractionDigits: 1 }));

/** Resultados del SUS para auditor y administrador (RNF-U2: meta ≥ 70). */
function SusResults() {
  const [data, setData] = useState(null);
  const [copied, setCopied] = useState(false);
  const surveyUrl = `${window.location.origin}/sus`;

  useEffect(() => {
    api.get('/api/audit/sus').then(({ data: d }) => setData(d)).catch(() => setData(null));
  }, []);

  const copy = () => navigator.clipboard?.writeText(surveyUrl).then(() => {
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, () => {});

  return (
    <div className="integrity-section sus-results">
      <div className="integrity-head">
        <div>
          <h3>Usabilidad (SUS)</h3>
          <p className="integrity-help">
            Encuesta anónima de 10 preguntas para quienes prueban el sistema. Meta de la tesis: 70/100 o más.
          </p>
        </div>
        <button className="btn-secondary" onClick={copy}>{copied ? 'Link copiado' : 'Copiar link de la encuesta'}</button>
      </div>

      {data && data.count === 0 && (
        <p className="integrity-help sus-empty">
          Todavía no hay respuestas. Compartí el link <code>{surveyUrl}</code> con quienes prueben el sistema.
        </p>
      )}

      {data && data.count > 0 && (
        <>
          <div className="sus-summary">
            <div className={`sus-big ${data.meets_target ? 'ok' : 'low'}`}>
              <span className="sus-big-number">{fmt(data.mean)}</span>
              <span className="sus-big-label">
                promedio de {data.count} {data.count === 1 ? 'respuesta' : 'respuestas'} ·{' '}
                {data.meets_target ? 'cumple la meta de 70' : 'debajo de la meta de 70'}
              </span>
            </div>
            <dl className="sus-stats">
              <div><dt>Mediana</dt><dd>{fmt(data.median)}</dd></div>
              <div><dt>Desvío</dt><dd>{fmt(data.stdev)}</dd></div>
              <div><dt>Mínimo</dt><dd>{fmt(data.min)}</dd></div>
              <div><dt>Máximo</dt><dd>{fmt(data.max)}</dd></div>
            </dl>
          </div>

          <table className="audit-table sus-items-table">
            <thead><tr><th>Pregunta</th><th>Promedio (1 a 5)</th><th>Lo deseable</th></tr></thead>
            <tbody>
              {SUS_ITEMS.map((text, i) => (
                <tr key={i}><td>{i + 1}. {text}</td><td>{fmt(data.item_means[i])}</td><td>{i % 2 === 0 ? 'Alto' : 'Bajo'}</td></tr>
              ))}
            </tbody>
          </table>

          {data.responses.some((r) => r.comment) && (
            <div className="sus-comments">
              <h4>Comentarios</h4>
              <ul>
                {data.responses.filter((r) => r.comment).map((r, i) => (
                  <li key={i}>“{r.comment}” <span>({fmt(r.score)}{r.profile ? `, ${r.profile}` : ''})</span></li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default SusResults;
