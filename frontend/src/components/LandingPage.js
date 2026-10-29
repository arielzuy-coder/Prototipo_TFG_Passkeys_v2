import React from 'react';
import { useNavigate } from 'react-router-dom';

function LandingPage() {
  const navigate = useNavigate();

  return (
    <div className="landing-container">
      <div className="landing-card">
        <div className="landing-hero">
          <h1>🔐 Bienvenido al Sistema de Autenticación Zero Trust</h1>
          <p className="hero-subtitle">
            Autenticación sin contraseñas utilizando Passkeys (FIDO2/WebAuthn)
          </p>
        </div>

        <div className="landing-features">
          <div className="feature-card">
            <span className="feature-icon">🔑</span>
            <h3>Passkeys</h3>
            <p>Autenticación biométrica segura sin contraseñas</p>
          </div>

          <div className="feature-card">
            <span className="feature-icon">🛡️</span>
            <h3>Zero Trust</h3>
            <p>Verificación continua basada en contexto</p>
          </div>

          <div className="feature-card">
            <span className="feature-icon">📊</span>
            <h3>Análisis de Riesgo</h3>
            <p>Evaluación en tiempo real de cada acceso</p>
          </div>

          <div className="feature-card">
            <span className="feature-icon">🔐</span>
            <h3>Step-Up Auth</h3>
            <p>Verificación adicional cuando se detectan anomalías</p>
          </div>
        </div>

        <div className="landing-actions">
          <button 
            className="btn-primary btn-large" 
            onClick={() => navigate('/login')}
          >
            🚀 Iniciar Sesión
          </button>
          
          <button 
            className="btn-secondary btn-large" 
            onClick={() => navigate('/enroll')}
          >
            ✨ Registrar Nueva Cuenta
          </button>
        </div>

        <div className="landing-info">
          <h3>🎓 Trabajo Final de Grado</h3>
          <p>Universidad Siglo 21 - Licenciatura en Ciberseguridad</p>
          <p><strong>Autor:</strong> Zuy, Ariel Hernán</p>
          <p className="note">
            Este prototipo implementa autenticación passwordless con evaluación 
            de riesgo contextual siguiendo los principios de Zero Trust Architecture.
          </p>
        </div>

        <div className="landing-tech">
          <h4>🛠️ Tecnologías Implementadas:</h4>
          <div className="tech-badges">
            <span className="tech-badge">WebAuthn / FIDO2</span>
            <span className="tech-badge">FastAPI</span>
            <span className="tech-badge">React</span>
            <span className="tech-badge">PostgreSQL</span>
            <span className="tech-badge">Docker</span>
          </div>
        </div>
      </div>

      <style jsx>{`
        .landing-container {
          min-height: 80vh;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 2rem;
        }

        .landing-card {
          max-width: 1000px;
          width: 100%;
          background: white;
          border-radius: 12px;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          padding: 3rem;
        }

        .landing-hero {
          text-align: center;
          margin-bottom: 3rem;
        }

        .landing-hero h1 {
          font-size: 2.5rem;
          color: #1a1a1a;
          margin-bottom: 1rem;
        }

        .hero-subtitle {
          font-size: 1.2rem;
          color: #666;
        }

        .landing-features {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
          gap: 1.5rem;
          margin-bottom: 3rem;
        }

        .feature-card {
          text-align: center;
          padding: 1.5rem;
          background: #f8f9fa;
          border-radius: 8px;
          transition: transform 0.2s;
        }

        .feature-card:hover {
          transform: translateY(-5px);
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        .feature-icon {
          font-size: 3rem;
          display: block;
          margin-bottom: 1rem;
        }

        .feature-card h3 {
          color: #333;
          margin-bottom: 0.5rem;
        }

        .feature-card p {
          color: #666;
          font-size: 0.9rem;
        }

        .landing-actions {
          display: flex;
          gap: 1rem;
          justify-content: center;
          margin-bottom: 3rem;
          flex-wrap: wrap;
        }

        .btn-large {
          padding: 1rem 2rem;
          font-size: 1.1rem;
          border-radius: 8px;
          border: none;
          cursor: pointer;
          font-weight: 600;
          transition: all 0.2s;
        }

        .btn-primary {
          background: #5865f2;
          color: white;
        }

        .btn-primary:hover {
          background: #4752c4;
          transform: translateY(-2px);
        }

        .btn-secondary {
          background: white;
          color: #5865f2;
          border: 2px solid #5865f2;
        }

        .btn-secondary:hover {
          background: #f0f1ff;
          transform: translateY(-2px);
        }

        .landing-info {
          background: #f0f9ff;
          padding: 2rem;
          border-radius: 8px;
          text-align: center;
          margin-bottom: 2rem;
        }

        .landing-info h3 {
          color: #0369a1;
          margin-bottom: 1rem;
        }

        .landing-info p {
          color: #333;
          margin-bottom: 0.5rem;
        }

        .note {
          font-size: 0.9rem;
          color: #666;
          font-style: italic;
          margin-top: 1rem;
        }

        .landing-tech {
          text-align: center;
        }

        .landing-tech h4 {
          color: #333;
          margin-bottom: 1rem;
        }

        .tech-badges {
          display: flex;
          gap: 0.5rem;
          flex-wrap: wrap;
          justify-content: center;
        }

        .tech-badge {
          background: #e0e7ff;
          color: #4338ca;
          padding: 0.5rem 1rem;
          border-radius: 20px;
          font-size: 0.9rem;
          font-weight: 500;
        }

        @media (max-width: 768px) {
          .landing-card {
            padding: 1.5rem;
          }

          .landing-hero h1 {
            font-size: 1.8rem;
          }

          .landing-features {
            grid-template-columns: 1fr;
          }

          .landing-actions {
            flex-direction: column;
          }

          .btn-large {
            width: 100%;
          }
        }
      `}</style>
    </div>
  );
}

export default LandingPage;
