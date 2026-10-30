import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, NavLink } from 'react-router-dom';
import './App.css';
import './styles/Dashboard_styles.css';
import './styles/RiskMonitor_styles.css';
import EnrollPasskey from './components/EnrollPasskey';
import LoginPasswordless from './components/LoginPasswordless';
import Dashboard from './components/Dashboard';
import AdminPanel from './components/AdminPanel';
import RiskMonitor from './components/RiskMonitor';
import AuditReports from './components/AuditReports';
import ReauthPrompt from './components/ReauthPrompt';
import { NotifierProvider } from './components/Notifier';
import SusSurvey from './components/SusSurvey';
import api, { clearSession, saveSession } from './services/api';

const ROLE_LABELS = { admin: 'Administrador', auditor: 'Auditor', user: 'Usuario' };

const hasRole = (user, ...roles) => !!user && roles.includes(user.role);

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const storedUser = localStorage.getItem('user');
    const storedToken = localStorage.getItem('access_token');
    
    if (storedUser && storedToken) {
      setUser(JSON.parse(storedUser));
    }
    
    setLoading(false);
  }, []);

  const handleLogin = (userData, tokens) => {
    saveSession(userData, tokens);
    setUser(userData);
  };

  const handleLogout = async () => {
    try {
      await api.post('/auth/logout');  // revoca la sesión en el servidor
    } catch (e) {
      // aunque falle, se limpia la sesión local
    }
    clearSession();
    setUser(null);
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
        <p>Cargando...</p>
      </div>
    );
  }

  return (
    <NotifierProvider>
    <Router>
      <div className="App">
        {user && <ReauthPrompt />}
        <header className="app-header">
          <div className="topbar">
            <NavLink to={user ? '/dashboard' : '/login'} className="brand" aria-label="Inicio">
              <svg className="brand-mark" viewBox="0 0 32 32" aria-hidden="true">
                <path d="M16 2.5 4.5 7v8.2c0 7 4.9 12.6 11.5 14.3 6.6-1.7 11.5-7.3 11.5-14.3V7L16 2.5Z" fill="currentColor" opacity=".16"/>
                <path d="M16 2.5 4.5 7v8.2c0 7 4.9 12.6 11.5 14.3 6.6-1.7 11.5-7.3 11.5-14.3V7L16 2.5Z" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round"/>
                <circle cx="16" cy="13.5" r="3.4" fill="none" stroke="currentColor" strokeWidth="1.8"/>
                <path d="M16 16.9v6.1M16 20.3h2.6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
              </svg>
              <span className="brand-text">
                <span className="brand-name">Acceso corporativo</span>
                <span className="brand-sub">Passkeys y Zero Trust</span>
              </span>
            </NavLink>

            {user && (
              <nav className="topnav" aria-label="Secciones">
                <NavLink to="/dashboard">Mi cuenta</NavLink>
                {hasRole(user, 'admin') && <NavLink to="/admin">Panel Admin</NavLink>}
                {hasRole(user, 'admin', 'auditor') && <NavLink to="/risk">Riesgo</NavLink>}
                {hasRole(user, 'admin', 'auditor') && <NavLink to="/audit">Auditoría</NavLink>}
              </nav>
            )}

            {user && (
              <div className="topbar-user">
                <span className="topbar-who">
                  <span className="topbar-name">{user.display_name || user.email}</span>
                  <span className={`role-chip role-${user.role}`}>{ROLE_LABELS[user.role] || user.role}</span>
                </span>
                <button type="button" className="topbar-logout" onClick={handleLogout}>Cerrar sesión</button>
              </div>
            )}
          </div>
        </header>

        <main className="app-main">
          <Routes>
            <Route 
              path="/enroll" 
              element={<EnrollPasskey user={user} />} 
            />
            
            <Route 
              path="/login" 
              element={
                user ? 
                  <Navigate to="/dashboard" replace /> : 
                  <LoginPasswordless onLogin={handleLogin} />
              } 
            />
            
            <Route 
              path="/dashboard" 
              element={
                user ? 
                  <Dashboard user={user} /> : 
                  <Navigate to="/login" replace />
              } 
            />
            
            <Route 
              path="/admin" 
              element={
                hasRole(user, 'admin') ?
                  <AdminPanel user={user} /> :
                  <Navigate to={user ? '/dashboard' : '/login'} replace />
              } 
            />

            <Route 
              path="/risk" 
              element={
                hasRole(user, 'admin', 'auditor') ?
                  <RiskMonitor user={user} /> :
                  <Navigate to={user ? '/dashboard' : '/login'} replace />
              } 
            />

            <Route
              path="/audit"
              element={
                hasRole(user, 'admin', 'auditor') ?
                  <div className="admin-panel"><AuditReports /></div> :
                  <Navigate to={user ? '/dashboard' : '/login'} replace />
              }
            />
            
            <Route path="/sus" element={<SusSurvey />} />

            <Route 
              path="/" 
              element={<Navigate to={user ? "/dashboard" : "/login"} replace />} 
            />
          </Routes>
        </main>

        <footer className="app-footer">
          <p>Trabajo Final de Grado, Licenciatura en Seguridad Informática, Universidad Siglo 21</p>
          <p>Ariel Hernán Zuy, legajo VLSI002384</p>
        </footer>
      </div>
    </Router>
    </NotifierProvider>
  );
}

export default App;
