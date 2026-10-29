import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';
import './styles/Dashboard_styles.css';
import './styles/RiskMonitor_styles.css';
import EnrollPasskey from './components/EnrollPasskey';
import LoginPasswordless from './components/LoginPasswordless';
import Dashboard from './components/Dashboard';
import AdminPanel from './components/AdminPanel';
import RiskMonitor from './components/RiskMonitor';
import AuditReports from './components/AuditReports';
import api, { clearSession, saveSession } from './services/api';

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
    <Router>
      <div className="App">
        <header className="app-header">
          <h1>🔐 Prototipo Autenticación Passkeys + Zero Trust</h1>
          <p className="subtitle">TFG - Universidad Siglo 21 | Zuy, Ariel Hernán</p>
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
                  <Dashboard user={user} onLogout={handleLogout} /> : 
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
            
            <Route 
              path="/" 
              element={<Navigate to={user ? "/dashboard" : "/login"} replace />} 
            />
          </Routes>
        </main>

        <footer className="app-footer">
          <p>© 2025 Zuy, Ariel Hernán | Legajo: VLSI002384</p>
          <p>Licenciatura en Seguridad Informática | Universidad Siglo 21</p>
        </footer>
      </div>
    </Router>
  );
}

export default App;
