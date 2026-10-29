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
    setUser(userData);
    localStorage.setItem('user', JSON.stringify(userData));
    localStorage.setItem('access_token', tokens.access_token);
    localStorage.setItem('refresh_token', tokens.refresh_token);
  };

  const handleLogout = () => {
    setUser(null);
    localStorage.removeItem('user');
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
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
              element={<EnrollPasskey />} 
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
                user ? 
                  <AdminPanel /> : 
                  <Navigate to="/login" replace />
              } 
            />

            <Route 
              path="/risk" 
              element={
                user ? 
                  <RiskMonitor user={user} /> : 
                  <Navigate to="/login" replace />
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
