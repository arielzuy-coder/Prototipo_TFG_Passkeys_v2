import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import AuditReports from './AuditReports';

function AdminPanel() {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState({ type: '', text: '' });
  const [showForm, setShowForm] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState(null);
  const [activeTab, setActiveTab] = useState('policies'); // Estado para tabs
  const navigate = useNavigate();

  // Formulario
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    min_risk_score: '',
    max_risk_score: '',
    customConditions: '', // NUEVO: Para condiciones JSON personalizadas
    action: 'allow',
    priority: 1,
    enabled: true
  });

  useEffect(() => {
    loadPolicies();
  }, []);

  const loadPolicies = async () => {
    try {
      setLoading(true);
      const { data } = await api.get('/admin/policies');
      setPolicies(data.policies);
    } catch (error) {
      console.error('Error loading policies:', error);
      setMessage({ type: 'error', text: 'Error al cargar políticas' });
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = () => {
    setEditingPolicy(null);
    setFormData({
      name: '',
      description: '',
      min_risk_score: '',
      max_risk_score: '',
      customConditions: '', // NUEVO
      action: 'allow',
      priority: policies.length + 1,
      enabled: true
    });
    setShowForm(true);
    setMessage({ type: '', text: '' });
  };

  const handleEdit = (policy) => {
    setEditingPolicy(policy);
    
    // Extraer condiciones conocidas
    const { min_risk_score, max_risk_score, ...otherConditions } = policy.conditions || {};
    
    // Si hay condiciones adicionales, convertirlas a JSON
    const customConditionsStr = Object.keys(otherConditions).length > 0 
      ? JSON.stringify(otherConditions, null, 2) 
      : '';
    
    setFormData({
      name: policy.name,
      description: policy.description,
      min_risk_score: min_risk_score || '',
      max_risk_score: max_risk_score || '',
      customConditions: customConditionsStr, // NUEVO
      action: policy.action,
      priority: policy.priority,
      enabled: policy.enabled
    });
    setShowForm(true);
    setMessage({ type: '', text: '' });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const conditions = {};
      
      // Agregar risk scores si están presentes
      if (formData.min_risk_score !== '') {
        conditions.min_risk_score = parseInt(formData.min_risk_score);
      }
      if (formData.max_risk_score !== '') {
        conditions.max_risk_score = parseInt(formData.max_risk_score);
      }

      // NUEVO: Parsear y merge condiciones personalizadas
      if (formData.customConditions && formData.customConditions.trim() !== '') {
        try {
          const customConds = JSON.parse(formData.customConditions);
          Object.assign(conditions, customConds);
        } catch (jsonError) {
          setMessage({ 
            type: 'error', 
            text: 'Error en formato JSON de condiciones personalizadas: ' + jsonError.message 
          });
          setLoading(false);
          return;
        }
      }

      const payload = {
        name: formData.name,
        description: formData.description,
        conditions: conditions,
        action: formData.action,
        priority: parseInt(formData.priority),
        enabled: formData.enabled
      };

      if (editingPolicy) {
        // Update
        await api.put(`/admin/policies/${editingPolicy.id}`, payload);
        setMessage({ type: 'success', text: 'Política actualizada exitosamente' });
      } else {
        // Create
        await api.post('/admin/policies', payload);
        setMessage({ type: 'success', text: 'Política creada exitosamente' });
      }

      setShowForm(false);
      loadPolicies();
    } catch (error) {
      console.error('Error saving policy:', error);
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || 'Error al guardar política' 
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (policy) => {
    if (!window.confirm(`¿Eliminar la política "${policy.name}"?`)) {
      return;
    }

    try {
      await api.delete(`/admin/policies/${policy.id}`);
      setMessage({ type: 'success', text: 'Política eliminada exitosamente' });
      loadPolicies();
    } catch (error) {
      console.error('Error deleting policy:', error);
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || 'Error al eliminar política' 
      });
    }
  };

  const handleToggle = async (policy) => {
    try {
      await api.put(`/admin/policies/${policy.id}/toggle`);
      setMessage({ 
        type: 'success', 
        text: `Política ${policy.enabled ? 'desactivada' : 'activada'} exitosamente` 
      });
      loadPolicies();
    } catch (error) {
      console.error('Error toggling policy:', error);
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || 'Error al cambiar estado' 
      });
    }
  };

  const getActionBadge = (action) => {
    const badges = {
      allow: { class: 'badge-success', text: '✓ Permitir' },
      stepup: { class: 'badge-warning', text: '⚠ Step-up' },
      deny: { class: 'badge-danger', text: '✗ Denegar' }
    };
    return badges[action] || badges.allow;
  };

  if (showForm) {
    return (
      <div className="admin-container">
        <div className="admin-card">
          <div className="admin-header">
            <h2>{editingPolicy ? '✏️ Editar Política' : '➕ Nueva Política'}</h2>
            <button 
              className="btn-secondary" 
              onClick={() => setShowForm(false)}
            >
              ← Volver
            </button>
          </div>

          {message.text && (
            <div className={`message ${message.type}`}>
              {message.text}
            </div>
          )}

          <form onSubmit={handleSubmit} className="policy-form">
            <div className="form-group">
              <label>Nombre de la política *</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({...formData, name: e.target.value})}
                placeholder="ej: nueva_politica_riesgo_medio"
                required
                disabled={loading}
              />
            </div>

            <div className="form-group">
              <label>Descripción *</label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData({...formData, description: e.target.value})}
                placeholder="Describe cuándo se aplica esta política"
                rows="3"
                required
                disabled={loading}
              />
            </div>

            <div className="form-group">
              <label>Condiciones personalizadas (JSON)</label>
              <textarea
                value={formData.customConditions}
                onChange={(e) => setFormData({...formData, customConditions: e.target.value})}
                placeholder='Ejemplo: {"allowed_countries": ["AR", "BR"]}'
                rows="4"
                disabled={loading}
                style={{ fontFamily: 'monospace', fontSize: '13px' }}
              />
              <small style={{ display: 'block', marginTop: '5px', color: '#666' }}>
                Opcional: Ingresa condiciones adicionales en formato JSON válido.
                <br />
                Ejemplos:
                <br />
                • <code>{`{"allowed_countries": ["AR"]}`}</code> - Solo Argentina
                <br />
                • <code>{`{"blocked_countries": ["CN", "RU"]}`}</code> - Bloquear países
              </small>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Riesgo mínimo</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={formData.min_risk_score}
                  onChange={(e) => setFormData({...formData, min_risk_score: e.target.value})}
                  placeholder="0-100"
                  disabled={loading}
                />
              </div>

              <div className="form-group">
                <label>Riesgo máximo</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={formData.max_risk_score}
                  onChange={(e) => setFormData({...formData, max_risk_score: e.target.value})}
                  placeholder="0-100"
                  disabled={loading}
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Acción *</label>
                <select
                  value={formData.action}
                  onChange={(e) => setFormData({...formData, action: e.target.value})}
                  required
                  disabled={loading}
                >
                  <option value="allow">✓ Permitir acceso</option>
                  <option value="stepup">⚠ Requerir step-up</option>
                  <option value="deny">✗ Denegar acceso</option>
                </select>
              </div>

              <div className="form-group">
                <label>Prioridad *</label>
                <input
                  type="number"
                  min="1"
                  value={formData.priority}
                  onChange={(e) => setFormData({...formData, priority: e.target.value})}
                  required
                  disabled={loading}
                />
                <small>Mayor prioridad = número menor</small>
              </div>
            </div>

            <div className="form-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={formData.enabled}
                  onChange={(e) => setFormData({...formData, enabled: e.target.checked})}
                  disabled={loading}
                />
                <span>Política activa</span>
              </label>
            </div>

            <div className="form-actions">
              <button 
                type="submit" 
                className="btn-primary"
                disabled={loading}
              >
                {loading ? 'Guardando...' : (editingPolicy ? 'Actualizar' : 'Crear Política')}
              </button>
              <button 
                type="button" 
                className="btn-secondary"
                onClick={() => setShowForm(false)}
                disabled={loading}
              >
                Cancelar
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="admin-container">
      <div className="admin-card">
        {/* Header Principal */}
        <div className="admin-header">
          <div>
            <h2>⚙️ Panel de Administración</h2>
            <p className="subtitle">Gestión de políticas de acceso y seguridad</p>
          </div>
        </div>

        {/* Tabs de navegación */}
        <div className="admin-tabs">
          <button 
            className={`tab-button ${activeTab === 'policies' ? 'active' : ''}`}
            onClick={() => setActiveTab('policies')}
          >
            <span>🔒</span> Políticas de Acceso
          </button>
          <button 
            className={`tab-button ${activeTab === 'audit' ? 'active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            <span>📊</span> Auditoría y Reportes
          </button>
        </div>

        {/* Contenido según tab activo */}
        {activeTab === 'policies' ? (
          // Tab de Políticas de Acceso
          <div className="policies-content">
            <div className="policies-header">
              <div className="header-title">
                <span className="icon">🔒</span>
                <div>
                  <h2>Políticas de Acceso</h2>
                  <p className="subtitle">Gestión de políticas de acceso y seguridad</p>
                </div>
              </div>
              <button 
                className="btn-primary" 
                onClick={handleCreate}
              >
                ➕ Nueva Política
              </button>
            </div>

            {message.text && (
              <div className={`message ${message.type}`}>
                {message.text}
              </div>
            )}

            {loading ? (
              <div className="loading-container">
                <div className="spinner"></div>
                <p>Cargando políticas...</p>
              </div>
            ) : (
              <>
                <div className="policies-stats">
                  <div className="stat-card">
                    <span className="stat-number">{policies.length}</span>
                    <span className="stat-label">Políticas totales</span>
                  </div>
                  <div className="stat-card">
                    <span className="stat-number">
                      {policies.filter(p => p.enabled).length}
                    </span>
                    <span className="stat-label">Activas</span>
                  </div>
                  <div className="stat-card">
                    <span className="stat-number">
                      {policies.filter(p => !p.enabled).length}
                    </span>
                    <span className="stat-label">Inactivas</span>
                  </div>
                </div>

                <div className="policies-table-container">
                  <table className="policies-table">
                    <thead>
                      <tr>
                        <th>Estado</th>
                        <th>Nombre</th>
                        <th>Descripción</th>
                        <th>Condiciones</th>
                        <th>Acción</th>
                        <th>Prioridad</th>
                        <th>Acciones</th>
                      </tr>
                    </thead>
                    <tbody>
                      {policies.map(policy => (
                        <tr key={policy.id} className={!policy.enabled ? 'disabled-row' : ''}>
                          <td>
                            <button
                              className={`toggle-btn ${policy.enabled ? 'active' : 'inactive'}`}
                              onClick={() => handleToggle(policy)}
                              title={policy.enabled ? 'Desactivar' : 'Activar'}
                            >
                              {policy.enabled ? '●' : '○'}
                            </button>
                          </td>
                          <td className="policy-name">{policy.name}</td>
                          <td className="policy-description">{policy.description}</td>
                          <td className="policy-conditions">
                            {policy.conditions.min_risk_score !== undefined && (
                              <span>Min: {policy.conditions.min_risk_score} </span>
                            )}
                            {policy.conditions.max_risk_score !== undefined && (
                              <span>Max: {policy.conditions.max_risk_score} </span>
                            )}
                            {policy.conditions.allowed_countries && (
                              <span title="Países permitidos">
                                🌍 {policy.conditions.allowed_countries.join(', ')} 
                              </span>
                            )}
                            {policy.conditions.blocked_countries && (
                              <span title="Países bloqueados">
                                🚫 {policy.conditions.blocked_countries.join(', ')} 
                              </span>
                            )}
                          </td>
                          <td>
                            <span className={`badge ${getActionBadge(policy.action).class}`}>
                              {getActionBadge(policy.action).text}
                            </span>
                          </td>
                          <td className="policy-priority">{policy.priority}</td>
                          <td className="policy-actions">
                            <button
                              className="btn-icon btn-edit"
                              onClick={() => handleEdit(policy)}
                              title="Editar"
                            >
                              ✏️
                            </button>
                            <button
                              className="btn-icon btn-delete"
                              onClick={() => handleDelete(policy)}
                              title="Eliminar"
                            >
                              🗑️
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {policies.length === 0 && (
                  <div className="empty-state">
                    <p>No hay políticas configuradas</p>
                    <button className="btn-primary" onClick={handleCreate}>
                      Crear primera política
                    </button>
                  </div>
                )}
              </>
            )}

            <div className="admin-footer">
              <button 
                className="btn-secondary" 
                onClick={() => navigate('/dashboard')}
              >
                ← Volver al Dashboard
              </button>
            </div>
          </div>
        ) : (
          // Tab de Auditoría y Reportes
          <AuditReports />
        )}
      </div>
    </div>
  );
}

export default AdminPanel;
