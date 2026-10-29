import axios from 'axios';

export const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000
});

// Claves de almacenamiento de la sesión
const KEYS = ['access_token', 'refresh_token', 'user'];

export const saveSession = (user, tokens) => {
  localStorage.setItem('user', JSON.stringify(user));
  localStorage.setItem('access_token', tokens.access_token);
  localStorage.setItem('refresh_token', tokens.refresh_token);
};

export const clearSession = () => KEYS.forEach((k) => localStorage.removeItem(k));

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Los endpoints de autenticación manejan sus propios 401 (credencial rechazada,
// step-up fallido): no deben disparar el refresh ni la redirección al login.
const isAuthEndpoint = (url = '') =>
  url.startsWith('/auth/') && !url.startsWith('/auth/me') && !url.startsWith('/auth/logout');

// Un solo refresh en curso aunque fallen varias requests a la vez
let refreshPromise = null;

// Re-autenticación (verificación continua / operaciones sensibles).
// La app registra un handler que muestra el aviso y pide la passkey; devuelve una promesa
// que se resuelve si el usuario confirmó su identidad.
let reauthHandler = null;
let reauthPromise = null;
export const setReauthHandler = (fn) => { reauthHandler = fn; };

const refreshTokens = async () => {
  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) throw new Error('sin refresh token');
  // Rotación obligatoria: el backend devuelve un refresh nuevo y el anterior queda inválido
  const { data } = await axios.post(`${API_URL}/auth/refresh`, { refresh_token: refreshToken });
  localStorage.setItem('access_token', data.access_token);
  localStorage.setItem('refresh_token', data.refresh_token);
  return data.access_token;
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config || {};
    const detail = error.response?.data?.detail;

    if (error.response?.status === 403 && detail?.code === 'reauth_required' && !original._reauth && reauthHandler) {
      original._reauth = true;
      try {
        reauthPromise = reauthPromise || reauthHandler(detail);
        await reauthPromise;
        return api(original);
      } catch (reauthError) {
        return Promise.reject(reauthError);
      } finally {
        reauthPromise = null;
      }
    }

    if (error.response?.status === 401 && !original._retry && !isAuthEndpoint(original.url)) {
      original._retry = true;
      try {
        refreshPromise = refreshPromise || refreshTokens();
        const accessToken = await refreshPromise;
        original.headers.Authorization = `Bearer ${accessToken}`;
        return api(original);
      } catch (refreshError) {
        clearSession();
        window.location.href = '/login';
        return Promise.reject(refreshError);
      } finally {
        refreshPromise = null;
      }
    }
    return Promise.reject(error);
  }
);

// Mensaje de error legible a partir de una respuesta de FastAPI
export const errorMessage = (error, fallback = 'Ocurrió un error') => {
  const detail = error?.response?.data?.detail;
  if (typeof detail === 'string') return detail;
  if (detail?.message) return detail.message;
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join(', ');
  return error?.message || fallback;
};

export default api;
