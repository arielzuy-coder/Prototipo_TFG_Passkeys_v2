import api from './api';

export const enrollPasskey = async (email, deviceName) => {
  try {
    const { data: options } = await api.post('/auth/register/begin', { email });
    
    const { startRegistration } = await import('@simplewebauthn/browser');
    
    const attResp = await startRegistration(options);
    
    const { data: result } = await api.post('/auth/register/complete', {
      email,
      credential: attResp,
      device_name: deviceName
    });
    
    return {
      success: true,
      data: result
    };
    
  } catch (error) {
    console.error('Error en enrollPasskey:', error);
    return {
      success: false,
      message: error.response?.data?.detail || error.message || 'Error al enrolar Passkey'
    };
  }
};

export const authenticateWithPasskey = async (email) => {
  try {
    const { data: options } = await api.post('/auth/login/begin', { email });
    
    const { startAuthentication } = await import('@simplewebauthn/browser');
    
    const asseResp = await startAuthentication(options);
    
    const { data: result } = await api.post('/auth/login/complete', {
      email,
      credential: asseResp
    });
    
    return {
      success: true,
      data: result
    };
    
  } catch (error) {
    console.error('Error en authenticateWithPasskey:', error);
    return {
      success: false,
      message: error.response?.data?.detail || error.message || 'Error al autenticar',
      riskAssessment: error.response?.data?.detail?.risk_assessment
    };
  }
};

export const listPasskeys = async (email) => {
  try {
    const { data } = await api.get(`/passkeys/${email}`);
    
    return {
      success: true,
      data: data.passkeys
    };
    
  } catch (error) {
    console.error('Error en listPasskeys:', error);
    return {
      success: false,
      message: error.response?.data?.detail || error.message || 'Error al listar Passkeys'
    };
  }
};

export const revokePasskey = async (passkeyId) => {
  try {
    await api.delete(`/passkeys/${passkeyId}`);
    
    return {
      success: true,
      message: 'Passkey revocada exitosamente'
    };
    
  } catch (error) {
    console.error('Error en revokePasskey:', error);
    return {
      success: false,
      message: error.response?.data?.detail || error.message || 'Error al revocar Passkey'
    };
  }
};

export const checkWebAuthnSupport = () => {
  if (!window.PublicKeyCredential) {
    return {
      supported: false,
      message: 'WebAuthn no está soportado en este navegador'
    };
  }
  
  return {
    supported: true,
    message: 'WebAuthn está soportado'
  };
};

export const checkPlatformAuthenticatorAvailable = async () => {
  try {
    const available = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    
    return {
      available,
      message: available 
        ? 'Autenticador de plataforma disponible (biometría/PIN)' 
        : 'No hay autenticador de plataforma disponible'
    };
    
  } catch (error) {
    return {
      available: false,
      message: 'Error al verificar autenticador de plataforma'
    };
  }
};