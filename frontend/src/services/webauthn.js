import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import api from './api';

// Traduce los errores del navegador a mensajes claros
const browserError = (error) => {
  if (error?.name === 'NotAllowedError') return new Error('Operación cancelada o tiempo agotado');
  if (error?.name === 'InvalidStateError') return new Error('Este autenticador ya está registrado');
  if (error?.name === 'SecurityError') return new Error('El dominio no coincide con el configurado (RP ID)');
  return new Error('El autenticador no pudo completar la operación');
};

const createCredential = async (options) => {
  try {
    return await startRegistration(options);
  } catch (error) {
    throw browserError(error);
  }
};

export const getAssertion = async (options) => {
  try {
    return await startAuthentication(options);
  } catch (error) {
    error.browserError = browserError(error);
    throw error;
  }
};

// Primera passkey, con la invitación de alta o de recuperación
export const enrollWithInvitation = async (invitationToken, deviceName) => {
  const { data: options } = await api.post('/auth/register/begin', { invitation_token: invitationToken });
  const credential = await createCredential(options);
  const { data } = await api.post('/auth/register/complete', {
    invitation_token: invitationToken,
    credential,
    device_name: deviceName
  });
  return data;
};

// Passkey adicional para un usuario con sesión iniciada (máx. 5)
export const addPasskey = async (deviceName) => {
  const { data: options } = await api.post('/passkeys/register/begin');
  const credential = await createCredential(options);
  const { data } = await api.post('/passkeys/register/complete', { credential, device_name: deviceName });
  return data;
};

// Re-autenticación para el step-up
export const stepUpWithPasskey = async (stepupToken) => {
  const { data: options } = await api.post('/auth/stepup/passkey/begin', { stepup_token: stepupToken });
  let credential;
  try {
    credential = await startAuthentication(options);
  } catch (error) {
    throw browserError(error);
  }
  const { data } = await api.post('/auth/stepup/verify', {
    stepup_token: stepupToken,
    verification_type: 'passkey',
    credential
  });
  return data;
};

export const checkWebAuthnSupport = () => ({
  supported: !!window.PublicKeyCredential,
  message: window.PublicKeyCredential ? 'WebAuthn está soportado' : 'WebAuthn no está soportado en este navegador'
});
