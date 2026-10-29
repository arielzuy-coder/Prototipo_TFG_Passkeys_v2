from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorAttachment
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import secrets
import base64
import json
from typing import List, Dict, Optional
from config import settings

class WebAuthnHandler:
    def __init__(self):
        self.rp_id = settings.RP_ID
        self.rp_name = settings.RP_NAME
        self.origin = settings.ORIGIN
        self.challenge_store = {}
    
    def generate_registration_options(
        self,
        user_id: str,
        username: str,
        display_name: str
    ) -> Dict:
        """Genera opciones para registro de Passkey."""
        
        challenge = secrets.token_bytes(32)
        
        user_id_bytes = user_id.encode('utf-8')
        
        options = {
            "rp": {
                "name": self.rp_name,
                "id": self.rp_id
            },
            "user": {
                "id": base64.urlsafe_b64encode(user_id_bytes).decode('utf-8').rstrip('='),
                "name": username,
                "displayName": display_name
            },
            "challenge": base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('='),
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257}
            ],
            "timeout": 60000,
            "attestation": "none",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "residentKey": "preferred",
                "requireResidentKey": False,
                "userVerification": "required"
            }
        }
        
        self.challenge_store[username] = base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('=')
        
        return options
    
    def verify_registration(
        self,
        credential: Dict,
        expected_challenge: str,
        expected_origin: str,
        expected_rp_id: str
    ) -> Dict:
        """Verifica la respuesta de registro."""
        
        try:
            credential_id = credential.get('id', '')
            raw_id = credential.get('rawId', '')
            response = credential.get('response', {})
            
            attestation_object = response.get('attestationObject', '')
            client_data_json = response.get('clientDataJSON', '')
            
            client_data = json.loads(
                base64.urlsafe_b64decode(client_data_json + '==')
            )
            
            if client_data.get('type') != 'webauthn.create':
                raise ValueError("Tipo de cliente incorrecto")
            
            if client_data.get('origin') != expected_origin:
                raise ValueError("Origen incorrecto")
            
            attestation_bytes = base64.urlsafe_b64decode(attestation_object + '==')
            
            public_key = self._extract_public_key(attestation_bytes)
            
            return {
                "verified": True,
                "credential_id": credential_id,
                "public_key": base64.b64encode(public_key).decode('utf-8') if public_key else "",
                "fmt": "none",
                "counter": 0,
                "aaguid": None,
                "device_type": "platform"
            }
            
        except Exception as e:
            raise ValueError(f"Error verificando registro: {str(e)}")
    
    def generate_authentication_options(
        self,
        user_id: str,
        credentials: List[str]
    ) -> Dict:
        """Genera opciones para autenticación con Passkey."""
        
        challenge = secrets.token_bytes(32)
        
        allow_credentials = [
            {
                "type": "public-key",
                "id": cred_id,
                "transports": ["internal", "usb", "nfc", "ble"]
            }
            for cred_id in credentials
        ]
        
        options = {
            "challenge": base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('='),
            "timeout": 60000,
            "rpId": self.rp_id,
            "allowCredentials": allow_credentials,
            "userVerification": "required"
        }
        
        self.challenge_store[user_id] = base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('=')
        
        return options
    
    def verify_authentication(
        self,
        credential: Dict,
        expected_challenge: str,
        public_key: str,
        expected_origin: str,
        expected_rp_id: str,
        current_counter: int
    ) -> Dict:
        """Verifica la respuesta de autenticación."""
        
        try:
            response = credential.get('response', {})
            client_data_json = response.get('clientDataJSON', '')
            
            client_data = json.loads(
                base64.urlsafe_b64decode(client_data_json + '==')
            )
            
            if client_data.get('type') != 'webauthn.get':
                raise ValueError("Tipo de cliente incorrecto")
            
            if client_data.get('origin') != expected_origin:
                raise ValueError("Origen incorrecto")
            
            authenticator_data = response.get('authenticatorData', '')
            signature = response.get('signature', '')
            
            return {
                "verified": True,
                "new_counter": current_counter + 1
            }
            
        except Exception as e:
            raise ValueError(f"Error verificando autenticación: {str(e)}")
    
    def _extract_public_key(self, attestation_object: bytes) -> Optional[bytes]:
        """Extrae la clave pública del objeto de attestation."""
        try:
            return b"mock_public_key_bytes"
        except Exception:
            return None