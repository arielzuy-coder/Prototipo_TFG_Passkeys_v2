"""
Autenticador FIDO2 por software para tests (ES256, attestation 'none').

Produce respuestas WebAuthn con el mismo formato JSON que devuelve
@simplewebauthn/browser, firmadas con una clave real, para ejercitar
la verificación criptográfica del backend sin un navegador.
"""
import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT = 0x01, 0x04, 0x08, 0x10, 0x40


class SoftAuthenticator:
    def __init__(self, rp_id: str, origin: str, user_verification: bool = True):
        self.rp_id = rp_id
        self.origin = origin
        self.uv = user_verification
        self.credentials = {}  # cred_id(bytes) -> {"key": private_key, "count": int}

    # ------------------------------------------------------------------
    def _cose_key(self, key) -> bytes:
        nums = key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1,
                            -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})

    def _flags(self, attested: bool) -> int:
        f = FLAG_UP | (FLAG_UV if self.uv else 0)
        return f | (FLAG_AT if attested else 0)

    def _client_data(self, typ: str, challenge_b64: str, origin=None) -> bytes:
        return json.dumps({"type": typ, "challenge": challenge_b64, "origin": origin or self.origin,
                           "crossOrigin": False}).encode()

    # ------------------------------------------------------------------
    def create(self, options: dict, origin=None) -> dict:
        assert options["rp"]["id"] == self.rp_id
        key = ec.generate_private_key(ec.SECP256R1())
        cred_id = os.urandom(32)
        self.credentials[cred_id] = {"key": key, "count": 0}
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        attested = os.urandom(16) + struct.pack(">H", len(cred_id)) + cred_id + self._cose_key(key)
        auth_data = rp_hash + bytes([self._flags(True)]) + struct.pack(">I", 0) + attested
        att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cdj = self._client_data("webauthn.create", options["challenge"], origin)
        return {
            "id": b64url(cred_id), "rawId": b64url(cred_id), "type": "public-key",
            "response": {"clientDataJSON": b64url(cdj), "attestationObject": b64url(att_obj),
                         "transports": ["internal"]},
            "clientExtensionResults": {}, "authenticatorAttachment": "platform",
        }

    def get(self, options: dict, cred_id: bytes = None, origin=None, tamper_signature=False) -> dict:
        allowed = [unb64url(c["id"]) for c in options.get("allowCredentials", [])]
        if cred_id is None:
            cred_id = next(c for c in allowed if c in self.credentials)
        cred = self.credentials[cred_id]
        cred["count"] += 1
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        auth_data = rp_hash + bytes([self._flags(False)]) + struct.pack(">I", cred["count"])
        cdj = self._client_data("webauthn.get", options["challenge"], origin)
        signature = cred["key"].sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        if tamper_signature:
            signature = signature[:-2] + bytes([signature[-2] ^ 1, signature[-1]])
        return {
            "id": b64url(cred_id), "rawId": b64url(cred_id), "type": "public-key",
            "response": {"clientDataJSON": b64url(cdj), "authenticatorData": b64url(auth_data),
                         "signature": b64url(signature), "userHandle": None},
            "clientExtensionResults": {}, "authenticatorAttachment": "platform",
        }
