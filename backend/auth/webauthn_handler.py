"""
Ceremonias WebAuthn (registro y autenticación) con verificación criptográfica real.

Toda la validación (firma, challenge, origen, RP ID, flags UP/UV, contador)
la hace py_webauthn. Este módulo agrega:
  - challenges de un solo uso guardados en base de datos, con vencimiento,
    atados al usuario, al tipo de ceremonia y (opcionalmente) a una invitación
    o transacción de step-up;
  - persistencia de la clave pública COSE real de cada passkey.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session as DBSession
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    options_to_json_dict,
    base64url_to_bytes,
    bytes_to_base64url,
    parse_authentication_credential_json,
    parse_client_data_json,
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from config import settings
from models import Passkey, User, WebAuthnChallenge

logger = logging.getLogger(__name__)


class WebAuthnError(Exception):
    """Error de verificación. El mensaje es apto para mostrar al cliente."""


def _descriptor(passkey: Passkey) -> PublicKeyCredentialDescriptor:
    transports = None
    if passkey.transports:
        valid = {t.value for t in AuthenticatorTransport}
        transports = [AuthenticatorTransport(t) for t in passkey.transports if t in valid] or None
    return PublicKeyCredentialDescriptor(id=base64url_to_bytes(passkey.credential_id), transports=transports)


class WebAuthnHandler:
    def __init__(self):
        self.rp_id = settings.RP_ID
        self.rp_name = settings.RP_NAME
        self.origin = settings.ORIGIN.rstrip("/")

    # ------------------------------------------------------------------
    # Challenges
    # ------------------------------------------------------------------
    def _store_challenge(self, db: DBSession, user: User, purpose: str, challenge: bytes,
                         ref_id: Optional[uuid.UUID]) -> None:
        db.add(WebAuthnChallenge(
            user_id=user.id,
            purpose=purpose,
            ref_id=ref_id,
            challenge=bytes_to_base64url(challenge),
            expires_at=datetime.utcnow() + timedelta(seconds=settings.CHALLENGE_TTL_SECONDS),
        ))
        db.commit()

    def _consume_challenge(self, db: DBSession, user: User, purpose: str, client_data_b64: str,
                           ref_id: Optional[uuid.UUID]) -> bytes:
        """Busca el challenge que firmó el autenticador y lo invalida (un solo uso)."""
        try:
            client_data = parse_client_data_json(base64url_to_bytes(client_data_b64))
            challenge_b64 = bytes_to_base64url(client_data.challenge)
        except Exception:
            raise WebAuthnError("Respuesta del autenticador malformada")

        row = (
            db.query(WebAuthnChallenge)
            .filter(
                WebAuthnChallenge.challenge == challenge_b64,
                WebAuthnChallenge.user_id == user.id,
                WebAuthnChallenge.purpose == purpose,
            )
            .with_for_update()
            .first()
        )
        if row is None or row.used_at is not None or row.expires_at < datetime.utcnow():
            raise WebAuthnError("Desafío inválido, vencido o ya utilizado")
        if ref_id is not None and row.ref_id != ref_id:
            raise WebAuthnError("Desafío inválido para esta operación")

        row.used_at = datetime.utcnow()
        db.commit()
        return base64url_to_bytes(row.challenge)

    def purge_expired_challenges(self, db: DBSession) -> int:
        n = db.query(WebAuthnChallenge).filter(
            WebAuthnChallenge.expires_at < datetime.utcnow() - timedelta(hours=1)
        ).delete()
        db.commit()
        return n

    # ------------------------------------------------------------------
    # Registro
    # ------------------------------------------------------------------
    def begin_registration(self, db: DBSession, user: User, ref_id: Optional[uuid.UUID] = None) -> Dict[str, Any]:
        existing = db.query(Passkey).filter(Passkey.user_id == user.id).all()
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user.id.bytes,  # user handle opaco, sin datos personales
            user_name=user.email,
            user_display_name=user.display_name or user.email,
            timeout=settings.WEBAUTHN_TIMEOUT_MS,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            # Evita registrar dos veces el mismo autenticador
            exclude_credentials=[_descriptor(pk) for pk in existing],
        )
        self._store_challenge(db, user, "register", options.challenge, ref_id)
        return options_to_json_dict(options)

    def finish_registration(self, db: DBSession, user: User, credential: Dict[str, Any],
                            ref_id: Optional[uuid.UUID] = None) -> Dict[str, Any]:
        try:
            parsed = parse_registration_credential_json(credential)
        except Exception:
            raise WebAuthnError("Credencial de registro malformada")

        expected_challenge = self._consume_challenge(
            db, user, "register", bytes_to_base64url(parsed.response.client_data_json), ref_id
        )
        try:
            verified = verify_registration_response(
                credential=parsed,
                expected_challenge=expected_challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                require_user_verification=True,
            )
        except Exception as e:
            logger.warning("Registro WebAuthn rechazado para %s: %s", user.email, e)
            raise WebAuthnError("No se pudo verificar la credencial")

        credential_id = bytes_to_base64url(verified.credential_id)
        if db.query(Passkey).filter(Passkey.credential_id == credential_id).first():
            raise WebAuthnError("Esta credencial ya está registrada")

        transports = None
        if parsed.response.transports:
            transports = [t.value for t in parsed.response.transports]

        return {
            "credential_id": credential_id,
            "public_key": bytes_to_base64url(verified.credential_public_key),
            "sign_count": verified.sign_count,
            "aaguid": verified.aaguid,
            "fmt": verified.fmt.value if hasattr(verified.fmt, "value") else str(verified.fmt),
            "device_type": verified.credential_device_type.value,
            "backed_up": verified.credential_backed_up,
            "transports": transports,
        }

    # ------------------------------------------------------------------
    # Autenticación (login y step-up)
    # ------------------------------------------------------------------
    def begin_authentication(self, db: DBSession, user: User, purpose: str = "login",
                             ref_id: Optional[uuid.UUID] = None,
                             passkeys: Optional[List[Passkey]] = None) -> Dict[str, Any]:
        if passkeys is None:
            passkeys = db.query(Passkey).filter(Passkey.user_id == user.id).all()
        if not passkeys:
            raise WebAuthnError("No hay passkeys registradas")
        options = generate_authentication_options(
            rp_id=self.rp_id,
            timeout=settings.WEBAUTHN_TIMEOUT_MS,
            allow_credentials=[_descriptor(pk) for pk in passkeys],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        self._store_challenge(db, user, purpose, options.challenge, ref_id)
        return options_to_json_dict(options)

    def finish_authentication(self, db: DBSession, user: User, credential: Dict[str, Any],
                              purpose: str = "login", ref_id: Optional[uuid.UUID] = None) -> Passkey:
        try:
            parsed = parse_authentication_credential_json(credential)
        except Exception:
            raise WebAuthnError("Credencial de autenticación malformada")

        # El challenge se consume antes de verificar: un intento fallido también lo invalida
        expected_challenge = self._consume_challenge(
            db, user, purpose, bytes_to_base64url(parsed.response.client_data_json), ref_id
        )

        credential_id = bytes_to_base64url(parsed.raw_id)
        passkey = (
            db.query(Passkey)
            .filter(Passkey.credential_id == credential_id, Passkey.user_id == user.id)
            .first()
        )
        if passkey is None:
            raise WebAuthnError("Credencial no reconocida")

        try:
            verified = verify_authentication_response(
                credential=parsed,
                expected_challenge=expected_challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                credential_public_key=base64url_to_bytes(passkey.public_key),
                credential_current_sign_count=passkey.counter or 0,
                require_user_verification=True,
            )
        except Exception as e:
            logger.warning("Autenticación WebAuthn rechazada para %s: %s", user.email, e)
            raise WebAuthnError("No se pudo verificar la credencial")

        passkey.counter = verified.new_sign_count
        passkey.backed_up = verified.credential_backed_up
        passkey.last_used_at = datetime.utcnow()
        db.commit()
        return passkey
