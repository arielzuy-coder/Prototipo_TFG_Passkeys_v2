"""Envío de OTP por email. Solo se usa si SMTP_HOST y SMTP_FROM están configurados."""
import logging
import smtplib
import ssl
from email.message import EmailMessage

from config import settings

logger = logging.getLogger(__name__)


def send_otp_email(to: str, code: str, minutes: int) -> bool:
    if not settings.otp_enabled:
        return False
    msg = EmailMessage()
    msg["Subject"] = f"{settings.RP_NAME}: código de verificación"
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to
    msg.set_content(
        f"Tu código de verificación es {code}.\n\n"
        f"Vence en {minutes} minutos. Si no intentaste iniciar sesión, avisá al equipo de seguridad."
    )
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as smtp:
            if settings.SMTP_STARTTLS:
                smtp.starttls(context=ssl.create_default_context())
            if settings.SMTP_USER:
                smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD or "")
            smtp.send_message(msg)
        return True
    except Exception as e:  # el código nunca se registra en logs
        logger.error("No se pudo enviar el OTP por email: %s", type(e).__name__)
        return False
