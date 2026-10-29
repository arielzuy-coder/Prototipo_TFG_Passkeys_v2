from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    DATABASE_URL: str

    # Security
    SECRET_KEY: str
    JWT_SECRET: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_HOURS: int = 8

    # WebAuthn
    RP_ID: str
    RP_NAME: str
    ORIGIN: str  # origen del frontend, ej. https://auth-frontend.onrender.com
    WEBAUTHN_TIMEOUT_MS: int = 60000
    CHALLENGE_TTL_SECONDS: int = 300
    MAX_PASSKEYS_PER_USER: int = 5

    # CORS: orígenes adicionales separados por coma (además de ORIGIN)
    CORS_ORIGINS: str = ""

    # Alta de usuarios por invitación
    FRONTEND_URL: Optional[str] = None  # base para armar el link de invitación (default: ORIGIN)
    INVITATION_TTL_HOURS: int = 72
    BOOTSTRAP_ADMIN_EMAIL: Optional[str] = None

    # Step-up
    STEPUP_TTL_MINUTES: int = 10
    STEPUP_MAX_ATTEMPTS: int = 5

    # OTP por email (opcional: solo se ofrece si SMTP_HOST está configurado)
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: Optional[str] = None
    SMTP_STARTTLS: bool = True

    # Risk Engine
    RISK_THRESHOLD_LOW: int = 40
    RISK_THRESHOLD_HIGH: int = 75

    @property
    def cors_origins(self) -> List[str]:
        extra = [o.strip().rstrip("/") for o in self.CORS_ORIGINS.split(",") if o.strip()]
        return list(dict.fromkeys([self.ORIGIN.rstrip("/"), *extra]))

    @property
    def frontend_url(self) -> str:
        return (self.FRONTEND_URL or self.ORIGIN).rstrip("/")

    @property
    def otp_enabled(self) -> bool:
        return bool(self.SMTP_HOST and self.SMTP_FROM)


settings = Settings()
