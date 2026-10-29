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
    TRUSTED_COUNTRIES: str = "AR"  # países de bajo riesgo, separados por coma
    # Horario laboral (hora de Buenos Aires). Fuera de él el factor "horario" suma riesgo.
    BUSINESS_HOURS_START: str = "08:00"
    BUSINESS_HOURS_END: str = "19:00"
    BUSINESS_WEEKDAYS_ONLY: bool = True  # sábados y domingos cuentan como fuera de horario

    # IP del cliente detrás de un proxy (Render, nginx, etc.)
    # TRUSTED_PROXY_HOPS = cantidad de proxies propios delante de la app que agregan a X-Forwarded-For.
    # 0 = usar la IP de la conexión. Nunca confiar en más saltos de los que existen: el cliente
    # puede enviar su propio X-Forwarded-For.
    TRUSTED_PROXY_HOPS: int = 0
    # Alternativa: header con la IP real que el proxy SOBRESCRIBE siempre (ej. "true-client-ip")
    CLIENT_IP_HEADER: Optional[str] = None

    # Geolocalización: "local" (base incluida, la IP no sale del servidor), "ipapi" o "none"
    GEOIP_PROVIDER: str = "local"
    GEOIP_CACHE_SECONDS: int = 3600
    # País asignado a IPs privadas/loopback. Vacío = ubicación desconocida (recomendado en producción)
    LOCAL_IP_COUNTRY: Optional[str] = None

    # Límite de intentos (rate limiting)
    RATE_LIMIT_ENABLED: bool = True

    # Re-autenticación para operaciones sensibles del administrador
    REAUTH_MAX_AGE_MINUTES: int = 10

    # Verificación continua de sesión (UC-03): intervalo de reevaluación según riesgo
    SESSION_REEVAL_MINUTES_LOW: int = 30
    SESSION_REEVAL_MINUTES_MEDIUM: int = 15
    SESSION_REEVAL_MINUTES_HIGH: int = 5

    @property
    def trusted_countries(self) -> List[str]:
        return [c.strip().upper() for c in self.TRUSTED_COUNTRIES.split(",") if c.strip()]

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
