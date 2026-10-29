from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
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
    ORIGIN: str
    
    # Risk Engine
    RISK_THRESHOLD_LOW: int = 40
    RISK_THRESHOLD_HIGH: int = 75
    
    class Config:
        env_file = ".env"

settings = Settings()