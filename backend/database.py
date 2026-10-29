"""Conexión a base de datos compartida por toda la aplicación."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import settings


def _normalize_url(url: str) -> str:
    # Render entrega "postgres://" o "postgresql://". SQLAlchemy 2.x necesita
    # el driver explícito para usar psycopg2 (el que está en requirements).
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url


engine = create_engine(_normalize_url(settings.DATABASE_URL), pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
