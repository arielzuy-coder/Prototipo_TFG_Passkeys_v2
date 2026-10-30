"""
Script de inicialización de base de datos para producción en Render
"""
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker
from models import Base, Policy, User
from config import settings
from database import engine
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Placeholder que la v1 guardaba como "clave pública" de todas las passkeys
_MOCK_PUBLIC_KEY = "bW9ja19wdWJsaWNfa2V5X2J5dGVz"

MIGRATIONS = [
    # v2: roles, rotación de refresh y metadatos reales de la passkey
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user'",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS refresh_jti_hash VARCHAR(64)",
    "ALTER TABLE passkeys ADD COLUMN IF NOT EXISTS backed_up BOOLEAN DEFAULT FALSE",
    "ALTER TABLE passkeys ADD COLUMN IF NOT EXISTS transports JSON",
    # Huella de dispositivo única por usuario, no global
    "ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_device_fingerprint_key",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_devices_user_fingerprint ON devices (user_id, device_fingerprint)",
    # Fase 3: verificación continua, re-autenticación y dispositivos atados a passkeys
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS credential_id TEXT",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_fingerprint VARCHAR(255)",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS country VARCHAR(10)",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_evaluated_at TIMESTAMP",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS strong_auth_at TIMESTAMP",
    "ALTER TABLE devices ADD COLUMN IF NOT EXISTS credential_ids JSON",
    # Las passkeys de la v1 no tienen clave pública real: no se pueden verificar.
    f"DELETE FROM passkeys WHERE public_key = '{_MOCK_PUBLIC_KEY}'",
    # Usuarios activos sin ninguna passkey válida quedan pendientes de re-enrolamiento
    "UPDATE users SET status = 'pending' WHERE status = 'active' "
    "AND NOT EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = users.id)",
    # Registro de auditoría encadenado (RNF-S4)
    "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS chain_seq BIGINT",
    "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(64)",
    "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS event_hash VARCHAR(64)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_audit_events_chain_seq ON audit_events (chain_seq)",
]


def migrate_schema():
    """Migraciones idempotentes para bases creadas con la v1 (create_all no altera tablas existentes)."""
    from services import audit_chain

    with engine.begin() as conn:
        for stmt in MIGRATIONS:
            conn.execute(text(stmt))
    try:
        with engine.begin() as conn:
            audit_chain.install_guard(conn)
    except Exception as e:  # sin permisos para crear el trigger: la cadena igual detecta alteraciones
        logger.warning("No se pudo instalar la protección de solo agregado en audit_events: %s", type(e).__name__)
    with Session(engine) as session:
        sealed = audit_chain.seal_pending(session)
    if sealed:
        logger.info("Eventos de auditoría previos sellados en la cadena: %s", sealed)
    logger.info("✅ Migraciones aplicadas")


def bootstrap_admin(session):
    """
    Si no hay ningún administrador y BOOTSTRAP_ADMIN_EMAIL está definido, crea el usuario
    y escribe en el log un link de invitación de un solo uso para enrolar su passkey.
    """
    from services.common import create_invitation, normalize_email

    if session.query(User).filter(User.role == "admin", User.status != "suspended").count() > 0:
        return
    if not settings.BOOTSTRAP_ADMIN_EMAIL:
        logger.warning("No hay administradores. Definí BOOTSTRAP_ADMIN_EMAIL o usá create_invitation.py")
        return
    email = normalize_email(settings.BOOTSTRAP_ADMIN_EMAIL)
    user = session.query(User).filter(User.email == email).first()
    if user is None:
        user = User(email=email, display_name=email.split("@")[0], role="admin", status="pending")
        session.add(user)
    else:
        user.role = "admin"
        if user.status != "active":
            user.status = "pending"
    session.commit()
    session.refresh(user)
    if user.status == "active":
        return
    inv = create_invitation(session, user, "enroll")
    logger.warning("=" * 70)
    logger.warning("Invitación de administrador inicial para %s (vence %s):", email, inv["expires_at"])
    logger.warning("%s", inv["url"])
    logger.warning("=" * 70)


def init_database():
    """Inicializa la base de datos creando tablas y datos iniciales"""
    try:
        # Crear todas las tablas
        logger.info("Creando tablas de base de datos...")
        Base.metadata.create_all(bind=engine)
        migrate_schema()
        logger.info("✅ Tablas creadas exitosamente")
        
        # Crear sesión
        Session = sessionmaker(bind=engine)
        session = Session()
        
        try:
            # Verificar si ya existen políticas
            count = session.query(Policy).count()
            
            if count == 0:
                logger.info("Insertando políticas por defecto...")
                
                # Crear políticas usando ORM
                policies = [
                    Policy(
                        name='high_risk_deny',
                        description='Denegar acceso cuando riesgo es alto',
                        conditions={'min_risk_score': 75},
                        action='deny',
                        priority=1,
                        enabled=True
                    ),
                    Policy(
                        name='medium_risk_stepup',
                        description='Requerir verificación adicional para riesgo medio',
                        conditions={'min_risk_score': 40, 'max_risk_score': 74},
                        action='stepup',
                        priority=2,
                        enabled=True
                    ),
                    Policy(
                        name='new_device_stepup',
                        description='Verificar dispositivos nuevos o desconocidos',
                        conditions={'new_device': True},
                        action='stepup',
                        priority=3,
                        enabled=True
                    ),
                    Policy(
                        name='unusual_location_stepup',
                        description='Verificar accesos desde ubicaciones inusuales',
                        conditions={'unusual_location': True},
                        action='stepup',
                        priority=4,
                        enabled=True
                    ),
                    Policy(
                        name='low_risk_allow',
                        description='Permitir acceso directo para riesgo bajo',
                        conditions={'max_risk_score': 39},
                        action='allow',
                        priority=5,
                        enabled=True
                    )
                ]
                
                session.add_all(policies)
                session.commit()
                logger.info("✅ Políticas por defecto insertadas")
            else:
                logger.info(f"Base de datos ya tiene {count} políticas, omitiendo inserción")
        
            bootstrap_admin(session)

        finally:
            session.close()
        
        logger.info("✅ Base de datos inicializada correctamente")
        
    except Exception as e:
        logger.error(f"❌ Error inicializando base de datos: {e}")
        raise

if __name__ == "__main__":
    init_database()