"""
Script de inicialización de base de datos para producción en Render
"""
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from models import Base, Policy
from config import settings
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_database():
    """Inicializa la base de datos creando tablas y datos iniciales"""
    try:
        engine = create_engine(settings.DATABASE_URL)
        
        # Crear todas las tablas
        logger.info("Creando tablas de base de datos...")
        Base.metadata.create_all(bind=engine)
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
        
        finally:
            session.close()
        
        logger.info("✅ Base de datos inicializada correctamente")
        
    except Exception as e:
        logger.error(f"❌ Error inicializando base de datos: {e}")
        raise

if __name__ == "__main__":
    init_database()