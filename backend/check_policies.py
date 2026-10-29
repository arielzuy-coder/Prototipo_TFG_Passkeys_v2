from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Policy
from config import settings

engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

print("\n===== POLÍTICAS EN LA BASE DE DATOS =====\n")

policies = db.query(Policy).order_by(Policy.priority.asc()).all()

for p in policies:
    print(f"ID: {p.id}")
    print(f"Nombre: {p.name}")
    print(f"Descripción: {p.description}")
    print(f"Condiciones: {p.conditions}")
    print(f"Acción: {p.action}")
    print(f"Prioridad: {p.priority}")
    print(f"Habilitada: {p.enabled}")
    print("-" * 50)

db.close()
