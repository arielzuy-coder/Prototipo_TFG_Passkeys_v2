"""
Verifica una base restaurada (prueba de la política de respaldo).

Compara la base restaurada con la de producción y comprueba que la cadena de auditoría
de la copia esté íntegra y coincida con producción hasta el punto restaurado.

Uso (desde la consola Shell del backend en Render):
    cd backend && RESTORE_DATABASE_URL='<Internal Database URL de la base restaurada>' python verify_backup.py

No imprime ninguna URL ni credencial.
"""
import os
import sys

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from database import engine as prod_engine
from services import audit_chain

TABLES = ["users", "passkeys", "policies", "sessions", "audit_events"]


def normalize(url: str) -> str:
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url


def counts(engine):
    with engine.connect() as conn:
        return {t: conn.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in TABLES}


def main():
    url = os.environ.get("RESTORE_DATABASE_URL")
    if not url:
        sys.exit("Falta RESTORE_DATABASE_URL (Internal Database URL de la base restaurada).")
    restore_engine = create_engine(normalize(url))

    prod, rest = counts(prod_engine), counts(restore_engine)
    print("\nRegistros por tabla        Producción   Restaurada")
    for t in TABLES:
        print(f"  {t:<24}{prod[t]:>10}   {rest[t]:>10}")

    with Session(restore_engine) as s:
        result = audit_chain.verify(s)
    print("\nCadena de auditoría de la copia restaurada:")
    if result["intact"]:
        print(f"  ÍNTEGRA: {result['checked']} eventos verificados")
    else:
        print(f"  ALTERADA: {result.get('broken_at') or result}")
        sys.exit(1)

    seq, seal = result["anchor"]["seq"], result["anchor"]["hash"]
    with prod_engine.connect() as conn:
        prod_seal = conn.execute(text("SELECT event_hash FROM audit_events WHERE chain_seq = :s"), {"s": seq}).scalar()
    same = prod_seal == seal
    print(f"\nÚltimo evento de la copia: n.º {seq}, sello {seal[:16]}…")
    print(f"  En producción, el evento n.º {seq} tiene el {'MISMO' if same else 'OTRO'} sello"
          + ("" if same else "  <-- revisar"))
    print("\nResultado:", "RESTAURACIÓN VERIFICADA" if same else "LA COPIA NO COINCIDE CON PRODUCCIÓN")


if __name__ == "__main__":
    main()
