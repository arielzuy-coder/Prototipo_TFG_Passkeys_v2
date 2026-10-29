"""
Crea un usuario (o reutiliza uno existente) y emite una invitación de enrolamiento.

Uso:
    python create_invitation.py admin@empresa.com --role admin
    python create_invitation.py juan@empresa.com --recovery     # re-enrolamiento: revoca sus passkeys
"""
import argparse

from auth.session_manager import SessionManager
from database import SessionLocal
from models import Passkey, User
from services.common import create_invitation, normalize_email


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("email")
    parser.add_argument("--role", choices=["user", "admin", "auditor"], default=None)
    parser.add_argument("--name", default=None)
    parser.add_argument("--recovery", action="store_true", help="revoca passkeys y sesiones del usuario")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        email = normalize_email(args.email)
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            user = User(email=email, display_name=args.name or email.split("@")[0],
                        role=args.role or "user", status="pending")
            db.add(user)
        elif args.role:
            user.role = args.role
        purpose = "enroll"
        if args.recovery:
            db.query(Passkey).filter(Passkey.user_id == user.id).delete()
            SessionManager().revoke_all_user_sessions(user.id, db)
            user.status = "pending"
            purpose = "recovery"
        elif user.status == "active":
            raise SystemExit("El usuario ya está activo. Usá --recovery para re-enrolarlo.")
        db.commit()
        db.refresh(user)
        inv = create_invitation(db, user, purpose)
        print(f"Usuario: {user.email} (rol: {user.role})")
        print(f"Invitación ({purpose}), vence {inv['expires_at']}:")
        print(inv["url"])
    finally:
        db.close()


if __name__ == "__main__":
    main()
