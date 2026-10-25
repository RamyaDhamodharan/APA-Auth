"""Idempotently seed an administrator from ADMIN_EMAIL and ADMIN_PASSWORD."""

import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.db.session_db import SessionLocal
from src.models.user_models import User
from src.services.auth_services import get_user_by_email, hash_new_password


def main() -> int:
    email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("ADMIN_PASSWORD", "")
    if not email or "@" not in email or not password:
        print("Admin seed skipped: ADMIN_EMAIL and ADMIN_PASSWORD must be configured.")
        return 1

    db = SessionLocal()
    try:
        if get_user_by_email(db, email) is not None:
            print("Admin seed skipped: an account with ADMIN_EMAIL already exists.")
            return 0

        user = User(
            id=uuid.uuid4(),
            name=email.split("@", 1)[0],
            email=email,
            role="admin",
            is_active=True,
            password_hash=hash_new_password(password),
            must_change_password=False,
            temp_password_expires_at=None,
        )
        db.add(user)
        db.commit()
        print("Admin user created.")
        return 0
    except Exception:
        db.rollback()
        print("Admin seed failed; credentials and database details were not logged.")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
