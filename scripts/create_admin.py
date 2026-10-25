"""Create or promote an AP administrator without accepting a password argument."""

import argparse
import getpass
import sys
import uuid
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.models.user_models import User
from src.services.auth_services import get_user_by_email, hash_new_password


def create_admin_user(db, email: str, password: str) -> tuple[User, bool]:
    email = email.strip().lower()
    user = get_user_by_email(db, email)
    created = user is None
    if created:
        user = User(
            id=uuid.uuid4(),
            name=email.split("@", 1)[0],
            email=email,
            role="admin",
            is_active=True,
            password_hash=hash_new_password(password),
            must_change_password=False,
        )
        db.add(user)
    else:
        user.role = "admin"
        user.is_active = True
        user.must_change_password = False
        user.password_hash = hash_new_password(password)
    db.commit()
    return user, created


def main(
    argv: list[str] | None = None,
    *,
    db_factory: Callable | None = None,
    input_fn: Callable[[str], str] = input,
    password_fn: Callable[[str], str] = getpass.getpass,
    output: Callable[[str], None] = print,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True)
    args = parser.parse_args(argv)
    email = args.email.strip().lower()
    if "@" not in email:
        parser.error("--email must be a valid email address")

    if db_factory is None:
        from src.db.session_db import SessionLocal

        db_factory = SessionLocal
    db = db_factory()
    try:
        existing = get_user_by_email(db, email)
        if existing and input_fn(
            f"{email} exists. Promote to admin and reset its password? [y/N] "
        ).strip().casefold() not in {"y", "yes"}:
            output("No changes made.")
            return 1
        password = password_fn("New admin password: ")
        confirmation = password_fn("Confirm password: ")
        if not password or password != confirmation:
            output("Passwords were empty or did not match; no changes made.")
            return 1
        create_admin_user(db, email, password)
        output("Admin user created." if existing is None else "Admin user updated.")
        return 0
    except Exception:
        db.rollback()
        output("Admin creation failed; no password or database details were logged.")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
