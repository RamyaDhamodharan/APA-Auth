import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import jwt

from src.core.config_core import get_settings


def create_access_token(
    subject: str,
    role: str,
    must_change_password: bool = False,
    email: str | None = None,
    name: str | None = None,
    temp_password_expires_at: datetime | None = None,
) -> str:
    settings = get_settings()
    expires_at = datetime.now(UTC) + timedelta(
        minutes=settings.access_token_expire_minutes
    )

    payload = {
        "sub": subject,
        "exp": expires_at,
        "iat": datetime.now(UTC),
        "type": "access",
        "role": role,
        "must_change_password": must_change_password,
        "scope": "password:change" if must_change_password else "workspace",
    }
    if email is not None:
        payload["email"] = email
    if name is not None:
        payload["name"] = name
    if temp_password_expires_at is not None:
        payload["temp_password_expires_at"] = temp_password_expires_at.isoformat()

    return jwt.encode(
        payload,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict[str, object]:
    settings = get_settings()
    return jwt.decode(
        token,
        settings.jwt_secret_key.get_secret_value(),
        algorithms=[settings.jwt_algorithm],
    )


def create_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
