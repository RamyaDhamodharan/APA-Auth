from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from sqlalchemy.orm import Session

from src.core.security_core import decode_access_token
from src.db.session_db import get_db
from src.models.user_models import User

bearer_scheme = HTTPBearer()


def _authenticate_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
    *,
    allow_password_change: bool = False,
) -> User:
    token = credentials.credentials

    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        token_type = payload.get("type")
        token_requires_password_change = payload.get("must_change_password") is True

        if not user_id or token_type != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid access token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    except InvalidTokenError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err

    user = db.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    if allow_password_change:
        if (
            not token_requires_password_change
            or payload.get("scope") != "password:change"
            or not user.must_change_password
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="A temporary-password session is required",
            )
    elif token_requires_password_change or user.must_change_password:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Change your temporary password before continuing",
        )

    return user


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    return _authenticate_user(credentials, db)


def get_password_change_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    return _authenticate_user(credentials, db, allow_password_change=True)


def require_role(role: str):
    def role_dependency(user: User = Depends(get_current_user)) -> User:
        if user.role != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role"
            )
        return user

    return role_dependency
