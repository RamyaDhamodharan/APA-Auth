import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import case, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from src.api.rest.dependencies import get_password_change_user
from src.core.config_core import get_settings
from src.core.security_core import (
    create_access_token,
    create_refresh_token,
    hash_refresh_token,
)
from src.db.session_db import get_db
from src.models.login_attempt_models import LoginAttempt
from src.models.refresh_session_models import RefreshSession
from src.models.user_models import User
from src.schemas.auth_schemas import (
    ChangePasswordRequest,
    LoginRequest,
    TokenResponse,
)
from src.services.audit_services import record_audit
from src.services.auth_services import (
    check_password,
    get_user_by_email,
    hash_new_password,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
password_change_alias_router = APIRouter(tags=["Authentication"])
_DUMMY_PASSWORD_HASH = hash_new_password(secrets.token_urlsafe(32))

INVALID_LOGIN_MESSAGE = "Invalid email or password. Please try again."
EXPIRED_PASSWORD_MESSAGE = (
    "Your temporary password has expired. Please contact your admin for a new one."
)
INACTIVE_ACCOUNT_MESSAGE = "Your account is inactive. Please contact your admin."
RATE_LIMIT_MESSAGE = "Too many attempts. Please try again in a few minutes."


def _is_login_locked(db: Session, email: str, client_ip: str, now: datetime) -> bool:
    attempt = (
        db.query(LoginAttempt)
        .filter(LoginAttempt.email == email, LoginAttempt.client_ip == client_ip)
        .first()
    )
    # Test doubles and databases without a row behave as an unlocked key.
    return bool(
        isinstance(attempt, LoginAttempt)
        and attempt.locked_until is not None
        and attempt.locked_until > now
    )


def _record_failed_login(
    db: Session, email: str, client_ip: str, now: datetime
) -> bool:
    settings = get_settings()
    window = timedelta(minutes=max(1, settings.login_window_minutes))
    lockout = timedelta(minutes=max(1, settings.login_lockout_minutes))
    cutoff = now - window
    expired_window = LoginAttempt.window_started_at < cutoff
    count = case((expired_window, 1), else_=LoginAttempt.failed_count + 1)
    statement = (
        pg_insert(LoginAttempt)
        .values(
            email=email,
            client_ip=client_ip,
            failed_count=1,
            window_started_at=now,
        )
        .on_conflict_do_update(
            constraint="uq_login_email_ip",
            set_={
                "failed_count": count,
                "window_started_at": case(
                    (expired_window, now), else_=LoginAttempt.window_started_at
                ),
                "locked_until": case(
                    (expired_window, None), else_=LoginAttempt.locked_until
                ),
            },
        )
        .returning(LoginAttempt.failed_count)
    )
    result = db.execute(statement)
    failed_count = result.scalar_one_or_none()
    if not isinstance(failed_count, int):
        failed_count = 1
    threshold = max(1, settings.login_max_attempts)
    locked = failed_count >= threshold
    if locked:
        db.query(LoginAttempt).filter(
            LoginAttempt.email == email, LoginAttempt.client_ip == client_ip
        ).update({"locked_until": now + lockout}, synchronize_session=False)
        if failed_count == threshold:
            record_audit(
                db,
                action="failed_login_lockout",
                entity_type="login_identity",
                entity_id=None,
                result="warning",
                message=(
                    "Login identity was rate limited after repeated failed attempts"
                ),
                output_summary={
                    "email": email,
                    "client_ip": client_ip,
                    "attempts": failed_count,
                },
            )
    db.commit()
    return locked


def _csrf_check(request: Request) -> None:
    settings = get_settings()
    allowed_origins = {
        origin.strip()
        for origin in settings.cors_allowed_origins.split(",")
        if origin.strip()
    }
    origin = request.headers.get("origin")
    if origin not in allowed_origins or request.headers.get("x-csrf-protection") != "1":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed",
        )


def _set_refresh_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=token,
        max_age=(
            settings.refresh_token_expire_days * 24 * 60 * 60
            if settings.auth_persistent_session
            else None
        ),
        httponly=True,
        secure=True,
        samesite=settings.refresh_cookie_samesite,
        domain=settings.refresh_cookie_domain,
        path=settings.refresh_cookie_path,
    )


def _clear_refresh_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        httponly=True,
        secure=True,
        samesite=settings.refresh_cookie_samesite,
        domain=settings.refresh_cookie_domain,
        path=settings.refresh_cookie_path,
    )


def _unauthorized(detail: str = "Invalid refresh session") -> JSONResponse:
    response = JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": detail},
    )
    _clear_refresh_cookie(response)
    return response


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    email = str(payload.email).strip().lower()
    now = datetime.now(UTC)
    client_ip = request.client.host if request.client else "unknown"

    if _is_login_locked(db, email, client_ip, now):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=RATE_LIMIT_MESSAGE,
        )

    user = get_user_by_email(db, email)
    password_hash = user.password_hash if user else _DUMMY_PASSWORD_HASH
    password_valid = check_password(payload.password, password_hash)
    if not user or not password_valid:
        if _record_failed_login(db, email, client_ip, now):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=RATE_LIMIT_MESSAGE,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_LOGIN_MESSAGE,
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=INACTIVE_ACCOUNT_MESSAGE,
        )

    now = datetime.now(UTC)
    if (
        user.must_change_password
        and user.temp_password_expires_at
        and user.temp_password_expires_at <= now
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=EXPIRED_PASSWORD_MESSAGE,
        )

    db.query(LoginAttempt).filter(
        LoginAttempt.email == email, LoginAttempt.client_ip == client_ip
    ).delete(synchronize_session=False)

    settings = get_settings()
    access_token = create_access_token(
        subject=str(user.id),
        role=str(getattr(user.role, "value", user.role)),
        must_change_password=user.must_change_password,
        email=user.email,
        name=user.name,
        temp_password_expires_at=user.temp_password_expires_at,
    )
    refresh_token = create_refresh_token()
    db.add(
        RefreshSession(
            user_id=user.id,
            token_hash=hash_refresh_token(refresh_token),
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
            created_by=user.id,
            updated_by=user.id,
        )
    )
    user.last_login_at = now
    db.add(user)
    db.commit()
    _set_refresh_cookie(response, refresh_token)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        must_change_password=user.must_change_password,
    )


@router.post("/set-password", response_model=TokenResponse)
@router.post("/change-password", response_model=TokenResponse, include_in_schema=False)
def set_password(
    payload: ChangePasswordRequest,
    response: Response,
    user: User = Depends(get_password_change_user),
    db: Session = Depends(get_db),
) -> TokenResponse:
    now = datetime.now(UTC)
    if (
        user.must_change_password
        and user.temp_password_expires_at
        and user.temp_password_expires_at <= now
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Temporary password expired. Ask an admin for a new one.",
        )
    if not check_password(payload.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )
    if payload.current_password == payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Choose a new password different from the temporary password",
        )

    user.password_hash = hash_new_password(payload.new_password)
    user.must_change_password = False
    user.temp_password_expires_at = None
    user.updated_at = now
    user.updated_by = user.id
    db.query(RefreshSession).filter(
        RefreshSession.user_id == user.id,
        RefreshSession.is_revoked.is_(False),
    ).update(
        {
            "is_revoked": True,
            "revoked_at": now,
            "updated_at": now,
            "updated_by": user.id,
        },
        synchronize_session=False,
    )
    refresh_token = create_refresh_token()
    settings = get_settings()
    db.add(
        RefreshSession(
            user_id=user.id,
            token_hash=hash_refresh_token(refresh_token),
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
            created_by=user.id,
            updated_by=user.id,
        )
    )
    db.add(user)
    db.commit()
    _set_refresh_cookie(response, refresh_token)
    return TokenResponse(
        access_token=create_access_token(
            subject=str(user.id),
            role=str(getattr(user.role, "value", user.role)),
            must_change_password=False,
            email=user.email,
            name=user.name,
        ),
        expires_in=settings.access_token_expire_minutes * 60,
        must_change_password=False,
    )


@router.post("/refresh", response_model=None)
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    refresh_token: str | None = Cookie(
        default=None, alias=get_settings().refresh_cookie_name
    ),
) -> TokenResponse | JSONResponse:
    _csrf_check(request)
    if not refresh_token:
        return _unauthorized()

    now = datetime.now(UTC)
    session = (
        db.query(RefreshSession)
        .filter(RefreshSession.token_hash == hash_refresh_token(refresh_token))
        .with_for_update()
        .first()
    )
    if session is None:
        return _unauthorized()
    if session.is_revoked:
        db.execute(
            update(RefreshSession)
            .where(
                RefreshSession.user_id == session.user_id,
                RefreshSession.is_revoked.is_(False),
            )
            .values(
                is_revoked=True,
                revoked_at=now,
                updated_at=now,
                updated_by=session.user_id,
            )
        )
        db.commit()
        return _unauthorized("Refresh token reuse detected")
    if session.expires_at <= now:
        session.is_revoked = True
        session.revoked_at = now
        session.updated_at = now
        session.updated_by = session.user_id
        db.commit()
        return _unauthorized("Refresh session expired")

    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        session.is_revoked = True
        session.revoked_at = now
        session.updated_at = now
        session.updated_by = session.user_id
        db.commit()
        return _unauthorized("Account is unavailable")

    if (
        user.must_change_password
        and user.temp_password_expires_at
        and user.temp_password_expires_at <= now
    ):
        session.is_revoked = True
        session.revoked_at = now
        session.updated_at = now
        session.updated_by = user.id
        db.commit()
        return _unauthorized(
            "Temporary password expired. Ask your administrator to issue a new one."
        )

    settings = get_settings()
    rotated_token = create_refresh_token()
    session.is_revoked = True
    session.revoked_at = now
    session.updated_at = now
    session.updated_by = user.id
    db.add(
        RefreshSession(
            user_id=user.id,
            token_hash=hash_refresh_token(rotated_token),
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
            created_by=user.id,
            updated_by=user.id,
        )
    )
    db.commit()
    _set_refresh_cookie(response, rotated_token)
    return TokenResponse(
        access_token=create_access_token(
            subject=str(user.id),
            role=str(getattr(user.role, "value", user.role)),
            must_change_password=user.must_change_password,
            email=user.email,
            name=user.name,
            temp_password_expires_at=user.temp_password_expires_at,
        ),
        expires_in=settings.access_token_expire_minutes * 60,
        must_change_password=user.must_change_password,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    refresh_token: str | None = Cookie(
        default=None, alias=get_settings().refresh_cookie_name
    ),
) -> Response:
    _csrf_check(request)
    if refresh_token:
        now = datetime.now(UTC)
        session = (
            db.query(RefreshSession)
            .filter(RefreshSession.token_hash == hash_refresh_token(refresh_token))
            .with_for_update()
            .first()
        )
        if session is not None and not session.is_revoked:
            session.is_revoked = True
            session.revoked_at = now
            session.updated_at = now
            session.updated_by = session.user_id
            db.commit()
    _clear_refresh_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


password_change_alias_router.add_api_route(
    "/auth/set-password",
    set_password,
    methods=["POST"],
    response_model=TokenResponse,
)
