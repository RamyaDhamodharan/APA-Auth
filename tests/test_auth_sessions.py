import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import Response
from fastapi.testclient import TestClient

from src.api.rest.app import app
from src.api.rest.routes import auth_routes
from src.core.config_core import get_settings
from src.core.security_core import decode_access_token
from src.db.session_db import get_db
from src.models.refresh_session_models import RefreshSession


@pytest.fixture(autouse=True)
def auth_settings(monkeypatch):
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "5")
    monkeypatch.delenv("AUTH_PERSISTENT_SESSION", raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client():
    return TestClient(app, base_url="https://localhost")


def _set_db(db):
    app.dependency_overrides[get_db] = lambda: db


def _clear_db():
    app.dependency_overrides.pop(get_db, None)


def _csrf_headers():
    return {"Origin": "http://localhost:3000", "X-CSRF-Protection": "1"}


def _refresh_headers():
    return {
        **_csrf_headers(),
        "Cookie": f"{get_settings().refresh_cookie_name}=presented-refresh-token",
    }


def _session(user_id, *, expires_at=None, is_revoked=False):
    return SimpleNamespace(
        id=uuid.uuid4(),
        user_id=user_id,
        token_hash=hashlib.sha256(b"presented-refresh-token").hexdigest(),
        expires_at=expires_at or datetime.now(UTC) + timedelta(days=1),
        is_revoked=is_revoked,
        revoked_at=None,
        updated_at=None,
        updated_by=None,
    )


def test_login_sets_hashed_refresh_cookie_and_returns_only_access_token(
    client, monkeypatch
):
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email="user@example.com",
        name="Test User",
        role="associate",
        is_active=True,
        password_hash="password-hash",
        must_change_password=False,
        temp_password_expires_at=None,
        last_login_at=None,
    )
    db = MagicMock()
    _set_db(db)
    monkeypatch.setattr(auth_routes, "get_user_by_email", lambda *_args: user)
    monkeypatch.setattr(auth_routes, "check_password", lambda *_args: True)
    monkeypatch.setattr(auth_routes, "create_access_token", lambda **_kwargs: "access")
    monkeypatch.setattr(auth_routes, "create_refresh_token", lambda: "refresh-secret")

    try:
        response = client.post(
            "/api/auth/login",
            json={"email": "user@example.com", "password": "password"},
        )
    finally:
        _clear_db()

    saved_session = next(
        item
        for item in (call.args[0] for call in db.add.call_args_list)
        if isinstance(item, RefreshSession)
    )
    assert response.status_code == 200
    assert response.json() == {
        "access_token": "access",
        "token_type": "bearer",
        "expires_in": 300,
        "must_change_password": False,
    }
    assert "refresh_token" not in response.json()
    assert response.cookies[get_settings().refresh_cookie_name] == "refresh-secret"
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "secure" in response.headers["set-cookie"].lower()
    assert "max-age=" not in response.headers["set-cookie"].lower()
    assert "expires=" not in response.headers["set-cookie"].lower()
    assert "path=/api/auth" in response.headers["set-cookie"].lower()
    assert "samesite=lax" in response.headers["set-cookie"].lower()
    assert saved_session.token_hash == hashlib.sha256(b"refresh-secret").hexdigest()
    assert saved_session.token_hash != "refresh-secret"


def test_persistent_session_flag_restores_cookie_max_age(monkeypatch):
    monkeypatch.setenv("AUTH_PERSISTENT_SESSION", "true")
    get_settings.cache_clear()
    response = Response()

    auth_routes._set_refresh_cookie(response, "refresh-secret")

    cookie = response.headers["set-cookie"].lower()
    assert "max-age=604800" in cookie
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=lax" in cookie


def test_expired_temporary_password_is_rejected(client, monkeypatch):
    user = SimpleNamespace(
        id=uuid.uuid4(),
        role="associate",
        is_active=True,
        password_hash="password-hash",
        must_change_password=True,
        temp_password_expires_at=datetime.now(UTC) - timedelta(seconds=1),
        last_login_at=None,
    )
    db = MagicMock()
    _set_db(db)
    monkeypatch.setattr(auth_routes, "get_user_by_email", lambda *_args: user)
    monkeypatch.setattr(auth_routes, "check_password", lambda *_args: True)

    try:
        response = client.post(
            "/api/auth/login",
            json={"email": "user@example.com", "password": "temporary-password"},
        )
    finally:
        _clear_db()

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Your temporary password has expired. Please contact your admin for a new one."
    )
    db.add.assert_not_called()


def test_unknown_email_and_wrong_password_return_same_generic_message(
    client, monkeypatch
):
    api = client
    db = MagicMock()
    _set_db(db)
    user = SimpleNamespace(password_hash="known-user-hash", is_active=True)
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _db, email: user if email == "known@example.com" else None,
    )
    password_checks = []

    def check_password(plain, hashed):
        password_checks.append(hashed)
        return False

    monkeypatch.setattr(auth_routes, "check_password", check_password)
    monkeypatch.setattr(auth_routes, "_record_failed_login", lambda *_args: False)
    try:
        unknown = api.post(
            "/api/auth/login",
            json={"email": "missing@example.com", "password": "bad"},
        )
        wrong_password = api.post(
            "/api/auth/login",
            json={"email": "known@example.com", "password": "bad"},
        )
    finally:
        _clear_db()

    expected = "Invalid email or password. Please try again."
    assert unknown.status_code == wrong_password.status_code == 401
    assert unknown.json()["detail"] == wrong_password.json()["detail"] == expected
    assert password_checks == [auth_routes._DUMMY_PASSWORD_HASH, "known-user-hash"]


def test_login_rate_limits_after_configured_failed_attempts(client, monkeypatch):
    api = client
    db = MagicMock()
    _set_db(db)
    monkeypatch.setenv("LOGIN_MAX_ATTEMPTS", "3")
    get_settings.cache_clear()
    monkeypatch.setattr(auth_routes, "get_user_by_email", lambda *_args: None)
    monkeypatch.setattr(auth_routes, "check_password", lambda *_args: False)
    monkeypatch.setattr(auth_routes, "_is_login_locked", lambda *_args: False)
    db.execute.return_value.scalar_one_or_none.side_effect = [1, 2, 3]
    try:
        responses = [
            api.post(
                "/api/auth/login",
                json={"email": "lock@example.com", "password": "wrong"},
            )
            for _ in range(3)
        ]
    finally:
        _clear_db()

    assert [response.status_code for response in responses] == [401, 401, 429]
    assert responses[-1].json()["detail"] == (
        "Too many attempts. Please try again in a few minutes."
    )
    assert db.execute.call_count == 4  # three upserts and the lockout audit record


def test_public_registration_is_disabled(client):
    response = client.post(
        "/api/auth/register",
        json={
            "email": "user@example.com",
            "password": "long-temporary-password",
            "full_name": "Test User",
        },
    )
    assert response.status_code == 404


@pytest.mark.parametrize("role", ["admin", "associate"])
def test_login_access_token_contains_user_role(client, monkeypatch, role):
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email="user@example.com",
        name="Test User",
        role=role,
        is_active=True,
        password_hash="password-hash",
        must_change_password=False,
        temp_password_expires_at=None,
        last_login_at=None,
    )
    db = MagicMock()
    _set_db(db)
    monkeypatch.setattr(auth_routes, "get_user_by_email", lambda *_args: user)
    monkeypatch.setattr(auth_routes, "check_password", lambda *_args: True)
    monkeypatch.setattr(auth_routes, "create_refresh_token", lambda: "refresh-secret")

    try:
        response = client.post(
            "/api/auth/login",
            json={"email": "user@example.com", "password": "password"},
        )
    finally:
        _clear_db()

    assert response.status_code == 200
    claims = decode_access_token(response.json()["access_token"])
    assert claims["role"] == role


def test_refresh_rotates_token_and_rejects_reuse(client, monkeypatch):
    user_id = uuid.uuid4()
    user = SimpleNamespace(
        id=user_id,
        email="user@example.com",
        name="Test User",
        role="associate",
        is_active=True,
        must_change_password=False,
        temp_password_expires_at=None,
    )
    session = _session(user_id)
    db = MagicMock()
    locked_query = (
        db.query.return_value.filter.return_value.with_for_update.return_value
    )
    locked_query.first.return_value = session
    db.get.return_value = user
    _set_db(db)
    monkeypatch.setattr(auth_routes, "create_refresh_token", lambda: "rotated-secret")
    monkeypatch.setattr(
        auth_routes, "create_access_token", lambda **_kwargs: "new-access"
    )

    try:
        response = client.post(
            "/api/auth/refresh",
            headers=_refresh_headers(),
        )
    finally:
        _clear_db()

    saved_session = next(
        item
        for item in (call.args[0] for call in db.add.call_args_list)
        if isinstance(item, RefreshSession)
    )
    assert response.status_code == 200
    assert response.json()["access_token"] == "new-access"
    assert "refresh_token" not in response.json()
    assert response.cookies[get_settings().refresh_cookie_name] == "rotated-secret"
    assert session.is_revoked is True
    assert saved_session.token_hash == hashlib.sha256(b"rotated-secret").hexdigest()


def test_refresh_uses_role_from_current_database_user(client, monkeypatch):
    user_id = uuid.uuid4()
    user = SimpleNamespace(
        id=user_id,
        email="user@example.com",
        name="Test User",
        role="associate",
        is_active=True,
        must_change_password=False,
        temp_password_expires_at=None,
    )
    session = _session(user_id)
    db = MagicMock()
    locked_query = (
        db.query.return_value.filter.return_value.with_for_update.return_value
    )
    locked_query.first.return_value = session
    db.get.return_value = user
    _set_db(db)
    monkeypatch.setattr(auth_routes, "create_refresh_token", lambda: "rotated-secret")
    # Simulate an administrator changing this user's role before the refresh.
    user.role = "admin"

    try:
        response = client.post("/api/auth/refresh", headers=_refresh_headers())
    finally:
        _clear_db()

    assert response.status_code == 200
    claims = decode_access_token(response.json()["access_token"])
    assert claims["role"] == "admin"


def test_expired_refresh_is_revoked_and_cookie_cleared(client):
    session = _session(
        uuid.uuid4(), expires_at=datetime.now(UTC) - timedelta(seconds=1)
    )
    db = MagicMock()
    locked_query = (
        db.query.return_value.filter.return_value.with_for_update.return_value
    )
    locked_query.first.return_value = session
    _set_db(db)

    try:
        response = client.post(
            "/api/auth/refresh",
            headers=_refresh_headers(),
        )
    finally:
        _clear_db()

    assert response.status_code == 401
    assert session.is_revoked is True
    assert "max-age=0" in response.headers["set-cookie"].lower()


def test_revoked_refresh_reuse_revokes_other_sessions(client):
    session = _session(uuid.uuid4(), is_revoked=True)
    db = MagicMock()
    locked_query = (
        db.query.return_value.filter.return_value.with_for_update.return_value
    )
    locked_query.first.return_value = session
    _set_db(db)

    try:
        response = client.post(
            "/api/auth/refresh",
            headers=_refresh_headers(),
        )
    finally:
        _clear_db()

    assert response.status_code == 401
    assert response.json()["detail"] == "Refresh token reuse detected"
    db.execute.assert_called_once()
    assert "max-age=0" in response.headers["set-cookie"].lower()


def test_logout_revokes_session_and_clears_cookie(client):
    session = _session(uuid.uuid4())
    db = MagicMock()
    locked_query = (
        db.query.return_value.filter.return_value.with_for_update.return_value
    )
    locked_query.first.return_value = session
    _set_db(db)

    try:
        response = client.post(
            "/api/auth/logout",
            headers=_refresh_headers(),
        )
    finally:
        _clear_db()

    assert response.status_code == 204
    assert session.is_revoked is True
    assert "max-age=0" in response.headers["set-cookie"].lower()


def test_cookie_refresh_requires_origin_and_csrf_header(client):
    db = MagicMock()
    _set_db(db)

    try:
        response = client.post("/api/auth/refresh")
    finally:
        _clear_db()

    assert response.status_code == 403
    db.query.assert_not_called()


def test_cors_allows_credentials_and_csrf_header_for_frontend_origin(client):
    response = client.options(
        "/api/auth/refresh",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-csrf-protection",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert (
        "x-csrf-protection" in response.headers["access-control-allow-headers"].lower()
    )
