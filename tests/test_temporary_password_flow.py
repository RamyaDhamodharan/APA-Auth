import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from src.api.rest.app import app
from src.api.rest.dependencies import get_db
from src.api.rest.routes import auth_routes, users_routes
from src.core.config_core import get_settings
from src.core.security_core import create_access_token, decode_access_token
from src.models.user_models import User


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-that-is-long-enough")
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "5")
    get_settings.cache_clear()
    db = MagicMock()
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app, base_url="https://localhost"), db
    app.dependency_overrides.pop(get_db, None)
    get_settings.cache_clear()


def test_first_login_sets_new_password_and_rejects_temporary_password_reuse(
    client, monkeypatch
):
    api, db = client
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email="associate@example.com",
        name="Test Associate",
        role="associate",
        is_active=True,
        password_hash="temporary-hash",
        must_change_password=True,
        temp_password_expires_at=datetime.now(UTC) + timedelta(hours=1),
        last_login_at=None,
        updated_at=None,
        updated_by=None,
    )
    db.get.return_value = user
    monkeypatch.setattr(auth_routes, "get_user_by_email", lambda *_: user)
    monkeypatch.setattr(
        auth_routes,
        "check_password",
        lambda plain, hashed: (
            (plain == "TempPass!One2026" and hashed == "temporary-hash")
            or (
                plain == "N3w!StrongPassword2026"
                and hashed == "hash:N3w!StrongPassword2026"
            )
        ),
    )
    monkeypatch.setattr(auth_routes, "hash_new_password", lambda value: f"hash:{value}")
    refresh_values = iter(("first-refresh", "next-refresh"))
    monkeypatch.setattr(
        auth_routes, "create_refresh_token", lambda: next(refresh_values)
    )

    login = api.post(
        "/api/auth/login",
        json={"email": user.email, "password": "TempPass!One2026"},
    )
    assert login.status_code == 200
    limited_claims = decode_access_token(login.json()["access_token"])
    assert limited_claims["must_change_password"] is True
    assert limited_claims["scope"] == "password:change"

    password_change = api.post(
        "/auth/set-password",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        json={
            "current_password": "TempPass!One2026",
            "new_password": "N3w!StrongPassword2026",
        },
    )
    assert password_change.status_code == 200
    assert user.password_hash == "hash:N3w!StrongPassword2026"
    assert user.must_change_password is False
    assert user.temp_password_expires_at is None
    assert (
        decode_access_token(password_change.json()["access_token"])[
            "must_change_password"
        ]
        is False
    )

    reuse = api.post(
        "/api/auth/login",
        json={"email": user.email, "password": "TempPass!One2026"},
    )
    assert reuse.status_code == 401


def test_limited_token_cannot_call_admin_or_other_protected_routes(client):
    api, db = client
    associate = SimpleNamespace(
        id=uuid.uuid4(),
        email="associate@example.com",
        name="Test Associate",
        role="associate",
        is_active=True,
        must_change_password=True,
    )
    db.get.return_value = associate
    limited_token = create_access_token(
        subject=str(associate.id),
        role="associate",
        must_change_password=True,
        email=associate.email,
        name=associate.name,
    )
    headers = {"Authorization": f"Bearer {limited_token}"}

    admin_response = api.get("/admin/associates", headers=headers)
    profile_response = api.get("/api/users/me", headers=headers)

    assert admin_response.status_code == 403
    assert profile_response.status_code == 403


def test_associate_without_password_change_cannot_call_admin_routes(client):
    api, db = client
    associate = SimpleNamespace(
        id=uuid.uuid4(),
        email="associate@example.com",
        name="Test Associate",
        role="associate",
        is_active=True,
        must_change_password=False,
    )
    db.get.return_value = associate
    token = create_access_token(
        subject=str(associate.id), role="associate", email=associate.email
    )

    response = api.get(
        "/admin/associates", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403


def test_admin_create_generates_and_returns_one_time_temporary_password(
    client, monkeypatch
):
    api, db = client
    admin = SimpleNamespace(
        id=uuid.uuid4(),
        email="admin@example.com",
        role="admin",
        is_active=True,
        must_change_password=False,
    )
    db.get.return_value = admin
    db.refresh.side_effect = lambda user: (
        setattr(user, "id", uuid.uuid4()),
        setattr(user, "created_at", datetime.now(UTC)),
    )
    monkeypatch.setattr(users_routes, "get_user_by_email", lambda *_: None)
    monkeypatch.setattr(
        users_routes, "_new_temporary_password", lambda: "Generated!TempPass2026"
    )
    monkeypatch.setattr(
        users_routes, "hash_new_password", lambda value: f"argon2:{value}"
    )
    token = create_access_token(
        subject=str(admin.id), role="admin", email=admin.email, name="Admin"
    )

    response = api.post(
        "/admin/associates",
        headers={"Authorization": f"Bearer {token}"},
        json={"email": "new-associate@example.com"},
    )

    saved_user = next(
        item for item in db.add.call_args_list[0].args if isinstance(item, User)
    )
    assert response.status_code == 201
    assert response.json()["temporary_password"] == "Generated!TempPass2026"
    assert response.json()["must_change_password"] is True
    assert saved_user.password_hash == "argon2:Generated!TempPass2026"
    assert saved_user.password_hash != response.json()["temporary_password"]


def test_admin_password_reset_invalidates_old_password_and_requires_password_change(
    client, monkeypatch
):
    api, db = client
    admin = SimpleNamespace(
        id=uuid.uuid4(),
        email="admin@example.com",
        name="Admin",
        role="admin",
        is_active=True,
        must_change_password=False,
    )
    associate = SimpleNamespace(
        id=uuid.uuid4(),
        email="associate@example.com",
        name="Associate",
        role="associate",
        is_active=True,
        password_hash="old-hash",
        must_change_password=False,
        temp_password_expires_at=None,
        last_login_at=None,
    )
    db.get.side_effect = [admin, associate]
    monkeypatch.setattr(
        users_routes, "_new_temporary_password", lambda: "Generated!ResetPass2026"
    )
    monkeypatch.setattr(
        users_routes, "hash_new_password", lambda value: f"hash:{value}"
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _db, email: associate if email == associate.email else None,
    )
    monkeypatch.setattr(
        auth_routes,
        "check_password",
        lambda plain, hashed: (
            hashed == "hash:Generated!ResetPass2026"
            and plain == "Generated!ResetPass2026"
        ),
    )
    monkeypatch.setattr(auth_routes, "_is_login_locked", lambda *_args: False)
    monkeypatch.setattr(auth_routes, "_record_failed_login", lambda *_args: False)
    token = create_access_token(
        subject=str(admin.id), role="admin", email=admin.email, name=admin.name
    )

    reset = api.post(
        f"/admin/associates/{associate.id}/reset-password",
        headers={"Authorization": f"Bearer {token}"},
        json={},
    )
    old_password = api.post(
        "/api/auth/login",
        json={"email": associate.email, "password": "OldPassword!2026"},
    )
    reset_password = api.post(
        "/api/auth/login",
        json={"email": associate.email, "password": "Generated!ResetPass2026"},
    )

    assert reset.status_code == 200
    assert reset.json()["must_change_password"] is True
    assert reset.json()["temporary_password"] == "Generated!ResetPass2026"
    assert associate.password_hash == "hash:Generated!ResetPass2026"
    assert old_password.status_code == 401
    assert reset_password.status_code == 200
    assert reset_password.json()["must_change_password"] is True
