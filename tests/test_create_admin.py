from types import SimpleNamespace
from unittest.mock import MagicMock

from scripts import create_admin
from scripts.create_admin import create_admin_user
from src.services.auth_services import check_password


def test_create_admin_uses_auth_hasher_and_sets_admin_flags():
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None

    user, created = create_admin_user(db, "Admin@Example.com", "safe-test-password")

    assert created is True
    assert user.email == "admin@example.com"
    assert user.role == "admin"
    assert user.is_active is True
    assert user.must_change_password is False
    assert check_password("safe-test-password", user.password_hash)
    db.add.assert_called_once_with(user)
    db.commit.assert_called_once()


def test_existing_admin_is_promoted_and_password_hash_reset():
    existing = SimpleNamespace(
        email="staff@example.com",
        role="associate",
        is_active=False,
        must_change_password=True,
        password_hash="old-hash",
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = existing

    user, created = create_admin_user(db, "staff@example.com", "new-safe-password")

    assert created is False
    assert user.role == "admin"
    assert user.is_active is True
    assert user.must_change_password is False
    assert check_password("new-safe-password", user.password_hash)
    assert user.password_hash != "old-hash"
    db.add.assert_not_called()
    db.commit.assert_called_once()


def test_existing_user_change_requires_confirmation(monkeypatch):
    existing = SimpleNamespace(email="staff@example.com", role="associate")
    db = MagicMock()
    monkeypatch.setattr(create_admin, "get_user_by_email", lambda *_: existing)
    password_prompt = MagicMock()

    result = create_admin.main(
        ["--email", "staff@example.com"],
        db_factory=lambda: db,
        input_fn=lambda _: "no",
        password_fn=password_prompt,
        output=lambda _: None,
    )

    assert result == 1
    password_prompt.assert_not_called()
    db.commit.assert_not_called()


def test_existing_user_is_changed_after_confirmation(monkeypatch):
    existing = SimpleNamespace(
        email="staff@example.com",
        role="associate",
        is_active=False,
        must_change_password=True,
        password_hash="old-hash",
    )
    db = MagicMock()
    monkeypatch.setattr(create_admin, "get_user_by_email", lambda *_: existing)
    prompts = iter(["new-safe-password", "new-safe-password"])

    result = create_admin.main(
        ["--email", "staff@example.com"],
        db_factory=lambda: db,
        input_fn=lambda _: "yes",
        password_fn=lambda _: next(prompts),
        output=lambda _: None,
    )

    assert result == 0
    assert existing.role == "admin"
    assert existing.is_active is True
    assert existing.must_change_password is False
    assert check_password("new-safe-password", existing.password_hash)
    db.commit.assert_called_once()
