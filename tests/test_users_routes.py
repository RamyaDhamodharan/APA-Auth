from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from src.api.rest.routes.users_routes import list_associates, remove_associate
from src.models.user_models import User


def test_list_associates_returns_admin_query_results():
    admin = SimpleNamespace(role="admin")
    associates = [SimpleNamespace(name="A", is_active=True)]
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.all.return_value = (
        associates
    )

    assert list_associates(db, admin) == associates
    db.query.assert_called_once_with(User)


def test_remove_associate_deactivates_user_and_revokes_refresh_sessions():
    associate = SimpleNamespace(
        id=uuid4(), role="associate", is_active=True, updated_at=None, updated_by=None
    )
    admin = SimpleNamespace(id=uuid4())
    db = MagicMock()
    db.get.return_value = associate

    assert remove_associate(associate.id, db, admin) is None

    assert associate.is_active is False
    assert associate.updated_by == admin.id
    db.query.return_value.filter.return_value.update.assert_called_once()
    db.commit.assert_called_once()


def test_remove_associate_does_not_remove_admin():
    admin_user = SimpleNamespace(id=uuid4(), role="admin", is_active=True)
    db = MagicMock()
    db.get.return_value = admin_user

    with pytest.raises(HTTPException) as error:
        remove_associate(admin_user.id, db, SimpleNamespace(id=uuid4()))

    assert error.value.status_code == 404
    db.commit.assert_not_called()
