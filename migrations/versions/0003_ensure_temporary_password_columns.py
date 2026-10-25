"""Ensure temporary password workflow columns exist on pre-existing auth tables."""

import sqlalchemy as sa
from alembic import context, op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if context.is_offline_mode():
        op.add_column(
            "users",
            sa.Column(
                "must_change_password",
                sa.Boolean(),
                server_default=sa.text("false"),
                nullable=False,
            ),
            schema="auth",
        )
        op.add_column(
            "users",
            sa.Column(
                "temp_password_expires_at", sa.DateTime(timezone=True), nullable=True
            ),
            schema="auth",
        )
        return

    inspector = sa.inspect(op.get_bind())
    columns = {
        column["name"] for column in inspector.get_columns("users", schema="auth")
    }
    if "must_change_password" not in columns:
        op.add_column(
            "users",
            sa.Column(
                "must_change_password",
                sa.Boolean(),
                server_default=sa.text("false"),
                nullable=False,
            ),
            schema="auth",
        )
    if "temp_password_expires_at" not in columns:
        op.add_column(
            "users",
            sa.Column(
                "temp_password_expires_at", sa.DateTime(timezone=True), nullable=True
            ),
            schema="auth",
        )


def downgrade() -> None:
    pass
