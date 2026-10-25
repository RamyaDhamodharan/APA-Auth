"""Ensure auth role and account-state columns exist on the shared users table."""

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    role_type = postgresql.ENUM(
        "associate",
        "admin",
        name="user_role",
        schema="auth",
        create_type=False,
    )
    if context.is_offline_mode():
        op.execute(sa.schema.CreateSchema("auth", if_not_exists=True))
        op.execute(postgresql.CreateEnumType(role_type))
        op.add_column(
            "users",
            sa.Column(
                "role",
                role_type,
                nullable=False,
                server_default=sa.text("'associate'"),
            ),
            schema="auth",
        )
        op.add_column(
            "users",
            sa.Column(
                "is_active", sa.Boolean(), nullable=False, server_default=sa.true()
            ),
            schema="auth",
        )
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("users", schema="auth"):
        return

    role_type.create(bind, checkfirst=True)
    existing_enums = {
        enum["name"]: enum["labels"] for enum in inspector.get_enums(schema="auth")
    }
    for label in ("associate", "admin"):
        if label not in existing_enums.get("user_role", []):
            op.execute(f"ALTER TYPE auth.user_role ADD VALUE IF NOT EXISTS '{label}'")
    columns = {
        column["name"] for column in inspector.get_columns("users", schema="auth")
    }
    if "role" not in columns:
        op.add_column(
            "users",
            sa.Column(
                "role",
                role_type,
                nullable=False,
                server_default=sa.text("'associate'"),
            ),
            schema="auth",
        )
    if "is_active" not in columns:
        op.add_column(
            "users",
            sa.Column(
                "is_active", sa.Boolean(), nullable=False, server_default=sa.true()
            ),
            schema="auth",
        )
    if "must_change_password" not in columns:
        op.add_column(
            "users",
            sa.Column(
                "must_change_password",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
            schema="auth",
        )
    if "temp_password_expires_at" not in columns:
        op.add_column(
            "users",
            sa.Column("temp_password_expires_at", sa.DateTime(timezone=True)),
            schema="auth",
        )


def downgrade() -> None:
    # Shared auth.users may be referenced by AP-Core; keep this migration additive.
    pass
