"""Track failed logins per email and IP address."""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "login_attempts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("client_ip", sa.String(length=64), nullable=False),
        sa.Column(
            "failed_count", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email", "client_ip", name="uq_login_email_ip"),
        schema="auth",
    )


def downgrade() -> None:
    op.drop_table("login_attempts", schema="auth")
