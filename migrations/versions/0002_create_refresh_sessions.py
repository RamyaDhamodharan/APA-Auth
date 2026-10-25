"""Create hashed server-side refresh sessions when absent."""

import sqlalchemy as sa
from alembic import context, op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if not context.is_offline_mode() and sa.inspect(op.get_bind()).has_table(
        "refresh_sessions", schema="auth"
    ):
        return
    op.execute(
        """
        CREATE TABLE auth.refresh_sessions (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id uuid NOT NULL REFERENCES auth.users(id),
          token_hash varchar(255) NOT NULL UNIQUE,
          expires_at timestamptz NOT NULL,
          is_revoked boolean NOT NULL DEFAULT false,
          revoked_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now(),
          created_by uuid REFERENCES auth.users(id),
          updated_at timestamptz NOT NULL DEFAULT now(),
          updated_by uuid REFERENCES auth.users(id)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_refresh_user_revoked "
        "ON auth.refresh_sessions (user_id, is_revoked)"
    )


def downgrade() -> None:
    pass
