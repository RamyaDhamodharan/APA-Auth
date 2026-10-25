from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

from src.core.config_core import get_settings
from src.db.session_db import Base
from src.models.login_attempt_models import LoginAttempt  # noqa: F401
from src.models.refresh_session_models import RefreshSession  # noqa: F401
from src.models.user_models import User  # noqa: F401

# Alembic configuration
config = context.config

config.set_main_option(
    "sqlalchemy.url",
    get_settings().database_url.replace("%", "%%"),
)

# Configure logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# SQLAlchemy models metadata
target_metadata = Base.metadata

# Keep AP-Auth migration tracking separate from AP-Core.
AUTH_VERSION_TABLE = "auth_alembic_version"

# AP-Auth owns the users and refresh session tables.
# This prevents Alembic from treating AP-Core tables as removed.
AUTH_TABLES = {"users", "refresh_sessions", "login_attempts"}


def include_name(name, type_, parent_names):
    """Include only tables owned by AP-Auth during autogeneration."""
    if type_ == "schema":
        return name == "auth"
    if type_ == "table":
        return name in AUTH_TABLES and parent_names.get("schema_name") == "auth"
    return True


def run_migrations_offline() -> None:
    """Run migrations without creating an Engine."""
    url = config.get_main_option("sqlalchemy.url")

    context.configure(
        url=url,
        target_metadata=target_metadata,
        compare_type=True,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table=AUTH_VERSION_TABLE,
        version_table_schema="auth",
        include_schemas=True,
        include_name=include_name,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations using a live database connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        connection.execute(text("CREATE SCHEMA IF NOT EXISTS auth"))
        connection.commit()
        connection.execute(text("SET search_path TO auth, public"))
        connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            version_table=AUTH_VERSION_TABLE,
            version_table_schema="auth",
            include_schemas=True,
            include_name=include_name,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
