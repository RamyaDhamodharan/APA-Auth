import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ENUM, UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.db.session_db import Base


class User(Base):
    __tablename__ = "users"

    __table_args__ = (UniqueConstraint("email", name="users_email_key"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    name: Mapped[str] = mapped_column(String, nullable=False)

    email: Mapped[str] = mapped_column(String, nullable=False)

    role: Mapped[str] = mapped_column(
        ENUM(
            "associate",
            "admin",
            name="user_role",
            schema="auth",
            create_type=False,
        ),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )

    password_hash: Mapped[str] = mapped_column(String, nullable=False)

    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )

    temp_password_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    failed_login_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )

    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", name="users_created_by_fkey"),
        nullable=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", name="users_updated_by_fkey"),
        nullable=True,
    )
