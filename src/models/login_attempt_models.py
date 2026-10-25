from datetime import datetime

from sqlalchemy import DateTime, Integer, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from src.db.session_db import Base


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    __table_args__ = (UniqueConstraint("email", "client_ip", name="uq_login_email_ip"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    client_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    failed_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    window_started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
