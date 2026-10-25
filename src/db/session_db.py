from collections.abc import Generator

from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from src.core.config_core import get_settings

settings = get_settings()

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    metadata = MetaData(schema="auth")


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
