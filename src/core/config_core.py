from functools import lru_cache
from typing import Literal, cast

from dotenv import load_dotenv
from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv()


class Settings(BaseSettings):
    app_name: str = "GenWorx AP Auth Service"
    app_env: str = "local"
    log_level: str = "INFO"

    database_url: str = (
        "postgresql+psycopg://genworx_app:CHANGE_ME@localhost:5432/genworx_ap"
    )
    jwt_secret_key: SecretStr = SecretStr("CHANGE_ME_TO_A_LONG_RANDOM_SECRET")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 5
    refresh_token_expire_days: int = 7
    auth_persistent_session: bool = False
    temp_password_ttl_hours: int = 24
    login_max_attempts: int = 5
    login_window_minutes: int = 15
    login_lockout_minutes: int = 15
    refresh_cookie_name: str = "ap_refresh"
    refresh_cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    refresh_cookie_domain: str | None = None
    refresh_cookie_path: str = "/api/auth"
    cors_allowed_origins: str = (
        "http://localhost:3000,http://127.0.0.1:3000,"
        "http://localhost:5173,http://127.0.0.1:5173"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("refresh_cookie_samesite")
    @classmethod
    def validate_cookie_samesite(cls, value: str) -> Literal["lax", "strict", "none"]:
        normalized = value.lower()
        if normalized not in {"lax", "strict", "none"}:
            raise ValueError("REFRESH_COOKIE_SAMESITE must be lax, strict, or none")
        return cast(Literal["lax", "strict", "none"], normalized)

    @field_validator("refresh_cookie_domain", mode="before")
    @classmethod
    def normalize_cookie_domain(cls, value: str | None) -> str | None:
        return value.strip() or None if isinstance(value, str) else value


@lru_cache
def get_settings() -> Settings:
    return Settings()
