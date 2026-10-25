from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserResponse(BaseModel):
    id: UUID
    email: EmailStr
    name: str
    role: str
    is_active: bool
    created_at: datetime
    must_change_password: bool = False
    temp_password_expires_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class AssociateCreateRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=150)
    temporary_password: str = Field(min_length=12, max_length=128)


class AdminAssociateCreateRequest(BaseModel):
    email: EmailStr
    name: str | None = Field(default=None, min_length=2, max_length=150)
    full_name: str | None = Field(default=None, min_length=2, max_length=150)
    temporary_password: str | None = Field(default=None, min_length=12, max_length=128)


class TemporaryPasswordResetRequest(BaseModel):
    email: EmailStr
    temporary_password: str = Field(min_length=12, max_length=128)


class AdminTemporaryPasswordResetRequest(BaseModel):
    temporary_password: str | None = Field(default=None, min_length=12, max_length=128)


class AssociateCreatedResponse(UserResponse):
    temporary_password: str


class TemporaryPasswordResetResponse(BaseModel):
    email: EmailStr
    temporary_password: str
    must_change_password: bool
    temp_password_expires_at: datetime
