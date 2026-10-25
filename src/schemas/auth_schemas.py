from pydantic import BaseModel, EmailStr, Field, field_validator


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password_strength(cls, value: str) -> str:
        if not any(char.islower() for char in value):
            raise ValueError("New password must include a lowercase letter")
        if not any(char.isupper() for char in value):
            raise ValueError("New password must include an uppercase letter")
        if not any(char.isdigit() for char in value):
            raise ValueError("New password must include a number")
        if not any(not char.isalnum() for char in value):
            raise ValueError("New password must include a symbol")
        return value


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    must_change_password: bool = False


class MessageResponse(BaseModel):
    message: str
