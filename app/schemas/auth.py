"""
Pydantic schemas for Authentication endpoints.
"""

from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator


class UserRegisterRequest(BaseModel):
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    password: str
    role: Optional[str] = "viewer"

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username must contain only letters, numbers, hyphens, or underscores")
        if len(v) < 3 or len(v) > 50:
            raise ValueError("Username must be between 3 and 50 characters")
        return v.lower()

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        allowed = {"admin", "security_analyst", "viewer"}
        if v not in allowed:
            raise ValueError(f"Role must be one of: {allowed}")
        return v


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int     # seconds until expiry


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: Optional[str]
    role: str
    is_active: bool

    model_config = {"from_attributes": True}


class UserUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
