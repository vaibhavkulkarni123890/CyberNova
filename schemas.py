from pydantic import BaseModel, EmailStr, constr, field_validator
from datetime import datetime
from typing import Optional, Literal


# ---------------------- USER MODELS ----------------------
class UserCreate(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    company: str
    password: constr(min_length=6)  # Ensure strong password


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    first_name: str
    last_name: str
    company: str
    is_active: bool
    created_at: datetime

    model_config = {
        "from_attributes": True  # Pydantic v2
    }


# ---------------------- WAITLIST MODELS ----------------------
class WaitlistCreate(BaseModel):
    email: EmailStr


# ---------------------- SECURITY EVENT MODELS ----------------------
class SecurityEventCreate(BaseModel):
    event_type: str
    severity: Literal["low", "medium", "high", "critical"]
    description: Optional[str] = None
    source_ip: Optional[str] = None
    metadata: Optional[str] = None

    @field_validator("event_type")
    def validate_event_type(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("event_type cannot be empty")
        return v


class SecurityEventResponse(BaseModel):
    id: int
    user_id: int
    event_type: str
    severity: str
    description: Optional[str]
    source_ip: Optional[str]
    metadata: Optional[str]
    created_at: datetime

    model_config = {
        "from_attributes": True
    }
