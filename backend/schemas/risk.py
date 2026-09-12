from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class RiskCreate(BaseModel):
    risk_uid: str = Field(min_length=3, max_length=100)
    title: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    category: str = Field(min_length=1, max_length=100)
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    owner: Optional[str] = None
    treatment: Optional[str] = None
    status: str = "open"
    due_date: Optional[datetime] = None
    metadata: Optional[dict] = None


class RiskUpdate(BaseModel):
    likelihood: Optional[int] = Field(default=None, ge=1, le=5)
    impact: Optional[int] = Field(default=None, ge=1, le=5)
    severity: Optional[str] = None
    owner: Optional[str] = None
    treatment: Optional[str] = None
    status: Optional[str] = None
    due_date: Optional[datetime] = None
    metadata: Optional[dict] = None


class RiskResponse(BaseModel):
    id: int
    risk_uid: str
    title: str
    description: Optional[str]
    category: str
    likelihood: int
    impact: int
    risk_score: int
    severity: str
    owner: Optional[str]
    treatment: Optional[str]
    status: str
    due_date: Optional[datetime]
    metadata: Optional[dict]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
