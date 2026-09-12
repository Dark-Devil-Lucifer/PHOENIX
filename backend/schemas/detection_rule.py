from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class DetectionRuleCreate(BaseModel):
    rule_uid: str = Field(min_length=3, max_length=100)
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    rule_type: str = Field(default="event", max_length=50)
    severity: str = Field(default="medium", max_length=20)
    confidence: int = Field(default=70, ge=0, le=100)
    query: Optional[dict] = None
    recommended_response: Optional[str] = None
    enabled: bool = True


class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=255)
    description: Optional[str] = None
    severity: Optional[str] = Field(default=None, max_length=20)
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    query: Optional[dict] = None
    recommended_response: Optional[str] = None
    enabled: Optional[bool] = None


class DetectionRuleResponse(BaseModel):
    id: int
    rule_uid: str
    name: str
    description: Optional[str]
    rule_type: str
    severity: str
    confidence: int
    query: Optional[dict]
    recommended_response: Optional[str]
    enabled: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
