from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class SensitiveResourceCreate(BaseModel):
    resource_uid: str = Field(min_length=3, max_length=100)
    name: str = Field(min_length=1, max_length=255)
    resource_type: str = Field(min_length=1, max_length=100)
    location: Optional[str] = Field(default=None, max_length=500)
    classification: str = Field(default="confidential", max_length=50)
    owner: Optional[str] = Field(default=None, max_length=255)
    description: Optional[str] = None
    enabled: bool = True


class SensitiveResourceResponse(BaseModel):
    id: int
    resource_uid: str
    name: str
    resource_type: str
    location: Optional[str]
    classification: str
    owner: Optional[str]
    description: Optional[str]
    enabled: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class DLPEventCreate(BaseModel):
    event_uid: str = Field(min_length=3, max_length=100)
    resource_id: Optional[int] = None
    event_type: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=100)
    username: Optional[str] = Field(default=None, max_length=255)
    source_ip: Optional[str] = Field(default=None, max_length=45)
    destination: Optional[str] = Field(default=None, max_length=500)
    data_classification: Optional[str] = Field(
        default=None,
        max_length=50,
    )
    bytes_transferred: Optional[int] = Field(
        default=None,
        ge=0,
    )
    policy_result: str = Field(
        default="allowed",
        max_length=50,
    )
    severity: str = Field(
        default="medium",
        max_length=20,
    )
    event_time: datetime
    description: Optional[str] = None
    metadata: Optional[dict] = None


class DLPEventResponse(BaseModel):
    id: int
    resource_id: Optional[int]
    event_uid: str
    event_type: str
    action: str
    username: Optional[str]
    source_ip: Optional[str]
    destination: Optional[str]
    data_classification: Optional[str]
    bytes_transferred: Optional[int]
    policy_result: str
    severity: str
    event_time: datetime
    description: Optional[str]
    metadata: Optional[dict]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class DLPAssessmentResponse(BaseModel):
    event_id: int
    risk_score: int
    risk_level: str
    triggered: bool
    reasons: list[str]
    recommended_action: str
