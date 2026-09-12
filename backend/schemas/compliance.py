from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ComplianceControlCreate(BaseModel):
    control_uid: str = Field(min_length=3, max_length=100)
    framework: str = Field(min_length=1, max_length=100)
    control_id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    owner: Optional[str] = None
    evidence: Optional[dict] = None


class ComplianceAssessmentUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=50)
    assessment_notes: Optional[str] = None
    evidence: Optional[dict] = None


class ComplianceControlResponse(BaseModel):
    id: int
    control_uid: str
    framework: str
    control_id: str
    title: str
    description: Optional[str]
    status: str
    owner: Optional[str]
    evidence: Optional[dict]
    assessment_notes: Optional[str]
    assessed_at: Optional[datetime]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
