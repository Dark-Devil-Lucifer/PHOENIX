from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class CaseResponse(BaseModel):
    id: int
    case_uid: str
    incident_id: Optional[int]
    title: str
    description: Optional[str]
    status: str
    priority: int
    assigned_to: Optional[int]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class CaseUpdate(BaseModel):
    status: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=30,
    )

    priority: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
    )

    assigned_to: Optional[int] = None

    description: Optional[str] = None


class CaseEvidenceCreate(BaseModel):
    evidence_type: str = Field(
        min_length=1,
        max_length=100,
    )

    reference_type: str = Field(
        min_length=1,
        max_length=100,
    )

    reference_id: Optional[int] = None

    description: Optional[str] = None


class CaseEvidenceResponse(BaseModel):
    id: int
    case_id: int
    evidence_type: str
    reference_type: str
    reference_id: Optional[str]
    description: Optional[str]
    added_by: Optional[int]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True
