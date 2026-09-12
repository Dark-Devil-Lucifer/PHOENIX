from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class SIEMSearchRequest(BaseModel):
    query: Optional[str] = None
    event_type: Optional[str] = None
    category: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(
        default=100,
        ge=1,
        le=500,
    )


class SIEMSearchResponse(BaseModel):
    total: int
    events: list[dict]


class SIEMCorrelationRequest(BaseModel):
    event_ids: list[int] = Field(
        min_length=1,
        max_length=100,
    )
    correlation_name: str = Field(
        min_length=3,
        max_length=255,
    )


class SIEMCorrelationResponse(BaseModel):
    correlation_name: str
    matched: bool
    event_count: int
    severity: str
    confidence: int
    timeline: list[dict]
    findings: list[str]
