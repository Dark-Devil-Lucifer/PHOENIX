from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SecurityEventCreate(BaseModel):
    event_uid: str = Field(min_length=2, max_length=100)

    source_type: str = Field(
        min_length=2,
        max_length=50,
    )

    event_type: str = Field(
        min_length=2,
        max_length=100,
    )

    timestamp: datetime | None = None

    source_ip: str | None = None
    destination_ip: str | None = None

    source_port: int | None = None
    destination_port: int | None = None

    username: str | None = None
    hostname: str | None = None

    action: str | None = None
    outcome: str | None = None

    severity: str = Field(
        default="informational",
        max_length=20,
    )

    raw_event: dict[str, Any] = Field(
        default_factory=dict
    )

    normalized_data: dict[str, Any] = Field(
        default_factory=dict
    )


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_uid: str

    event_time: datetime

    event_type: str
    category: str | None

    action: str | None
    severity: str | None

    source_ip: str | None
    destination_ip: str | None

    source_port: int | None
    destination_port: int | None

    username: str | None
    process_name: str | None

    message: str | None

    raw_event: dict[str, Any] | None
    normalized_data: dict[str, Any] | None

    ingestion_time: datetime | None
