from datetime import datetime

from pydantic import BaseModel, Field


class EndpointCreate(BaseModel):
    endpoint_uid: str = Field(min_length=2, max_length=100)
    asset_id: int

    hostname: str = Field(min_length=2, max_length=255)

    operating_system: str | None = None
    agent_version: str | None = None

    isolation_status: str = "connected"
    protection_status: str = "protected"


class EndpointEventCreate(BaseModel):
    endpoint_id: int

    event_type: str = Field(min_length=2, max_length=100)

    process_name: str | None = None
    process_path: str | None = None
    command_line: str | None = None

    username: str | None = None
    parent_process: str | None = None

    hash_sha256: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
    )

    severity: str = "informational"

    event_time: datetime

    metadata: dict | None = None


class EndpointIsolationRequest(BaseModel):
    endpoint_id: int
    reason: str = Field(min_length=3, max_length=500)
