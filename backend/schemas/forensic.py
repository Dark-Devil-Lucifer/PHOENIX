from datetime import datetime

from pydantic import BaseModel, Field


class ForensicArtifactCreate(BaseModel):
    artifact_uid: str = Field(
        min_length=3,
        max_length=100,
    )

    case_id: int

    artifact_type: str = Field(
        min_length=2,
        max_length=100,
    )

    source: str | None = Field(
        default=None,
        max_length=255,
    )

    hash_sha256: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
    )

    evidence: dict | None = None


class ForensicArtifactResponse(BaseModel):
    id: int
    artifact_uid: str
    case_id: int
    artifact_type: str
    source: str | None
    hash_sha256: str | None
    collected_by: int | None
    collected_at: datetime | None
    evidence: dict | None

    model_config = {
        "from_attributes": True
    }
