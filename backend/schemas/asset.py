from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AssetCreate(BaseModel):
    asset_uid: str = Field(min_length=2, max_length=100)
    hostname: str = Field(min_length=1, max_length=255)
    asset_type: str = Field(min_length=1, max_length=50)

    ip_address: str | None = None
    operating_system: str | None = None

    environment: str = Field(default="production", max_length=50)
    criticality: str = Field(default="medium", max_length=20)

    owner: str | None = None
    location: str | None = None

    status: str = Field(default="active", max_length=30)


class AssetUpdate(BaseModel):
    hostname: str | None = Field(default=None, max_length=255)
    asset_type: str | None = Field(default=None, max_length=50)

    ip_address: str | None = None
    operating_system: str | None = None

    environment: str | None = Field(default=None, max_length=50)
    criticality: str | None = Field(default=None, max_length=20)

    owner: str | None = None
    location: str | None = None

    status: str | None = Field(default=None, max_length=30)


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_uid: str
    hostname: str
    asset_type: str

    ip_address: str | None
    operating_system: str | None

    environment: str
    criticality: str

    owner: str | None
    location: str | None

    status: str

    first_seen_at: datetime | None
    last_seen_at: datetime | None

    created_at: datetime
    updated_at: datetime
