from typing import Any

from pydantic import BaseModel, Field


class CloudAccountCreate(BaseModel):
    account_uid: str = Field(min_length=2, max_length=100)
    provider: str = Field(min_length=2, max_length=50)
    account_name: str = Field(min_length=2, max_length=255)
    account_identifier: str | None = None
    environment: str = "production"


class CloudAssetCreate(BaseModel):
    cloud_asset_uid: str = Field(min_length=2, max_length=100)
    cloud_account_id: int

    resource_type: str = Field(min_length=2, max_length=100)
    resource_name: str | None = None
    region: str | None = None

    criticality: str = "medium"

    configuration: dict[str, Any] | None = None


class CloudFindingCreate(BaseModel):
    finding_uid: str = Field(min_length=2, max_length=100)
    cloud_asset_id: int

    title: str = Field(min_length=2, max_length=255)
    description: str | None = None

    severity: str

    control_id: str | None = None
    remediation: str | None = None
