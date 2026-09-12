from typing import Any

from pydantic import BaseModel, Field


class KubernetesClusterCreate(BaseModel):
    cluster_uid: str = Field(min_length=2, max_length=100)
    name: str = Field(min_length=2, max_length=255)
    environment: str | None = None
    version: str | None = None
    api_endpoint: str | None = None


class ContainerImageCreate(BaseModel):
    image_uid: str = Field(min_length=2, max_length=100)
    repository: str = Field(min_length=2, max_length=255)
    tag: str | None = None
    digest: str | None = None
    registry: str | None = None


class ContainerFindingCreate(BaseModel):
    finding_uid: str = Field(min_length=2, max_length=100)
    image_id: int
    cve_id: str | None = None
    title: str = Field(min_length=2, max_length=255)
    severity: str
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    remediation: str | None = None


class KubernetesWorkloadCreate(BaseModel):
    workload_uid: str = Field(min_length=2, max_length=100)
    cluster_id: int

    namespace: str = Field(min_length=1, max_length=255)
    workload_name: str = Field(min_length=1, max_length=255)

    workload_type: str | None = None
    image_id: int | None = None

    baseline: dict[str, Any] | None = None
    observed_state: dict[str, Any] | None = None
