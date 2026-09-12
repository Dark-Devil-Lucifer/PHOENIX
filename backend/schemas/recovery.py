from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class BackupJobCreate(BaseModel):
    job_uid: str = Field(min_length=3, max_length=100)
    name: str = Field(min_length=1, max_length=255)
    target_type: str = Field(min_length=1, max_length=100)
    target_reference: str = Field(min_length=1, max_length=500)
    schedule: Optional[str] = None
    backup_type: str = Field(default="incremental", max_length=50)
    retention_days: int = Field(default=30, ge=1, le=3650)


class BackupJobResponse(BaseModel):
    id: int
    job_uid: str
    name: str
    target_type: str
    target_reference: str
    schedule: Optional[str]
    backup_type: str
    retention_days: int
    status: str
    last_run_at: Optional[datetime]
    last_success_at: Optional[datetime]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class RecoveryTestCreate(BaseModel):
    test_uid: str = Field(min_length=3, max_length=100)
    backup_job_id: Optional[int] = None
    name: str = Field(min_length=1, max_length=255)
    recovery_type: str = Field(min_length=1, max_length=100)
    target_reference: str = Field(min_length=1, max_length=500)
    rto_minutes: Optional[int] = Field(default=None, ge=1)
    rpo_minutes: Optional[int] = Field(default=None, ge=1)
    notes: Optional[str] = None


class RecoveryTestUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=50)
    findings: Optional[dict] = None
    notes: Optional[str] = None
    rto_minutes: Optional[int] = Field(default=None, ge=1)
    rpo_minutes: Optional[int] = Field(default=None, ge=1)


class RecoveryTestResponse(BaseModel):
    id: int
    test_uid: str
    backup_job_id: Optional[int]
    name: str
    recovery_type: str
    target_reference: str
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    rto_minutes: Optional[int]
    rpo_minutes: Optional[int]
    findings: Optional[dict]
    notes: Optional[str]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True
