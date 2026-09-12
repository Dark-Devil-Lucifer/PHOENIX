from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class HuntingQueryCreate(BaseModel):
    query_uid: str = Field(min_length=3, max_length=100)
    name: str = Field(min_length=3, max_length=255)
    description: Optional[str] = None
    query_type: str = Field(default="sql", max_length=50)
    query_text: str = Field(min_length=1)
    severity: str = Field(default="medium", max_length=20)
    enabled: bool = True


class HuntingQueryResponse(BaseModel):
    id: int
    query_uid: str
    name: str
    description: Optional[str]
    query_type: str
    query_text: str
    severity: str
    enabled: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class HuntingRunCreate(BaseModel):
    query_id: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    parameters: Optional[dict] = None


class HuntingRunResponse(BaseModel):
    id: int
    query_id: int
    executed_by: Optional[int]
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    result_count: int
    status: str
    results: Optional[dict]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True
