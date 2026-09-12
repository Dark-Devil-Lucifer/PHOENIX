from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_uid: str
    detection_rule_id: int | None
    asset_id: int | None
    title: str
    description: str | None
    severity: str
    confidence: int
    status: str
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime
