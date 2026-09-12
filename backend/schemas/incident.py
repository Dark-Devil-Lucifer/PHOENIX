from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_uid: str
    title: str
    description: str | None
    severity: str
    status: str | None
    priority: int | None
    assigned_to: int | None
    detected_at: datetime | None
    contained_at: datetime | None
    resolved_at: datetime | None
    created_at: datetime | None
    updated_at: datetime | None


class InvestigationAlert(BaseModel):
    id: int
    alert_uid: str
    title: str
    description: str | None
    severity: str
    confidence: int
    status: str
    asset_id: int | None
    detection_rule_id: int | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None


class InvestigationEvent(BaseModel):
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
    normalized_data: dict[str, Any] | None


class InvestigationTimelineEntry(BaseModel):
    id: int
    event_type: str
    description: str
    actor_type: str | None
    actor_id: int | None
    occurred_at: datetime | None
    metadata: dict[str, Any] | None


class IncidentInvestigationResponse(BaseModel):
    incident: IncidentResponse
    alerts: list[InvestigationAlert]
    events: list[InvestigationEvent]
    timeline: list[InvestigationTimelineEntry]
