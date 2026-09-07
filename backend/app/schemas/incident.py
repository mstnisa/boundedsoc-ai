import uuid
from datetime import datetime

from app.models.incident import IncidentStatus, Severity
from app.schemas.common import ORMModel


class IncidentSummary(ORMModel):
    id: uuid.UUID
    title: str
    severity: Severity
    severity_source: str
    status: IncidentStatus
    created_at: datetime
    closed_at: datetime | None = None


class IncidentDetail(IncidentSummary):
    alert_count: int = 0
    event_count: int = 0
    ioc_count: int = 0
