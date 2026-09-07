import uuid
from datetime import datetime
from typing import Any

from app.schemas.common import ORMModel


class TimelineEventOut(ORMModel):
    sequence: int
    event_id: uuid.UUID
    event_type: str
    source_host: str | None
    timestamp: datetime
    raw_data: dict[str, Any]


class TimelineOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    generated_at: datetime
    events: list[TimelineEventOut]
