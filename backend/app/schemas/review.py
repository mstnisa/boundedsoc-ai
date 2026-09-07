import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas.common import ORMModel


class ReviewIn(BaseModel):
    target_entity_type: Literal[
        "incident_severity", "mitre_suggestion", "report", "enrichment_result"
    ]
    target_entity_id: uuid.UUID
    decision: Literal["approve", "edit", "reject"]
    comment: str | None = None
    correction: str | None = None


class ReviewOut(ORMModel):
    id: uuid.UUID
    user_id: uuid.UUID
    target_entity_type: str
    target_entity_id: uuid.UUID
    decision: str
    comment: str | None
    correction: str | None
    reviewed_at: datetime


class SeverityUpdateIn(BaseModel):
    severity: Literal["low", "medium", "high", "critical"]
    reason: str
