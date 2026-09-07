import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class WazuhAlertIn(BaseModel):
    """
    Accepts a Wazuh-style alert. We keep this permissive (extra fields
    allowed) because real Wazuh payloads vary widely — normalization.py is
    responsible for pulling out what we need and treating everything else as
    untrusted, opaque data.
    """

    model_config = {"extra": "allow"}

    rule: dict[str, Any] = Field(default_factory=dict)
    agent: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    full_log: str | None = None
    timestamp: str | None = None


class AlertIngestRequest(BaseModel):
    source: str = "wazuh-synthetic"
    alerts: list[WazuhAlertIn]


class AlertOut(ORMModel):
    id: uuid.UUID
    source: str
    normalized_payload: dict[str, Any]
    received_at: datetime
    incident_id: uuid.UUID | None = None


class AlertIngestResponse(BaseModel):
    ingested: int
    alert_ids: list[uuid.UUID]
    incident_id: uuid.UUID
