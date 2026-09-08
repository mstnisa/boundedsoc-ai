import uuid
from datetime import datetime

from app.schemas.common import ORMModel


class SecretExposureAlertOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    secret_type: str
    masked_value: str
    source_ref: str
    provider: str
    status: str
    approved_by: str | None
    approved_at: datetime | None
    revoked_at: datetime | None
    escalation_deadline: datetime | None
    created_at: datetime
