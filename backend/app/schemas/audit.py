import uuid
from datetime import datetime
from typing import Any

from app.schemas.common import ORMModel


class AuditLogOut(ORMModel):
    id: uuid.UUID
    actor: str
    action: str
    target: str
    reason: str
    details: dict[str, Any]
    timestamp: datetime
