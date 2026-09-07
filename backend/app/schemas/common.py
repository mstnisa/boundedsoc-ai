from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())


class EvidenceRef(ORMModel):
    source: str
    detail: dict[str, Any] = {}
    timestamp: datetime
    confidence: float
