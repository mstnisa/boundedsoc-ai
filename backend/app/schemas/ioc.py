import uuid
from datetime import datetime
from typing import Any

from app.models.ioc import IOCType
from app.schemas.common import ORMModel


class IOCOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    type: IOCType
    value: str
    first_seen: datetime


class EnrichmentResultOut(ORMModel):
    id: uuid.UUID
    ioc_id: uuid.UUID
    provider: str
    verdict: str
    confidence: float
    evidence: dict[str, Any]
    fetched_at: datetime
    is_mocked: bool


class IOCWithEnrichment(IOCOut):
    enrichment_results: list[EnrichmentResultOut] = []


class ExtractIOCsResponse(ORMModel):
    incident_id: uuid.UUID
    extracted: int
    iocs: list[IOCOut]


class EnrichResponse(ORMModel):
    incident_id: uuid.UUID
    results: list[EnrichmentResultOut]
