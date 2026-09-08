import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas.common import ORMModel

Framework = Literal["owasp_top10", "pci_dss", "iso27001", "gdpr"]


class ComplianceMappingOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    finding_type: str
    finding_id: uuid.UUID
    framework: str
    control_id: str
    control_title: str
    confidence: float
    rationale: str
    evidence_refs: list[str]
    created_at: datetime


class ComplianceMappingRequest(BaseModel):
    framework: Framework


class ComplianceMappingResponse(ORMModel):
    incident_id: uuid.UUID
    framework: str
    mappings: list[ComplianceMappingOut]


class ComplianceCoverageOut(BaseModel):
    coverage: dict[str, dict[str, int]]
