import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class ReportSection(BaseModel):
    """Structured-output schema for one section of the LLM-drafted report."""

    heading: str
    body: str
    evidence_refs: list[str] = Field(default_factory=list)


class ReportDraft(BaseModel):
    executive_summary: str
    severity_assessment: str
    sections: list[ReportSection]
    disclaimer: str = (
        "This report was drafted by an AI system and has not yet been reviewed "
        "or approved by a human analyst. Do not use for response decisions."
    )


class ReportOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    version: int
    content: str
    status: str
    generated_by: str
    generated_at: datetime
    model_metadata: dict
