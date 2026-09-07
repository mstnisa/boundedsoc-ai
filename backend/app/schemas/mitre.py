import uuid

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class MitreTechniqueClaim(BaseModel):
    """Structured-output schema the LLM MUST fill in — no free text allowed.
    evidence_refs is mandatory and non-empty: an AI claim without provenance
    is dropped before it ever reaches the database (see app.ai.guardrails).
    """

    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str
    rationale: str = Field(min_length=10)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(min_length=1)


class MitreSuggestionOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    technique_id: str
    technique_name: str
    rationale: str
    confidence: float
    evidence_refs: list[str]
    status: str
    model_metadata: dict


class MitreSuggestionResponse(ORMModel):
    incident_id: uuid.UUID
    suggestions: list[MitreSuggestionOut]
