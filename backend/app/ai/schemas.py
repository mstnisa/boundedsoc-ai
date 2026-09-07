"""Pydantic schemas the LangGraph parse node validates raw LLM JSON against.
These are intentionally strict — validation failure means the claim is
discarded (see app.services.ai_orchestration), never coerced or guessed."""

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.mitre import MitreTechniqueClaim
from app.schemas.report import ReportDraft


class SeverityClaim(BaseModel):
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=10)
    evidence_refs: list[str] = Field(min_length=1)


class MitreSuggestionsResponse(BaseModel):
    suggestions: list[MitreTechniqueClaim]


ReportDraftResponse = ReportDraft
