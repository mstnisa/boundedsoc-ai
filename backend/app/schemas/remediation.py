import uuid
from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import ORMModel


class RemediationSuggestionOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    repo_full_name: str
    file_path: str
    vulnerable_snippet: str
    proposed_patch: str
    cwe_ref: str | None
    confidence: float
    rationale: str
    evidence_refs: list[str]
    status: str
    pr_url: str | None
    created_at: datetime


class RemediationDraftRequest(BaseModel):
    repo_full_name: str = "example-org/example-repo"
