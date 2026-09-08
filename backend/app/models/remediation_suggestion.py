import uuid

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin


class RemediationSuggestion(UUIDPKMixin, TimestampMixin, Base):
    """
    An AI-drafted code fix for a finding tied to an incident. It never
    merges anything — approving a suggestion only unlocks a *separate*,
    explicit "create PR" action (services.mcp_gateway), so approving in the
    review queue can never silently write to a repo.
    """

    __tablename__ = "remediation_suggestions"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False, index=True
    )
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    vulnerable_snippet: Mapped[str] = mapped_column(Text, nullable=False)
    proposed_patch: Mapped[str] = mapped_column(Text, nullable=False)
    cwe_ref: Mapped[str | None] = mapped_column(String(20), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_refs: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|approved|edited|rejected
    pr_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
