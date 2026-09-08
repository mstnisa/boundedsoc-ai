import uuid

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin


class ComplianceMapping(UUIDPKMixin, TimestampMixin, Base):
    """
    Maps an already-approved finding (currently: an approved/edited MITRE
    suggestion) to a control in a compliance framework. Informational
    mapping only — see docs/business-value.md and the UI copy: this is
    explicitly never presented as a certification.
    """

    __tablename__ = "compliance_mappings"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False, index=True
    )
    finding_type: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g. "mitre_suggestion"
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    framework: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # owasp_top10|pci_dss|...
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)
    control_title: Mapped[str] = mapped_column(String(500), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_refs: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
