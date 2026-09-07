import uuid

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin


class MitreSuggestion(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "mitre_suggestions"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False, index=True
    )
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g. T1059.001
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence_refs: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    model_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)  # provider/model/prompt version

    # Human-in-the-loop status
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|approved|edited|rejected

    incident: Mapped["Incident"] = relationship(back_populates="mitre_suggestions")
