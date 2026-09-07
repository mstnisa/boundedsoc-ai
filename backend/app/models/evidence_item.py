import uuid
from datetime import datetime

from sqlalchemy import Float, String, DateTime
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin, utcnow


class EvidenceItem(UUIDPKMixin, TimestampMixin, Base):
    """
    Polymorphic provenance record. Every AI-generated claim (severity, MITRE
    suggestion, report statement, ...) must point to at least one of these.
    related_entity_type/id identify the claim this evidence supports.
    """

    __tablename__ = "evidence_items"

    related_entity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    related_entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. "event:<id>", "enrichment:<id>"
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
