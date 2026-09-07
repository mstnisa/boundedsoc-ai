import uuid
from datetime import datetime

from sqlalchemy import Float, ForeignKey, String, DateTime
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin, utcnow


class EnrichmentResult(UUIDPKMixin, TimestampMixin, Base):
    """A single threat-intel lookup result for one IOC, from one provider."""

    __tablename__ = "enrichment_results"

    ioc_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("iocs.id"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    verdict: Mapped[str] = mapped_column(String(50), nullable=False)  # malicious|suspicious|benign|unknown
    confidence: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0 - 1.0
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    is_mocked: Mapped[bool] = mapped_column(default=True)

    ioc: Mapped["IOC"] = relationship(back_populates="enrichment_results")
