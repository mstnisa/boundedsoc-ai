import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin, utcnow


class Alert(UUIDPKMixin, TimestampMixin, Base):
    """Raw ingested alert (Wazuh-style JSON) plus its normalized form."""

    __tablename__ = "alerts"

    source: Mapped[str] = mapped_column(String(100), nullable=False, default="wazuh-synthetic")
    raw_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    normalized_payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True, index=True
    )

    incident: Mapped["Incident"] = relationship(back_populates="alerts")
