import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, Text, DateTime
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin, utcnow


class Report(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "reports"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, default=1)
    content: Mapped[str] = mapped_column(Text, nullable=False)  # markdown, always labeled AI-generated
    status: Mapped[str] = mapped_column(String(20), default="draft")  # draft|approved|rejected
    generated_by: Mapped[str] = mapped_column(String(100), default="ai")  # ai|analyst
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    model_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)

    incident: Mapped["Incident"] = relationship(back_populates="reports")
