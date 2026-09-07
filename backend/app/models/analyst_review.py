import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import UUIDPKMixin, utcnow


class AnalystReview(UUIDPKMixin, Base):
    """A human decision on an AI-generated claim: approve / edit / reject."""

    __tablename__ = "analyst_reviews"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )
    target_entity_type: Mapped[str] = mapped_column(String(50), nullable=False)  # incident|mitre_suggestion|report|...
    target_entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)  # approve|edit|reject
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    correction: Mapped[str | None] = mapped_column(Text, nullable=True)  # edited value, if decision == edit
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped["User"] = relationship(back_populates="reviews")
