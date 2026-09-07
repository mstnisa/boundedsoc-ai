import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin, utcnow


class Timeline(UUIDPKMixin, Base):
    __tablename__ = "timelines"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False, index=True
    )
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="timelines")
    ordered_events: Mapped[list["TimelineEvent"]] = relationship(
        back_populates="timeline", order_by="TimelineEvent.sequence"
    )


class TimelineEvent(UUIDPKMixin, Base):
    """Join entity: an event placed at a position in a timeline's ordered sequence."""

    __tablename__ = "timeline_events"

    timeline_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("timelines.id"), nullable=False, index=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("events.id"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)

    timeline: Mapped["Timeline"] = relationship(back_populates="ordered_events")
    event: Mapped["Event"] = relationship()
