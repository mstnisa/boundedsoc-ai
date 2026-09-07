import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin


class Severity(str, enum.Enum):
    unknown = "unknown"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IncidentStatus(str, enum.Enum):
    new = "new"
    triaging = "triaging"
    investigating = "investigating"
    pending_review = "pending_review"
    closed_true_positive = "closed_true_positive"
    closed_false_positive = "closed_false_positive"


class Incident(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "incidents"

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="incident_severity"), default=Severity.unknown, nullable=False
    )
    # Human-confirmed severity always wins over the AI suggestion once set.
    severity_source: Mapped[str] = mapped_column(String(20), default="unset")  # unset|ai|analyst
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, name="incident_status"), default=IncidentStatus.new, nullable=False
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident")
    events: Mapped[list["Event"]] = relationship(back_populates="incident")
    iocs: Mapped[list["IOC"]] = relationship(back_populates="incident")
    timelines: Mapped[list["Timeline"]] = relationship(back_populates="incident")
    reports: Mapped[list["Report"]] = relationship(back_populates="incident")
    mitre_suggestions: Mapped[list["MitreSuggestion"]] = relationship(back_populates="incident")
