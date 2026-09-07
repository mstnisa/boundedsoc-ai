from datetime import datetime

from sqlalchemy import String, Text, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import UUIDPKMixin, utcnow


class AuditLog(UUIDPKMixin, Base):
    """
    Append-only audit trail. Nothing in this application ever UPDATEs or
    DELETEs a row here — see app.services.audit for the only writer.
    """

    __tablename__ = "audit_logs"

    actor: Mapped[str] = mapped_column(String(255), nullable=False)  # user email, "system", or "ai:<model>"
    action: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g. "incident.severity.suggest"
    target: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. "incident:<id>"
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
