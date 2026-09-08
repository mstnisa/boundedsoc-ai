import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin


class SecretExposureAlert(UUIDPKMixin, TimestampMixin, Base):
    """
    A detected leaked-credential finding. The raw secret is NEVER stored —
    only a masked value (prefix + hash suffix). Revocation requires
    status=='approved', enforced server-side in services.secret_exposure,
    not just hidden in the UI. Escalation (if configured) only notifies —
    it never auto-revokes.
    """

    __tablename__ = "secret_exposure_alerts"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False, index=True
    )
    secret_type: Mapped[str] = mapped_column(String(50), nullable=False)  # aws_key|github_token|generic_...
    masked_value: Mapped[str] = mapped_column(String(100), nullable=False)
    source_ref: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. "event:<id>"
    provider: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g. "github", "aws"
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|approved|revoked|rejected
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    escalation_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
