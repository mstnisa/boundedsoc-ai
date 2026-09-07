import enum
import uuid
from datetime import datetime

from sqlalchemy import Enum, ForeignKey, String, UniqueConstraint, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin, utcnow


class IOCType(str, enum.Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash_md5 = "hash_md5"
    hash_sha1 = "hash_sha1"
    hash_sha256 = "hash_sha256"
    username = "username"


class IOC(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("incident_id", "type", "value", name="uq_ioc_per_incident"),)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False, index=True
    )
    type: Mapped[IOCType] = mapped_column(Enum(IOCType, name="ioc_type"), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="iocs")
    enrichment_results: Mapped[list["EnrichmentResult"]] = relationship(back_populates="ioc")
