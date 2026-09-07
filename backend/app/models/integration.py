from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin


class Integration(UUIDPKMixin, TimestampMixin, Base):
    """A configured adapter, e.g. a threat-intel provider or LLM provider."""

    __tablename__ = "integrations"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # threat_intel|llm|siem
    config_ref: Mapped[str] = mapped_column(String(255), nullable=False)  # env var name, never the secret itself
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
