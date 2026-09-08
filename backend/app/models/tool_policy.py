from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin, utcnow


class ToolAccessPolicy(UUIDPKMixin, TimestampMixin, Base):
    """
    What an AI-initiated tool call is allowed to do. This is the ONLY table
    services.mcp_gateway.invoke_tool() consults to decide allow/block — there
    is no other code path that lets an AI action reach an external tool.
    """

    __tablename__ = "tool_access_policies"

    tool_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)  # e.g. "github"
    allowed_actions: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)  # e.g. ["create_pr"]
    scope: Mapped[str] = mapped_column(String(500), default="")  # human-readable scope note
    updated_by: Mapped[str] = mapped_column(String(255), default="system")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AIActionLog(UUIDPKMixin, Base):
    """
    Append-only log of every attempted AI-initiated tool call, allowed or
    blocked. Separate from audit_logs (which records human-facing actions)
    so "what did the AI try to reach outside this system" can be audited on
    its own, tool-by-tool.
    """

    __tablename__ = "ai_action_log"

    tool_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    requested_action: Mapped[str] = mapped_column(String(100), nullable=False)
    params_summary: Mapped[dict] = mapped_column(JSONB, default=dict)
    allowed: Mapped[bool] = mapped_column(nullable=False)
    policy_rule_matched: Mapped[str | None] = mapped_column(String(255), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
