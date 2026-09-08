import uuid
from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import ORMModel


class ToolAccessPolicyOut(ORMModel):
    id: uuid.UUID
    tool_name: str
    allowed_actions: list[str]
    scope: str
    updated_by: str
    updated_at: datetime


class ToolAccessPolicyIn(BaseModel):
    allowed_actions: list[str]
    scope: str = ""


class AIActionLogOut(ORMModel):
    id: uuid.UUID
    tool_name: str
    requested_action: str
    params_summary: dict
    allowed: bool
    policy_rule_matched: str | None
    timestamp: datetime
