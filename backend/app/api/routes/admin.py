from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import CurrentUser, require_role
from app.db.session import get_db
from app.models.tool_policy import AIActionLog, ToolAccessPolicy
from app.schemas.tool_policy import AIActionLogOut, ToolAccessPolicyIn, ToolAccessPolicyOut
from app.services import mcp_gateway

router = APIRouter()


@router.get("/admin/tool-policies", response_model=list[ToolAccessPolicyOut])
def list_tool_policies(
    db: Session = Depends(get_db),
    _: CurrentUser = Depends(require_role("admin")),
):
    mcp_gateway.ensure_default_policies(db)
    return db.execute(select(ToolAccessPolicy)).scalars().all()


@router.put("/admin/tool-policies/{tool_name}", response_model=ToolAccessPolicyOut)
def update_tool_policy(
    tool_name: str,
    payload: ToolAccessPolicyIn,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role("admin")),
):
    policy = (
        db.execute(select(ToolAccessPolicy).where(ToolAccessPolicy.tool_name == tool_name)).scalars().first()
    )
    if not policy:
        policy = ToolAccessPolicy(tool_name=tool_name)
    policy.allowed_actions = payload.allowed_actions
    policy.scope = payload.scope
    policy.updated_by = user.email
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


@router.get("/admin/ai-action-log", response_model=list[AIActionLogOut])
def list_ai_action_log(
    db: Session = Depends(get_db),
    _: CurrentUser = Depends(require_role("admin")),
):
    return db.execute(select(AIActionLog).order_by(AIActionLog.timestamp.desc()).limit(200)).scalars().all()
