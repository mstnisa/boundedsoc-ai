from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.schemas.audit import AuditLogOut

router = APIRouter()


@router.get("/audit-logs", response_model=list[AuditLogOut])
def list_audit_logs(
    actor: str | None = Query(default=None),
    action: str | None = Query(default=None),
    target: str | None = Query(default=None),
    limit: int = Query(default=200, le=1000),
    db: Session = Depends(get_db),
    _: CurrentUser = Depends(get_current_user),
):
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if target:
        stmt = stmt.where(AuditLog.target == target)
    return db.execute(stmt).scalars().all()
