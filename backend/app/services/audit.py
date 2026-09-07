"""
The single writer to audit_logs. Every service in this codebase that performs
a consequential action (ingest, extract, enrich, suggest, generate, review)
MUST call record() with a real reason. Rows are never updated or deleted —
enforced socially here and at the DB layer (no update/delete helpers exist).
"""
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def record(
    db: Session,
    *,
    actor: str,
    action: str,
    target: str,
    reason: str,
    details: dict | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        actor=actor,
        action=action,
        target=target,
        reason=reason,
        details=details or {},
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    return entry
