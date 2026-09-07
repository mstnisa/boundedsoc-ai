from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import CurrentUser, get_current_user, require_role
from app.db.session import get_db
from app.models.integration import Integration
from app.schemas.integration import IntegrationIn, IntegrationOut

router = APIRouter()


@router.get("/integrations", response_model=list[IntegrationOut])
def list_integrations(db: Session = Depends(get_db), _: CurrentUser = Depends(get_current_user)):
    # Read access: any authenticated role may see which adapters are configured.
    return db.execute(select(Integration)).scalars().all()


@router.post("/integrations", response_model=IntegrationOut)
def upsert_integration(
    payload: IntegrationIn,
    db: Session = Depends(get_db),
    _: CurrentUser = Depends(require_role("admin")),
):
    # Write access: configuring/enabling adapters (including toggling
    # TI_USE_LIVE_PROVIDERS-style integrations) is admin-only once
    # AUTH_SINGLE_USER_MODE=false and real roles are in play.
    existing = db.execute(select(Integration).where(Integration.name == payload.name)).scalar_one_or_none()
    if existing:
        existing.type = payload.type
        existing.config_ref = payload.config_ref
        existing.enabled = payload.enabled
        db.add(existing)
        db.commit()
        db.refresh(existing)
        return existing

    integration = Integration(**payload.model_dump())
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration
