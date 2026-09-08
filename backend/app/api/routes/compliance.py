import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db
from app.models.compliance_mapping import ComplianceMapping
from app.models.incident import Incident
from app.schemas.compliance import (
    ComplianceCoverageOut,
    ComplianceMappingOut,
    ComplianceMappingRequest,
    ComplianceMappingResponse,
    Framework,
)
from app.services import compliance_mapper

router = APIRouter()


def _get_incident_or_404(db: Session, incident_id: uuid.UUID) -> Incident:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/incidents/{incident_id}/compliance-mapping", response_model=ComplianceMappingResponse)
def create_compliance_mapping(
    incident_id: uuid.UUID,
    payload: ComplianceMappingRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    incident = _get_incident_or_404(db, incident_id)
    mappings = compliance_mapper.map_incident(db, incident, payload.framework, actor=user.email)
    return ComplianceMappingResponse(
        incident_id=incident_id,
        framework=payload.framework,
        mappings=[ComplianceMappingOut.model_validate(m) for m in mappings],
    )


@router.get("/incidents/{incident_id}/compliance-report", response_model=list[ComplianceMappingOut])
def get_compliance_report(
    incident_id: uuid.UUID,
    framework: Framework = Query(...),
    db: Session = Depends(get_db),
    _: CurrentUser = Depends(get_current_user),
):
    _get_incident_or_404(db, incident_id)
    rows = (
        db.execute(
            select(ComplianceMapping).where(
                ComplianceMapping.incident_id == incident_id, ComplianceMapping.framework == framework
            )
        )
        .scalars()
        .all()
    )
    return rows


@router.get("/compliance/coverage", response_model=ComplianceCoverageOut)
def get_compliance_coverage(
    db: Session = Depends(get_db),
    _: CurrentUser = Depends(get_current_user),
):
    return ComplianceCoverageOut(coverage=compliance_mapper.coverage(db))
