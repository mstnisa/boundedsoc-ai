import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import CurrentUser, get_current_user, require_role
from app.db.session import get_db
from app.models.event import Event
from app.models.incident import Incident, IncidentStatus, Severity
from app.models.ioc import IOC
from app.models.report import Report
from app.models.timeline import Timeline
from app.schemas.incident import IncidentDetail, IncidentSummary
from app.schemas.ioc import EnrichmentResultOut, EnrichResponse, ExtractIOCsResponse
from app.schemas.mitre import MitreSuggestionOut, MitreSuggestionResponse
from app.schemas.remediation import RemediationDraftRequest, RemediationSuggestionOut
from app.schemas.report import ReportOut
from app.schemas.review import ReviewIn, ReviewOut
from app.schemas.secret_exposure import SecretExposureAlertOut
from app.schemas.timeline import TimelineEventOut, TimelineOut
from app.services import (
    ai_orchestration,
    audit,
    enrichment,
    export,
    mcp_gateway,
    remediation,
    review,
    secret_exposure,
    timeline_builder,
    users,
)
from app.services.ioc_extraction import extract_from_normalized_event

router = APIRouter()


@router.get("/incidents", response_model=list[IncidentSummary])
def list_incidents(
    status_filter: IncidentStatus | None = Query(default=None, alias="status"),
    severity_filter: Severity | None = Query(default=None, alias="severity"),
    db: Session = Depends(get_db),
    _: CurrentUser = Depends(get_current_user),
):
    stmt = select(Incident).order_by(Incident.created_at.desc())
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter)
    if severity_filter:
        stmt = stmt.where(Incident.severity == severity_filter)
    return db.execute(stmt).scalars().all()


def _get_incident_or_404(db: Session, incident_id: uuid.UUID) -> Incident:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(
    incident_id: uuid.UUID, db: Session = Depends(get_db), _: CurrentUser = Depends(get_current_user)
):
    incident = _get_incident_or_404(db, incident_id)
    detail = IncidentDetail.model_validate(incident)
    detail.alert_count = len(incident.alerts)
    detail.event_count = len(incident.events)
    detail.ioc_count = len(incident.iocs)
    return detail


@router.post("/incidents/{incident_id}/extract-iocs", response_model=ExtractIOCsResponse)
def extract_iocs_for_incident(
    incident_id: uuid.UUID, db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)
):
    incident = _get_incident_or_404(db, incident_id)
    events = db.execute(select(Event).where(Event.incident_id == incident_id)).scalars().all()

    created: list[IOC] = []
    existing_keys = {(i.type, i.value) for i in incident.iocs}

    for event in events:
        for extracted in extract_from_normalized_event(event.raw_data):
            key = (extracted.type, extracted.value)
            if key in existing_keys:
                continue
            existing_keys.add(key)
            ioc = IOC(incident_id=incident_id, type=extracted.type, value=extracted.value)
            db.add(ioc)
            created.append(ioc)

    db.flush()

    audit.record(
        db,
        actor=user.email,
        action="incident.extract_iocs",
        target=f"incident:{incident_id}",
        reason=f"Deterministic regex-based extraction over {len(events)} correlated event(s).",
        details={"new_iocs": len(created)},
        commit=False,
    )
    db.commit()
    for i in created:
        db.refresh(i)

    all_iocs = db.execute(select(IOC).where(IOC.incident_id == incident_id)).scalars().all()
    return ExtractIOCsResponse(incident_id=incident_id, extracted=len(created), iocs=all_iocs)


@router.post("/incidents/{incident_id}/enrich", response_model=EnrichResponse)
def enrich_incident(
    incident_id: uuid.UUID, db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)
):
    incident = _get_incident_or_404(db, incident_id)
    all_results = []
    for ioc in incident.iocs:
        results = enrichment.enrich_ioc(db, ioc)
        all_results.extend(results)

    audit.record(
        db,
        actor=user.email,
        action="incident.enrich",
        target=f"incident:{incident_id}",
        reason=f"Ran configured TI adapters over {len(incident.iocs)} IOC(s); mocked unless TI_USE_LIVE_PROVIDERS=true.",
        details={"result_count": len(all_results)},
        commit=False,
    )
    db.commit()
    for r in all_results:
        db.refresh(r)
    return EnrichResponse(
        incident_id=incident_id, results=[EnrichmentResultOut.model_validate(r) for r in all_results]
    )


@router.get("/incidents/{incident_id}/timeline", response_model=TimelineOut)
def get_timeline(
    incident_id: uuid.UUID, db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)
):
    _get_incident_or_404(db, incident_id)  # 404s early if the incident doesn't exist
    existing = (
        db.execute(
            select(Timeline).where(Timeline.incident_id == incident_id).order_by(Timeline.generated_at.desc())
        )
        .scalars()
        .first()
    )
    if existing is None:
        existing = timeline_builder.build_timeline(db, incident_id)
        audit.record(
            db,
            actor=user.email,
            action="incident.timeline.generate",
            target=f"incident:{incident_id}",
            reason="Chronological timeline built deterministically from correlated events.",
            commit=False,
        )
        db.commit()
        db.refresh(existing)

    events_out = [
        TimelineEventOut(
            sequence=te.sequence,
            event_id=te.event.id,
            event_type=te.event.event_type,
            source_host=te.event.source_host,
            timestamp=te.event.timestamp,
            raw_data=te.event.raw_data,
        )
        for te in existing.ordered_events
    ]
    return TimelineOut(
        id=existing.id, incident_id=incident_id, generated_at=existing.generated_at, events=events_out
    )


@router.post("/incidents/{incident_id}/severity-suggestion")
def suggest_severity(
    incident_id: uuid.UUID, db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)
):
    incident = _get_incident_or_404(db, incident_id)
    result = ai_orchestration.suggest_severity(db, incident, actor=user.email)
    return result


@router.post("/incidents/{incident_id}/mitre-suggestions", response_model=MitreSuggestionResponse)
def mitre_suggestions(
    incident_id: uuid.UUID, db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)
):
    incident = _get_incident_or_404(db, incident_id)
    created = ai_orchestration.suggest_mitre(db, incident, actor=user.email)
    return MitreSuggestionResponse(
        incident_id=incident_id, suggestions=[MitreSuggestionOut.model_validate(s) for s in created]
    )


@router.post("/incidents/{incident_id}/report-draft", response_model=ReportOut)
def report_draft(
    incident_id: uuid.UUID, db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)
):
    incident = _get_incident_or_404(db, incident_id)
    report = ai_orchestration.draft_report(db, incident, actor=user.email)
    return report


@router.post("/incidents/{incident_id}/review", response_model=ReviewOut)
def submit_incident_review(
    incident_id: uuid.UUID,
    payload: ReviewIn,
    db: Session = Depends(get_db),
    # Only analyst/senior_analyst/admin roles may render a review decision —
    # this is the human-in-the-loop gate itself, so it's the one endpoint in
    # the API where role-based access control matters most. A no-op in the
    # default AUTH_SINGLE_USER_MODE=true demo config; enforced once real
    # multi-user auth is turned on.
    user: CurrentUser = Depends(require_role("analyst", "senior_analyst", "admin")),
):
    _get_incident_or_404(db, incident_id)
    local_user = users.get_or_create_local_user(db)
    return review.submit_review(
        db,
        user_id=local_user.id,
        actor_email=user.email,
        target_entity_type=payload.target_entity_type,
        target_entity_id=payload.target_entity_id,
        decision=payload.decision,
        comment=payload.comment,
        correction=payload.correction,
    )


@router.get("/incidents/{incident_id}/export")
def export_incident(
    incident_id: uuid.UUID,
    format: str = Query(default="markdown", pattern="^(markdown|pdf|json)$"),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    incident = _get_incident_or_404(db, incident_id)
    report = (
        db.execute(select(Report).where(Report.incident_id == incident_id).order_by(Report.version.desc()))
        .scalars()
        .first()
    )
    if not report:
        raise HTTPException(status_code=404, detail="No report has been generated for this incident yet")

    audit.record(
        db,
        actor=user.email,
        action="incident.export",
        target=f"incident:{incident_id}",
        reason=f"Exported report v{report.version} as {format}.",
        details={"report_id": str(report.id), "format": format},
    )

    if format == "markdown":
        content = export.export_markdown(report)
        media_type, filename = "text/markdown", f"incident-{incident_id}.md"
    elif format == "json":
        content = export.export_json(db, incident, report)
        media_type, filename = "application/json", f"incident-{incident_id}.json"
    else:
        content = export.export_pdf(report)
        media_type, filename = "application/pdf", f"incident-{incident_id}.pdf"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --- Remediation Drafting Agent -------------------------------------------


@router.post(
    "/incidents/{incident_id}/remediation-suggestions", response_model=RemediationSuggestionOut | None
)
def draft_remediation_suggestion(
    incident_id: uuid.UUID,
    payload: RemediationDraftRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    incident = _get_incident_or_404(db, incident_id)
    return remediation.draft_remediation(
        db, incident, actor=user.email, repo_full_name=payload.repo_full_name
    )


@router.post(
    "/incidents/{incident_id}/remediation-suggestions/{rid}/create-pr",
    response_model=RemediationSuggestionOut,
)
def create_remediation_pr(
    incident_id: uuid.UUID,
    rid: uuid.UUID,
    db: Session = Depends(get_db),
    # Deliberately a *separate* explicit call from "approve" — this is the
    # one endpoint in the whole remediation flow that writes to GitHub.
    user: CurrentUser = Depends(require_role("analyst", "senior_analyst", "admin")),
):
    _get_incident_or_404(db, incident_id)
    from app.models.remediation_suggestion import RemediationSuggestion

    suggestion = db.get(RemediationSuggestion, rid)
    if not suggestion or suggestion.incident_id != incident_id:
        raise HTTPException(status_code=404, detail="Remediation suggestion not found")
    try:
        return remediation.create_pr(db, suggestion, actor=user.email)
    except (ValueError, mcp_gateway.ToolInvocationBlocked) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# --- Credential Exposure Response ------------------------------------------


@router.post("/incidents/{incident_id}/secret-exposure", response_model=list[SecretExposureAlertOut])
def scan_secret_exposure(
    incident_id: uuid.UUID, db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)
):
    incident = _get_incident_or_404(db, incident_id)
    return secret_exposure.scan_incident(db, incident, actor=user.email)


@router.post("/incidents/{incident_id}/secret-exposure/{sid}/revoke", response_model=SecretExposureAlertOut)
def revoke_secret_exposure(
    incident_id: uuid.UUID,
    sid: uuid.UUID,
    db: Session = Depends(get_db),
    # Same role gate as the remediation PR-create step — this is the one
    # endpoint that actually calls out to revoke a credential, and it's
    # enforced again server-side inside services.secret_exposure.revoke().
    user: CurrentUser = Depends(require_role("analyst", "senior_analyst", "admin")),
):
    _get_incident_or_404(db, incident_id)
    from app.models.secret_exposure_alert import SecretExposureAlert

    alert = db.get(SecretExposureAlert, sid)
    if not alert or alert.incident_id != incident_id:
        raise HTTPException(status_code=404, detail="Secret exposure alert not found")
    try:
        return secret_exposure.revoke(db, alert, actor=user.email)
    except (ValueError, mcp_gateway.ToolInvocationBlocked) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
