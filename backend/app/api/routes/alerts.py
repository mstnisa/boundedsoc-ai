import uuid
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db
from app.models.alert import Alert
from app.schemas.alert import AlertIngestRequest, AlertIngestResponse
from app.services import audit, correlation, ml_prefilter, normalization

router = APIRouter()


@router.post("/alerts", response_model=AlertIngestResponse)
def ingest_alerts(
    payload: AlertIngestRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    alert_ids: list[uuid.UUID] = []
    incident = None

    for raw_alert in payload.alerts:
        normalized = normalization.normalize_wazuh_alert(raw_alert.model_dump())

        alert = Alert(
            source=payload.source, raw_payload=raw_alert.model_dump(), normalized_payload=normalized
        )
        db.add(alert)
        db.flush()
        alert_ids.append(alert.id)

        incident = correlation.find_or_create_incident(
            db,
            host=normalized.get("source_host"),
            alert_time=datetime.fromisoformat(normalized["timestamp"]),
            rule_description=normalized.get("rule_description") or "",
        )
        alert.incident_id = incident.id
        db.add(alert)

        correlation.alert_to_event(db, alert, incident)

    audit.record(
        db,
        actor=user.email,
        action="alerts.ingest",
        target=f"incident:{incident.id}" if incident else "none",
        reason=f"Ingested {len(alert_ids)} synthetic Wazuh-style alert(s).",
        details={"alert_ids": [str(a) for a in alert_ids], "source": payload.source},
    )

    if incident is not None:
        db.refresh(incident)
        ml_prefilter.classify_incident(db, incident, actor="system")

    return AlertIngestResponse(
        ingested=len(alert_ids), alert_ids=alert_ids, incident_id=incident.id if incident else None
    )
