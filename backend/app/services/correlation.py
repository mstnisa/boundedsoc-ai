"""
Investigation/correlation engine: groups incoming alerts into incidents by
shared host + a time-proximity window, deduplicates repeated alerts, and
turns each alert into one or more Event rows for the timeline builder.
Deterministic, rule-based — no LLM involvement.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident, IncidentStatus

CORRELATION_WINDOW = timedelta(hours=2)


def find_or_create_incident(
    db: Session, *, host: str | None, alert_time: datetime, rule_description: str
) -> Incident:
    """
    Groups an alert into an existing open incident on the same host within
    the correlation window, or opens a new one. This is intentionally
    simple/explainable (host + time proximity) rather than an ML clustering
    step, so every grouping decision can be justified to an analyst.
    """
    if host:
        window_start = alert_time - CORRELATION_WINDOW
        window_end = alert_time + CORRELATION_WINDOW
        stmt = (
            select(Incident)
            .join(Event, Event.incident_id == Incident.id, isouter=True)
            .where(
                Incident.status.notin_(
                    [IncidentStatus.closed_true_positive, IncidentStatus.closed_false_positive]
                )
            )
        )
        candidates = db.execute(stmt).scalars().unique().all()
        for incident in candidates:
            for ev in incident.events:
                if ev.source_host == host and window_start <= ev.timestamp <= window_end:
                    return incident

    safe_description = str(rule_description) if rule_description else ""
    incident = Incident(
        title=f"Incident: {safe_description[:200]}" if safe_description else "Untitled incident",
        status=IncidentStatus.new,
    )
    db.add(incident)
    db.flush()
    return incident


def alert_to_event(db: Session, alert: Alert, incident: Incident) -> Event:
    norm = alert.normalized_payload
    event = Event(
        incident_id=incident.id,
        event_type=norm.get("event_type", "unknown"),
        source_host=norm.get("source_host"),
        timestamp=(
            datetime.fromisoformat(norm["timestamp"]) if norm.get("timestamp") else datetime.now(timezone.utc)
        ),
        raw_data=norm,
    )
    db.add(event)
    db.flush()
    return event
