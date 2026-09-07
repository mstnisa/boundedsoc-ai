"""Deterministic timeline construction: sorts an incident's events by time."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.event import Event
from app.models.timeline import Timeline, TimelineEvent


def build_timeline(db: Session, incident_id) -> Timeline:
    events = (
        db.execute(select(Event).where(Event.incident_id == incident_id).order_by(Event.timestamp))
        .scalars()
        .all()
    )

    timeline = Timeline(incident_id=incident_id)
    db.add(timeline)
    db.flush()

    for i, event in enumerate(events):
        db.add(TimelineEvent(timeline_id=timeline.id, event_id=event.id, sequence=i))

    db.flush()
    db.refresh(timeline)
    return timeline
