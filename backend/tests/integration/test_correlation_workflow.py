"""Workflow-level integration tests for the correlation/grouping engine —
the deterministic logic that stands in for the n8n orchestration layer's
"trigger" step."""

from datetime import datetime, timedelta, timezone

from app.models.alert import Alert
from app.services import correlation


def _ingest_like_alert(db_session, incident, host: str, when: datetime):
    """Mirrors what app.api.routes.alerts.ingest_alerts actually does after
    find_or_create_incident: it always creates the Event that later lookups
    correlate against. find_or_create_incident alone never does this."""
    normalized = {
        "event_type": "test_event",
        "source_host": host,
        "timestamp": when.isoformat(),
        "rule_description": "test",
        "data": {},
    }
    alert = Alert(source="test", raw_payload={}, normalized_payload=normalized, incident_id=incident.id)
    db_session.add(alert)
    db_session.flush()
    correlation.alert_to_event(db_session, alert, incident)


def test_alerts_on_same_host_within_window_share_incident(db_session):
    t0 = datetime.now(timezone.utc)
    inc1 = correlation.find_or_create_incident(
        db_session, host="HOST-X", alert_time=t0, rule_description="first"
    )
    _ingest_like_alert(db_session, inc1, "HOST-X", t0)
    db_session.commit()

    inc2 = correlation.find_or_create_incident(
        db_session, host="HOST-X", alert_time=t0 + timedelta(minutes=30), rule_description="second"
    )
    db_session.commit()

    assert inc1.id == inc2.id


def test_alerts_outside_window_create_separate_incidents(db_session):
    t0 = datetime.now(timezone.utc)
    inc1 = correlation.find_or_create_incident(
        db_session, host="HOST-Y", alert_time=t0, rule_description="first"
    )
    _ingest_like_alert(db_session, inc1, "HOST-Y", t0)
    db_session.commit()

    inc2 = correlation.find_or_create_incident(
        db_session, host="HOST-Y", alert_time=t0 + timedelta(hours=5), rule_description="much later"
    )
    db_session.commit()

    assert inc1.id != inc2.id


def test_alerts_on_different_hosts_create_separate_incidents(db_session):
    t0 = datetime.now(timezone.utc)
    inc1 = correlation.find_or_create_incident(db_session, host="HOST-A", alert_time=t0, rule_description="a")
    _ingest_like_alert(db_session, inc1, "HOST-A", t0)
    db_session.commit()
    inc2 = correlation.find_or_create_incident(db_session, host="HOST-B", alert_time=t0, rule_description="b")
    db_session.commit()

    assert inc1.id != inc2.id


def test_no_host_always_creates_new_incident(db_session):
    t0 = datetime.now(timezone.utc)
    inc1 = correlation.find_or_create_incident(db_session, host=None, alert_time=t0, rule_description="a")
    db_session.commit()
    inc2 = correlation.find_or_create_incident(db_session, host=None, alert_time=t0, rule_description="b")
    db_session.commit()

    assert inc1.id != inc2.id
