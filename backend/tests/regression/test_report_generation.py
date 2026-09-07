"""Regression tests for report generation: pin the shape and required
disclaimers of a generated report so future changes can't silently drop the
"AI-generated" labeling or the evidence trail."""

from app.models.incident import Incident
from app.services import ai_orchestration, correlation
from app.services.export import export_json, export_markdown, export_pdf


def _seed_incident_with_signal(db_session):
    incident = Incident(title="regression test incident")
    db_session.add(incident)
    db_session.flush()

    from datetime import datetime, timezone

    from app.models.alert import Alert

    normalized = {
        "event_type": "process_creation",
        "source_host": "HOST-REG",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule_description": "Suspicious encoded PowerShell execution",
        "rule_level": 15,
        "data": {},
        "full_log": "powershell.exe -enc ...",
    }
    alert = Alert(source="test", raw_payload={}, normalized_payload=normalized, incident_id=incident.id)
    db_session.add(alert)
    db_session.flush()
    correlation.alert_to_event(db_session, alert, incident)
    db_session.commit()
    db_session.refresh(incident)
    return incident


def test_report_always_labeled_ai_generated(db_session):
    incident = _seed_incident_with_signal(db_session)
    report = ai_orchestration.draft_report(db_session, incident, actor="test@local")
    assert "AI-GENERATED" in report.content
    assert "has not been reviewed" in report.content
    assert report.generated_by == "ai"
    assert report.status == "draft"


def test_report_version_increments(db_session):
    incident = _seed_incident_with_signal(db_session)
    r1 = ai_orchestration.draft_report(db_session, incident, actor="test@local")
    r2 = ai_orchestration.draft_report(db_session, incident, actor="test@local")
    assert r2.version == r1.version + 1


def test_report_records_model_metadata(db_session):
    incident = _seed_incident_with_signal(db_session)
    report = ai_orchestration.draft_report(db_session, incident, actor="test@local")
    assert "prompt_template_version" in report.model_metadata
    assert "provider" in report.model_metadata


def test_export_formats_all_succeed(db_session):
    incident = _seed_incident_with_signal(db_session)
    report = ai_orchestration.draft_report(db_session, incident, actor="test@local")

    md = export_markdown(report)
    assert b"AI-GENERATED" in md

    js = export_json(db_session, incident, report)
    import json as _json

    parsed = _json.loads(js)
    assert parsed["ai_generated_disclaimer"]

    pdf = export_pdf(report)
    assert pdf[:4] == b"%PDF"
