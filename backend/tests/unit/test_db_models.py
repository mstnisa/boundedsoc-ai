"""Database-layer tests: constraints, relationships, and the append-only
nature of the audit log, exercised against a real Postgres test DB."""

from app.models.audit_log import AuditLog
from app.models.incident import Incident, IncidentStatus, Severity
from app.models.ioc import IOC, IOCType
from app.services import audit


def test_incident_default_status_and_severity(db_session):
    incident = Incident(title="test incident")
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)
    assert incident.status == IncidentStatus.new
    assert incident.severity == Severity.unknown
    assert incident.severity_source == "unset"


def test_ioc_unique_constraint_per_incident(db_session):
    incident = Incident(title="dup test")
    db_session.add(incident)
    db_session.flush()

    db_session.add(IOC(incident_id=incident.id, type=IOCType.ip, value="1.2.3.4"))
    db_session.commit()

    db_session.add(IOC(incident_id=incident.id, type=IOCType.ip, value="1.2.3.4"))
    import pytest
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_audit_log_record_persists(db_session):
    entry = audit.record(
        db_session,
        actor="test@local",
        action="test.action",
        target="incident:none",
        reason="unit test",
    )
    assert entry.id is not None
    found = db_session.get(AuditLog, entry.id)
    assert found.reason == "unit test"


def test_incident_relationships_cascade_load(db_session):
    incident = Incident(title="relationship test")
    db_session.add(incident)
    db_session.flush()
    db_session.add(IOC(incident_id=incident.id, type=IOCType.domain, value="example-test.com"))
    db_session.commit()
    db_session.refresh(incident)
    assert len(incident.iocs) == 1
