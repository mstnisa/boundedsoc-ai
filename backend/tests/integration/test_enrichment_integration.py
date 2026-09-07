"""Integration tests with mocked threat-intelligence providers (the default
configuration — no network calls, no API keys)."""

from app.models.incident import Incident
from app.models.ioc import IOC, IOCType
from app.services.enrichment import enrich_ioc, get_adapters


def test_get_adapters_returns_only_mocked_by_default():
    adapters = get_adapters()
    assert len(adapters) >= 2
    assert all("mock" in a.name for a in adapters)


def test_enrich_ioc_persists_provenance(db_session):
    incident = Incident(title="enrichment integration test")
    db_session.add(incident)
    db_session.flush()

    ioc = IOC(incident_id=incident.id, type=IOCType.ip, value="185.220.101.47")
    db_session.add(ioc)
    db_session.flush()

    results = enrich_ioc(db_session, ioc)
    db_session.commit()

    assert len(results) >= 1
    for r in results:
        assert r.provider
        assert r.verdict in {"malicious", "suspicious", "benign", "unknown"}
        assert 0.0 <= r.confidence <= 1.0
        assert r.evidence  # every result must carry evidence, never empty
        assert r.is_mocked is True


def test_enrich_is_deterministic_for_same_ioc(db_session):
    incident = Incident(title="determinism test")
    db_session.add(incident)
    db_session.flush()

    ioc1 = IOC(incident_id=incident.id, type=IOCType.domain, value="malware-c2.example.net")
    db_session.add(ioc1)
    db_session.flush()
    results1 = enrich_ioc(db_session, ioc1)
    db_session.commit()

    verdicts1 = sorted((r.provider, r.verdict) for r in results1)

    incident2 = Incident(title="determinism test 2")
    db_session.add(incident2)
    db_session.flush()
    ioc2 = IOC(incident_id=incident2.id, type=IOCType.domain, value="malware-c2.example.net")
    db_session.add(ioc2)
    db_session.flush()
    results2 = enrich_ioc(db_session, ioc2)
    db_session.commit()
    verdicts2 = sorted((r.provider, r.verdict) for r in results2)

    assert verdicts1 == verdicts2


def test_enrich_skips_unsupported_ioc_types(db_session):
    incident = Incident(title="unsupported type test")
    db_session.add(incident)
    db_session.flush()
    ioc = IOC(incident_id=incident.id, type=IOCType.username, value="j.rahman")
    db_session.add(ioc)
    db_session.flush()

    results = enrich_ioc(db_session, ioc)
    # no adapter supports 'username' lookups -> no results, no error
    assert results == []
