SAMPLE_ALERT = {
    "source": "wazuh-synthetic",
    "alerts": [
        {
            "rule": {"id": "1", "level": 5, "description": "test alert", "groups": ["test"]},
            "agent": {"name": "HOST-A", "ip": "10.0.0.1"},
            "data": {"event_type": "test_event"},
            "full_log": "a benign test log line",
            "timestamp": "2026-01-01T00:00:00+00:00",
        }
    ],
}


def test_ingest_alert_creates_incident(client):
    resp = client.post("/alerts", json=SAMPLE_ALERT)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ingested"] == 1
    assert "incident_id" in body


def test_ingested_alert_groups_by_host_and_time(client):
    resp1 = client.post("/alerts", json=SAMPLE_ALERT)
    resp2 = client.post("/alerts", json=SAMPLE_ALERT)
    # same host, same timestamp -> should land in the same incident
    assert resp1.json()["incident_id"] == resp2.json()["incident_id"]


def test_get_incident_detail(client):
    ingest = client.post("/alerts", json=SAMPLE_ALERT).json()
    incident_id = ingest["incident_id"]
    resp = client.get(f"/incidents/{incident_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["alert_count"] == 1
    assert body["event_count"] == 1


def test_get_nonexistent_incident_404(client):
    resp = client.get("/incidents/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


def test_list_incidents(client):
    client.post("/alerts", json=SAMPLE_ALERT)
    resp = client.get("/incidents")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1
