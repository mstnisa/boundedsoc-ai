from app.services.normalization import normalize_wazuh_alert


def test_normalize_maps_core_fields():
    raw = {
        "rule": {
            "id": "100301",
            "level": 15,
            "description": "Suspicious PowerShell",
            "mitre": {"id": ["T1059.001"]},
        },
        "agent": {"name": "WKSTN-01", "ip": "10.0.0.5"},
        "data": {"event_type": "process_creation"},
        "full_log": "powershell.exe -enc ...",
        "timestamp": "2026-09-05T09:14:07+00:00",
    }
    norm = normalize_wazuh_alert(raw)
    assert norm["rule_id"] == "100301"
    assert norm["rule_level"] == 15
    assert norm["source_host"] == "WKSTN-01"
    assert norm["event_type"] == "process_creation"
    assert norm["full_log"] == "powershell.exe -enc ..."


def test_normalize_handles_missing_fields_gracefully():
    norm = normalize_wazuh_alert({})
    assert norm["rule_id"] is None
    assert norm["source_host"] is None
    assert norm["full_log"] == ""
    assert "timestamp" in norm  # falls back to current time, never raises


def test_normalize_handles_malformed_timestamp():
    raw = {"timestamp": "not-a-real-timestamp"}
    norm = normalize_wazuh_alert(raw)
    # must not raise, must still produce a parseable ISO timestamp
    assert "timestamp" in norm
    from datetime import datetime

    datetime.fromisoformat(norm["timestamp"])


def test_normalize_handles_non_dict_nested_fields():
    # malformed/adversarial input: rule.groups is a string, not a list
    raw = {"rule": {"groups": "not-a-list", "description": "x"}, "data": {}}
    norm = normalize_wazuh_alert(raw)
    assert norm["event_type"] == "unknown"
