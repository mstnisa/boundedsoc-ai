"""
Normalization layer: maps varying Wazuh-style alert shapes into one internal
schema. This is deterministic code — no LLM involvement — per the AI design
rule "use deterministic code for parsing, validation, timestamps...".
"""

from datetime import datetime, timezone
from typing import Any


def _safe_get(d: dict, path: list[str], default=None):
    cur: Any = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key, default)
    return cur


def normalize_wazuh_alert(raw: dict) -> dict:
    """
    Produces the internal normalized schema:
    {
      rule_id, rule_description, rule_level, mitre_hint,
      agent_name, agent_ip,
      event_type, source_host,
      timestamp (ISO8601),
      full_log,
      data (arbitrary decoded fields, still treated as untrusted downstream)
    }
    """
    rule = raw.get("rule", {}) or {}
    agent = raw.get("agent", {}) or {}
    data = raw.get("data", {}) or {}

    ts_raw = raw.get("timestamp")
    try:
        timestamp = (
            datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else datetime.now(timezone.utc)
        )
    except (ValueError, AttributeError):
        timestamp = datetime.now(timezone.utc)

    rule_description = rule.get("description")
    if rule_description is not None and not isinstance(rule_description, str):
        # Defensive: malformed/adversarial input can send an object here
        # instead of a string. Never let a non-string reach downstream code
        # that assumes str (e.g. slicing for an incident title).
        rule_description = str(rule_description)

    return {
        "rule_id": rule.get("id"),
        "rule_description": rule_description,
        "rule_level": rule.get("level"),
        "mitre_hint": rule.get("mitre", {}).get("id", []) if isinstance(rule.get("mitre"), dict) else [],
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "event_type": (
            data.get("event_type") or rule.get("groups", ["unknown"])[0]
            if isinstance(rule.get("groups"), list) and rule.get("groups")
            else data.get("event_type", "unknown")
        ),
        "source_host": agent.get("name") or data.get("hostname"),
        "timestamp": timestamp.isoformat(),
        "full_log": raw.get("full_log", ""),
        "data": data,
    }
