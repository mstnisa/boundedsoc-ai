"""
Credential Exposure Response (Module 2 of the commercial proposal).
Deterministic regex-based secret detection (same explainability posture as
ioc_extraction.py) over already-correlated event data. The raw secret value
is NEVER stored — only a masked prefix + hash suffix.

Revocation requires status == 'approved', enforced HERE server-side (not
just hidden in the UI), and is routed through services.mcp_gateway exactly
like remediation's create_pr — so it is subject to the same policy gate and
the same append-only ai_action_log. No escalation path in this codebase
ever sets status to 'revoked' on its own; escalation (if wired up) can only
notify a human.
"""

import hashlib
import re

from sqlalchemy.orm import Session

from app.models.event import Event
from app.models.incident import Incident
from app.models.mixins import utcnow
from app.models.secret_exposure_alert import SecretExposureAlert
from app.services import audit, mcp_gateway

# (secret_type, provider, compiled regex) — deliberately conservative
# patterns to keep false positives low; extend as needed.
_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("aws_access_key", "aws", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", "github", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("generic_api_key", "generic", re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9/_\-]{16,})")),
    ("generic_password", "generic", re.compile(r"(?i)password\s*[:=]\s*['\"]?([^\s'\"]{8,})")),
]


def _mask(raw_value: str) -> str:
    prefix = raw_value[:4]
    digest = hashlib.sha256(raw_value.encode()).hexdigest()[:10]
    return f"{prefix}…{digest}"


def scan_incident(db: Session, incident: Incident, actor: str) -> list[SecretExposureAlert]:
    events = db.query(Event).filter(Event.incident_id == incident.id).all()
    existing_sources = {a.source_ref for a in incident.secret_exposure_alerts}

    created: list[SecretExposureAlert] = []
    for ev in events:
        token = f"event:{ev.id}"
        if token in existing_sources:
            continue
        blob = str(ev.raw_data)
        for secret_type, provider, pattern in _PATTERNS:
            match = pattern.search(blob)
            if not match:
                continue
            raw_value = match.group(0)
            alert = SecretExposureAlert(
                incident_id=incident.id,
                secret_type=secret_type,
                masked_value=_mask(raw_value),
                source_ref=token,
                provider=provider,
                status="pending",
            )
            db.add(alert)
            created.append(alert)
            break  # one alert per event is enough for the demo scenario

    db.flush()
    audit.record(
        db,
        actor=actor,
        action="incident.secret_exposure.scan",
        target=f"incident:{incident.id}",
        reason=f"Deterministic regex scan over {len(events)} correlated event(s) found {len(created)} candidate secret(s).",
        details={"count": len(created)},
        commit=False,
    )
    db.commit()
    for a in created:
        db.refresh(a)
    return created


def revoke(db: Session, alert: SecretExposureAlert, actor: str) -> SecretExposureAlert:
    if alert.status != "approved":
        raise ValueError("A secret exposure alert can only be revoked once an analyst has approved it.")

    result = mcp_gateway.invoke_tool(
        db,
        tool_name="secret_provider",
        action="revoke",
        params={
            "provider": alert.provider,
            "secret_type": alert.secret_type,
            "masked_value": alert.masked_value,
        },
        actor=actor,
    )

    alert.status = "revoked"
    alert.revoked_at = utcnow()
    db.add(alert)

    audit.record(
        db,
        actor=actor,
        action="incident.secret_exposure.revoke",
        target=f"secret_exposure_alert:{alert.id}",
        reason=f"Analyst-triggered revocation via the MCP gateway ({result.get('mode')} mode).",
        details={"mode": result.get("mode")},
        commit=False,
    )
    db.commit()
    db.refresh(alert)
    return alert
