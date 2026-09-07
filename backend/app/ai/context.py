"""
Builds the bounded, evidence-tagged context handed to the AI layer for one
incident. Every fact included gets a stable `evidence_id=<token>` tag so
that whatever the model cites back in `evidence_refs` can be resolved to a
real, storable EvidenceItem — this is what makes "never invent evidence"
enforceable rather than aspirational.

All incident-derived text (rule descriptions, raw log fragments, enrichment
notes) is untrusted and is wrapped via app.ai.guardrails before inclusion.
"""

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.ai.guardrails import build_untrusted_data_block
from app.models.enrichment_result import EnrichmentResult
from app.models.event import Event
from app.models.incident import Incident
from app.models.ioc import IOC


@dataclass
class EvidenceCandidate:
    token: str
    source: str
    detail: dict
    confidence: float


@dataclass
class IncidentContext:
    user_prompt_body: str
    evidence_index: dict[str, EvidenceCandidate] = field(default_factory=dict)
    injection_flags: list[str] = field(default_factory=list)


def build_incident_context(db: Session, incident: Incident) -> IncidentContext:
    evidence_index: dict[str, EvidenceCandidate] = {}
    injection_flags: list[str] = []
    lines: list[str] = [f"Incident: {incident.title} (status={incident.status.value})"]

    events = db.query(Event).filter(Event.incident_id == incident.id).order_by(Event.timestamp).all()
    for ev in events:
        token = f"event:{ev.id}"
        rule_desc = str(ev.raw_data.get("rule_description", ""))
        rule_level = ev.raw_data.get("rule_level", "")
        block, flags = build_untrusted_data_block(
            f"EVENT ({token})",
            f"type={ev.event_type} host={ev.source_host} time={ev.timestamp.isoformat()} "
            f"rule_level={rule_level} rule_description={rule_desc}",
        )
        injection_flags.extend(flags)
        lines.append(f"evidence_id={token} :: {block}")
        evidence_index[token] = EvidenceCandidate(
            token=token,
            source=f"event:{ev.id}",
            detail={"event_type": ev.event_type, "rule_description": rule_desc, "rule_level": rule_level},
            confidence=0.9,
        )

    iocs = db.query(IOC).filter(IOC.incident_id == incident.id).all()
    for ioc in iocs:
        results = db.query(EnrichmentResult).filter(EnrichmentResult.ioc_id == ioc.id).all()
        for res in results:
            token = f"enrichment:{res.id}"
            block, flags = build_untrusted_data_block(
                f"ENRICHMENT ({token})",
                f"ioc_type={ioc.type.value} ioc_value={ioc.value} provider={res.provider} "
                f"verdict={res.verdict} confidence={res.confidence}",
            )
            injection_flags.extend(flags)
            lines.append(f"evidence_id={token} :: {block}")
            evidence_index[token] = EvidenceCandidate(
                token=token,
                source=f"enrichment:{res.id}",
                detail={"ioc": ioc.value, "provider": res.provider, "verdict": res.verdict},
                confidence=res.confidence,
            )

    return IncidentContext(
        user_prompt_body="\n".join(lines),
        evidence_index=evidence_index,
        injection_flags=injection_flags,
    )
