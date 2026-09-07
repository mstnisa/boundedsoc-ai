"""
Ties together: context building (evidence-tagged, sanitized) -> the bounded
LangGraph task -> evidence enforcement -> DB persistence -> audit logging.

Nothing here ever sets Incident.status to a closed/actioned state, ever
calls an enrichment/response API automatically, and every write is preceded
by an audit_logs entry explaining what happened and why (including when a
claim was DROPPED for lacking evidence).
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.ai.context import build_incident_context
from app.ai.graph import run_bounded_task
from app.ai.guardrails import has_evidence
from app.ai.prompts import (
    MITRE_SYSTEM_PROMPT,
    PROMPT_TEMPLATE_VERSION,
    REPORT_SYSTEM_PROMPT,
    SEVERITY_SYSTEM_PROMPT,
)
from app.ai.providers.factory import get_provider
from app.ai.schemas import MitreSuggestionsResponse, ReportDraftResponse, SeverityClaim
from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.mitre_suggestion import MitreSuggestion
from app.models.report import Report
from app.services import audit


def _record_evidence(db: Session, *, entity_type: str, entity_id, token: str, evidence_index: dict) -> bool:
    """Materializes one EvidenceItem for a claim, iff the cited token is a
    real evidence_id we handed the model. Returns False (and records
    nothing) for a hallucinated/unknown token."""
    candidate = evidence_index.get(token)
    if candidate is None:
        return False
    db.add(
        EvidenceItem(
            related_entity_type=entity_type,
            related_entity_id=entity_id,
            source=candidate.source,
            detail=candidate.detail,
            confidence=candidate.confidence,
        )
    )
    return True


def suggest_severity(db: Session, incident: Incident, actor: str) -> dict:
    ctx = build_incident_context(db, incident)
    provider = get_provider()

    result = run_bounded_task(
        provider,
        system_prompt=SEVERITY_SYSTEM_PROMPT,
        user_prompt=ctx.user_prompt_body,
        prompt_template_version=PROMPT_TEMPLATE_VERSION,
        schema=SeverityClaim,
    )

    if not result.get("parsed") or not has_evidence(result["parsed"].get("evidence_refs")):
        audit.record(
            db,
            actor=f"ai:{result.get('provider')}/{result.get('model')}",
            action="incident.severity.suggest.dropped",
            target=f"incident:{incident.id}",
            reason="No valid, evidence-backed severity claim produced.",
            details={"errors": result.get("errors", []), "injection_flags": ctx.injection_flags},
        )
        return {"suggested": False, "errors": result.get("errors", [])}

    claim = result["parsed"]
    valid_refs = [ref for ref in claim["evidence_refs"] if ref in ctx.evidence_index]
    for ref in valid_refs:
        _record_evidence(
            db,
            entity_type="incident_severity",
            entity_id=incident.id,
            token=ref,
            evidence_index=ctx.evidence_index,
        )

    if not valid_refs:
        audit.record(
            db,
            actor=f"ai:{result.get('provider')}/{result.get('model')}",
            action="incident.severity.suggest.dropped",
            target=f"incident:{incident.id}",
            reason="All cited evidence_refs were hallucinated (not present in supplied context).",
            details={"claim": claim},
        )
        return {"suggested": False, "errors": ["all_evidence_refs_hallucinated"]}

    incident.severity = claim["severity"]
    incident.severity_source = "ai"
    db.add(incident)

    audit.record(
        db,
        actor=f"ai:{result.get('provider')}/{result.get('model')}",
        action="incident.severity.suggest",
        target=f"incident:{incident.id}",
        reason=claim["rationale"],
        details={
            "confidence": claim["confidence"],
            "evidence_refs": valid_refs,
            "prompt_template_version": PROMPT_TEMPLATE_VERSION,
            "requires_human_approval": True,
        },
        commit=False,
    )
    db.commit()
    db.refresh(incident)
    return {
        "suggested": True,
        "severity": claim["severity"],
        "confidence": claim["confidence"],
        "rationale": claim["rationale"],
        "evidence_refs": valid_refs,
    }


def suggest_mitre(db: Session, incident: Incident, actor: str) -> list[MitreSuggestion]:
    ctx = build_incident_context(db, incident)
    provider = get_provider()

    result = run_bounded_task(
        provider,
        system_prompt=MITRE_SYSTEM_PROMPT,
        user_prompt=ctx.user_prompt_body,
        prompt_template_version=PROMPT_TEMPLATE_VERSION,
        schema=MitreSuggestionsResponse,
    )

    created: list[MitreSuggestion] = []
    if not result.get("parsed"):
        audit.record(
            db,
            actor=f"ai:{result.get('provider')}/{result.get('model')}",
            action="incident.mitre.suggest.dropped",
            target=f"incident:{incident.id}",
            reason="Model output failed schema validation; no suggestions stored.",
            details={"errors": result.get("errors", [])},
        )
        return created

    for raw_claim in result["parsed"].get("suggestions", []):
        valid_refs = [ref for ref in raw_claim.get("evidence_refs", []) if ref in ctx.evidence_index]
        if not valid_refs:
            audit.record(
                db,
                actor=f"ai:{result.get('provider')}/{result.get('model')}",
                action="incident.mitre.suggest.dropped",
                target=f"incident:{incident.id}",
                reason=f"Technique {raw_claim.get('technique_id')} cited no valid evidence_refs; discarded.",
                details={"claim": raw_claim},
            )
            continue

        suggestion = MitreSuggestion(
            incident_id=incident.id,
            technique_id=raw_claim["technique_id"],
            technique_name=raw_claim["technique_name"],
            rationale=raw_claim["rationale"],
            confidence=raw_claim["confidence"],
            evidence_refs=valid_refs,
            model_metadata={
                "provider": result.get("provider"),
                "model": result.get("model"),
                "prompt_template_version": PROMPT_TEMPLATE_VERSION,
            },
            status="pending",
        )
        db.add(suggestion)
        db.flush()
        for ref in valid_refs:
            _record_evidence(
                db,
                entity_type="mitre_suggestion",
                entity_id=suggestion.id,
                token=ref,
                evidence_index=ctx.evidence_index,
            )
        created.append(suggestion)

    audit.record(
        db,
        actor=f"ai:{result.get('provider')}/{result.get('model')}",
        action="incident.mitre.suggest",
        target=f"incident:{incident.id}",
        reason=f"Generated {len(created)} evidence-backed MITRE technique suggestion(s) for human review.",
        details={"technique_ids": [s.technique_id for s in created], "requires_human_approval": True},
        commit=False,
    )
    db.commit()
    for s in created:
        db.refresh(s)
    return created


def draft_report(db: Session, incident: Incident, actor: str) -> Report:
    ctx = build_incident_context(db, incident)
    provider = get_provider()

    result = run_bounded_task(
        provider,
        system_prompt=REPORT_SYSTEM_PROMPT,
        user_prompt=ctx.user_prompt_body,
        prompt_template_version=PROMPT_TEMPLATE_VERSION,
        schema=ReportDraftResponse,
    )

    parsed = result.get("parsed") or {
        "executive_summary": "AI report generation failed validation; this is an empty placeholder draft.",
        "severity_assessment": "N/A",
        "sections": [],
        "disclaimer": "This report was drafted by an AI system and has not yet been reviewed or approved by a human analyst.",
    }

    markdown = _render_report_markdown(incident, parsed)

    existing_versions = db.query(Report).filter(Report.incident_id == incident.id).count()
    report = Report(
        incident_id=incident.id,
        version=existing_versions + 1,
        content=markdown,
        status="draft",
        generated_by="ai",
        model_metadata={
            "provider": result.get("provider"),
            "model": result.get("model"),
            "prompt_template_version": PROMPT_TEMPLATE_VERSION,
            "schema_errors": result.get("errors", []),
        },
    )
    db.add(report)
    db.flush()

    audit.record(
        db,
        actor=f"ai:{result.get('provider')}/{result.get('model')}",
        action="incident.report.draft",
        target=f"incident:{incident.id}",
        reason="Generated AI report draft; explicitly labeled as such, pending analyst review/approval.",
        details={"report_id": str(report.id), "version": report.version, "requires_human_approval": True},
        commit=False,
    )
    db.commit()
    db.refresh(report)
    return report


def _render_report_markdown(incident: Incident, parsed: dict) -> str:
    lines = [
        f"# Incident Report (AI-GENERATED DRAFT) — {incident.title}",
        "",
        "> **This report was drafted by an AI system and has not been reviewed or "
        "approved by a human analyst. Do not use it to justify a response action.**",
        "",
        f"_Generated: {datetime.now(timezone.utc).isoformat()}_",
        "",
        "## Executive Summary",
        parsed.get("executive_summary", ""),
        "",
        "## Severity Assessment",
        parsed.get("severity_assessment", ""),
        "",
    ]
    for section in parsed.get("sections", []):
        lines.append(f"## {section.get('heading', 'Section')}")
        lines.append(section.get("body", ""))
        refs = section.get("evidence_refs", [])
        if refs:
            lines.append("")
            lines.append(f"_Evidence: {', '.join(refs)}_")
        lines.append("")
    lines.append("---")
    lines.append(parsed.get("disclaimer", ""))
    return "\n".join(lines)
