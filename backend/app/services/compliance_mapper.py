"""
Maps already-approved findings (currently: approved/edited MITRE
suggestions) to controls in a compliance framework, using small bundled
reference JSON files (data/compliance/*.json) — same pattern as
data/mitre/attack_subset.json. Always labeled as informational mapping, not
a certification (see docs/business-value.md and the UI copy).
"""

import json
from functools import lru_cache
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.compliance_mapping import ComplianceMapping
from app.models.incident import Incident
from app.services import audit

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "compliance"
SUPPORTED_FRAMEWORKS = ("owasp_top10", "pci_dss", "iso27001", "gdpr")


@lru_cache(maxsize=8)
def load_framework(framework: str) -> dict:
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"Unknown framework '{framework}'. Supported: {SUPPORTED_FRAMEWORKS}")
    return json.loads((DATA_DIR / f"{framework}.json").read_text())


def map_incident(db: Session, incident: Incident, framework: str, actor: str) -> list[ComplianceMapping]:
    ref = load_framework(framework)
    approved = [s for s in incident.mitre_suggestions if s.status in ("approved", "edited")]

    created: list[ComplianceMapping] = []
    for suggestion in approved:
        for control in ref["controls"]:
            if suggestion.technique_id not in control["mitre_technique_ids"]:
                continue
            mapping = ComplianceMapping(
                incident_id=incident.id,
                finding_type="mitre_suggestion",
                finding_id=suggestion.id,
                framework=framework,
                control_id=control["control_id"],
                control_title=control["control_title"],
                confidence=suggestion.confidence,
                rationale=(
                    f"Analyst-approved MITRE technique {suggestion.technique_id} "
                    f"({suggestion.technique_name}) maps to {framework} control {control['control_id']}."
                ),
                evidence_refs=suggestion.evidence_refs,
            )
            db.add(mapping)
            created.append(mapping)

    db.flush()
    audit.record(
        db,
        actor=actor,
        action="incident.compliance_mapping",
        target=f"incident:{incident.id}",
        reason=(
            f"Mapped {len(created)} approved finding(s) to {framework} controls. "
            "Informational mapping only — not a compliance certification."
        ),
        details={"framework": framework, "mapping_count": len(created)},
        commit=False,
    )
    db.commit()
    for m in created:
        db.refresh(m)
    return created


def coverage(db: Session) -> dict:
    """Org-wide aggregate: how many distinct controls have at least one
    mapping, per framework — a rough 'what have we got evidence for' view,
    not a compliance score."""
    rows = db.execute(select(ComplianceMapping)).scalars().all()
    result: dict[str, dict] = {}
    for fw in SUPPORTED_FRAMEWORKS:
        ref = load_framework(fw)
        total_controls = len(ref["controls"])
        covered_controls = {r.control_id for r in rows if r.framework == fw}
        result[fw] = {
            "total_controls": total_controls,
            "controls_with_evidence": len(covered_controls),
            "mapping_count": len([r for r in rows if r.framework == fw]),
        }
    return result
