"""
Human-in-the-loop review: the only place any AI claim becomes "approved".
Every decision is stored (append-only, via analyst_reviews) and audited.
Edits/rejections mutate the target entity's status so the dashboard and
API always reflect the human's final word, never silently keep the AI's
original claim as authoritative.
"""

import uuid

from sqlalchemy.orm import Session

from app.models.analyst_review import AnalystReview
from app.models.incident import Incident
from app.models.mitre_suggestion import MitreSuggestion
from app.models.report import Report
from app.services import audit


def submit_review(
    db: Session,
    *,
    user_id: uuid.UUID,
    actor_email: str,
    target_entity_type: str,
    target_entity_id: uuid.UUID,
    decision: str,
    comment: str | None,
    correction: str | None,
) -> AnalystReview:
    review = AnalystReview(
        user_id=user_id,
        target_entity_type=target_entity_type,
        target_entity_id=target_entity_id,
        decision=decision,
        comment=comment,
        correction=correction,
    )
    db.add(review)
    db.flush()

    if target_entity_type == "mitre_suggestion":
        suggestion = db.get(MitreSuggestion, target_entity_id)
        if suggestion:
            suggestion.status = {"approve": "approved", "edit": "edited", "reject": "rejected"}[decision]
            if decision == "edit" and correction:
                suggestion.rationale = correction
            db.add(suggestion)

    elif target_entity_type == "report":
        report = db.get(Report, target_entity_id)
        if report:
            report.status = {"approve": "approved", "edit": "draft", "reject": "rejected"}[decision]
            if decision == "edit" and correction:
                report.content = correction
                report.version += 1
                report.generated_by = "analyst"
            db.add(report)

    elif target_entity_type == "incident_severity":
        incident = db.get(Incident, target_entity_id)
        if incident:
            if decision == "edit" and correction:
                incident.severity = correction
            incident.severity_source = "analyst"
            db.add(incident)

    audit.record(
        db,
        actor=actor_email,
        action=f"review.{decision}",
        target=f"{target_entity_type}:{target_entity_id}",
        reason=comment or f"Analyst {decision} via review endpoint.",
        details={"correction": correction},
        commit=False,
    )
    db.commit()
    db.refresh(review)
    return review
