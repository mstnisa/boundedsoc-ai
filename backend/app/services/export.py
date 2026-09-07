"""Report export: markdown (native), JSON (full evidence-backed structure),
and PDF (rendered from the markdown with fpdf2 — pure-Python, no system
dependencies)."""
import json
from io import BytesIO

from fpdf import FPDF
from sqlalchemy.orm import Session

from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.ioc import IOC
from app.models.mitre_suggestion import MitreSuggestion
from app.models.report import Report


def export_markdown(report: Report) -> bytes:
    return report.content.encode("utf-8")


def export_json(db: Session, incident: Incident, report: Report) -> bytes:
    iocs = db.query(IOC).filter(IOC.incident_id == incident.id).all()
    mitre = db.query(MitreSuggestion).filter(MitreSuggestion.incident_id == incident.id).all()
    evidence = (
        db.query(EvidenceItem)
        .filter(
            EvidenceItem.related_entity_type.in_(["incident_severity", "mitre_suggestion", "report"]),
        )
        .all()
    )

    payload = {
        "incident": {
            "id": str(incident.id),
            "title": incident.title,
            "severity": incident.severity.value,
            "severity_source": incident.severity_source,
            "status": incident.status.value,
        },
        "report": {
            "id": str(report.id),
            "version": report.version,
            "status": report.status,
            "generated_by": report.generated_by,
            "model_metadata": report.model_metadata,
            "content_markdown": report.content,
        },
        "iocs": [{"type": i.type.value, "value": i.value} for i in iocs],
        "mitre_suggestions": [
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "rationale": m.rationale,
                "confidence": m.confidence,
                "evidence_refs": m.evidence_refs,
                "status": m.status,
            }
            for m in mitre
        ],
        "evidence_items": [
            {
                "related_entity_type": e.related_entity_type,
                "related_entity_id": str(e.related_entity_id),
                "source": e.source,
                "confidence": e.confidence,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in evidence
        ],
        "ai_generated_disclaimer": (
            "All AI-derived fields in this export are recommendations pending or "
            "subject to human analyst review, not final determinations."
        ),
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def _wrap_long_tokens(text: str, max_token_len: int = 60) -> str:
    """fpdf2's multi_cell can't break a single unbroken token wider than the
    page (e.g. a long evidence-ref list with no spaces); insert soft breaks."""
    words = text.split(" ")
    wrapped = []
    for word in words:
        if len(word) > max_token_len:
            wrapped.append(" ".join(word[i : i + max_token_len] for i in range(0, len(word), max_token_len)))
        else:
            wrapped.append(word)
    return " ".join(wrapped)


def export_pdf(report: Report) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)

    def cell(text: str, size: int, style: str = "", height: int = 6):
        pdf.set_font("Helvetica", style, size)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, height, text if text.strip() else " ")
        pdf.set_font("Helvetica", size=11)

    for raw_line in report.content.split("\n"):
        line = _wrap_long_tokens(raw_line.encode("latin-1", "replace").decode("latin-1"))
        if line.startswith("# "):
            cell(line[2:], 16, "B", 10)
        elif line.startswith("## "):
            cell(line[3:], 13, "B", 8)
        elif line.startswith(">"):
            cell(line.lstrip("> "), 10, "I", 6)
        else:
            cell(line, 11, "", 6)

    buf = BytesIO()
    pdf.output(buf)
    return buf.getvalue()
