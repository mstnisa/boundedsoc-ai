"""
Import hub so Alembic autogenerate (and anything else that needs the full
metadata, like app startup) sees every model. Import this module — never
import an individual app.models.* module before this one has run — to avoid
the circular-import trap of models importing Base while Base's own module
tries to import models.
"""

from app.db.base import Base  # noqa: F401
from app.models.alert import Alert  # noqa: E402,F401
from app.models.analyst_review import AnalystReview  # noqa: E402,F401
from app.models.audit_log import AuditLog  # noqa: E402,F401
from app.models.compliance_mapping import ComplianceMapping  # noqa: E402,F401
from app.models.enrichment_result import EnrichmentResult  # noqa: E402,F401
from app.models.event import Event  # noqa: E402,F401
from app.models.evidence_item import EvidenceItem  # noqa: E402,F401
from app.models.incident import Incident  # noqa: E402,F401
from app.models.integration import Integration  # noqa: E402,F401
from app.models.ioc import IOC  # noqa: E402,F401
from app.models.mitre_suggestion import MitreSuggestion  # noqa: E402,F401
from app.models.remediation_suggestion import RemediationSuggestion  # noqa: E402,F401
from app.models.report import Report  # noqa: E402,F401
from app.models.secret_exposure_alert import SecretExposureAlert  # noqa: E402,F401
from app.models.timeline import Timeline, TimelineEvent  # noqa: E402,F401
from app.models.tool_policy import AIActionLog, ToolAccessPolicy  # noqa: E402,F401
from app.models.user import User  # noqa: E402,F401
