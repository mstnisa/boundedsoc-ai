"""
Remediation Drafting Agent (Module 1 of the commercial proposal). Drafts an
illustrative code-level fix tied to an approved MITRE finding. Deterministic
and rule-based (same explainability posture as ioc_extraction.py), not an
LLM call — there is no real source-repo scanning in this build, so every
suggestion says so plainly rather than pretending to have read the
analyst's actual codebase.

It NEVER opens a pull request itself. Approving a suggestion here only
changes its status; a separate, explicit call to create_pr() — gated on
status == 'approved' and routed through services.mcp_gateway — is the only
thing that ever reaches GitHub.
"""

from sqlalchemy.orm import Session

from app.ai.context import build_incident_context
from app.models.incident import Incident
from app.models.remediation_suggestion import RemediationSuggestion
from app.services import audit, mcp_gateway

# Illustrative fix templates keyed by MITRE technique. These are generic,
# labeled-as-generic patterns — not output from scanning any real
# repository — meant to demonstrate the workflow, not to be applied blindly.
_TEMPLATES: dict[str, dict[str, str]] = {
    "T1059.001": {
        "file_path": "scripts/deploy.ps1",
        "vulnerable_snippet": "Invoke-Expression $userSuppliedCommand",
        "proposed_patch": (
            "# Avoid dynamic script execution from untrusted input.\n"
            "# Replace Invoke-Expression with an explicit allow-listed command dispatch:\n"
            "switch ($userSuppliedCommand) {\n"
            "    'deploy'  { Start-Deploy }\n"
            "    'rollback'{ Start-Rollback }\n"
            '    default   { throw "Unrecognized command: $userSuppliedCommand" }\n'
            "}"
        ),
        "cwe_ref": "CWE-78",
    },
    "T1110": {
        "file_path": "app/auth/login.py",
        "vulnerable_snippet": "def login(username, password):\n    # no attempt limiting\n    return check_credentials(username, password)",
        "proposed_patch": (
            "def login(username, password):\n"
            "    if rate_limiter.too_many_attempts(username):\n"
            "        raise AccountLockedError()\n"
            "    ok = check_credentials(username, password)\n"
            "    rate_limiter.record_attempt(username, ok)\n"
            "    return ok"
        ),
        "cwe_ref": "CWE-307",
    },
    "T1003.001": {
        "file_path": "infra/endpoint-hardening.md",
        "vulnerable_snippet": "(no LSASS protection configured)",
        "proposed_patch": (
            "Enable Credential Guard / LSA Protection (RunAsPPL) via Group Policy, "
            "and restrict debug-privilege delegation to break common LSASS-dumping "
            "tool chains (e.g. Mimikatz, procdump)."
        ),
        "cwe_ref": "CWE-522",
    },
}


def draft_remediation(
    db: Session, incident: Incident, actor: str, repo_full_name: str
) -> RemediationSuggestion | None:
    ctx = build_incident_context(db, incident)
    approved = [s for s in incident.mitre_suggestions if s.status in ("approved", "edited")]

    template = None
    matched_technique = None
    for s in approved:
        if s.technique_id in _TEMPLATES:
            template = _TEMPLATES[s.technique_id]
            matched_technique = s
            break

    if template is None or matched_technique is None:
        audit.record(
            db,
            actor=actor,
            action="incident.remediation.suggest.dropped",
            target=f"incident:{incident.id}",
            reason="No approved MITRE finding with a known remediation template; nothing drafted.",
        )
        return None

    evidence_refs = matched_technique.evidence_refs or list(ctx.evidence_index.keys())[:1]

    suggestion = RemediationSuggestion(
        incident_id=incident.id,
        repo_full_name=repo_full_name,
        file_path=template["file_path"],
        vulnerable_snippet=template["vulnerable_snippet"],
        proposed_patch=template["proposed_patch"],
        cwe_ref=template["cwe_ref"],
        confidence=matched_technique.confidence,
        rationale=(
            f"Illustrative fix pattern for {matched_technique.technique_id} "
            f"({matched_technique.technique_name}), based on the analyst-approved MITRE finding. "
            "This is a generic pattern, not a scan of your actual repository — review the diff "
            "against your real code before creating a PR."
        ),
        evidence_refs=evidence_refs,
        status="pending",
    )
    db.add(suggestion)
    db.flush()

    audit.record(
        db,
        actor=actor,
        action="incident.remediation.suggest",
        target=f"incident:{incident.id}",
        reason=f"Drafted a remediation suggestion for {matched_technique.technique_id}, pending analyst review.",
        details={"suggestion_id": str(suggestion.id), "requires_human_approval": True},
        commit=False,
    )
    db.commit()
    db.refresh(suggestion)
    return suggestion


def create_pr(db: Session, suggestion: RemediationSuggestion, actor: str) -> RemediationSuggestion:
    if suggestion.status != "approved":
        raise ValueError("Only an approved remediation suggestion can have a PR created.")

    result = mcp_gateway.invoke_tool(
        db,
        tool_name="github",
        action="create_pr",
        params={
            "repo_full_name": suggestion.repo_full_name,
            "file_path": suggestion.file_path,
            "patch_preview": suggestion.proposed_patch[:200],
        },
        actor=actor,
    )
    suggestion.pr_url = result.get("pr_url")
    db.add(suggestion)

    audit.record(
        db,
        actor=actor,
        action="incident.remediation.create_pr",
        target=f"remediation_suggestion:{suggestion.id}",
        reason=f"Analyst-triggered PR creation via the MCP gateway ({result.get('mode')} mode).",
        details={"pr_url": suggestion.pr_url, "mode": result.get("mode")},
        commit=False,
    )
    db.commit()
    db.refresh(suggestion)
    return suggestion
