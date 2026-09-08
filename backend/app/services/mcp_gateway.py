"""
The single choke point every AI-initiated external tool call must pass
through. This is what turns "the AI can only do what we've explicitly
allowed" from a policy statement into a structural guarantee: Module 1
(Remediation Drafting Agent) and Module 2 (Credential Exposure Response)
literally cannot reach GitHub or a secrets provider except by calling
invoke_tool() below, and invoke_tool() refuses anything not present in the
tool_access_policies table — logging every attempt, allowed or blocked, to
ai_action_log.

Mirrors the same mocked-by-default / opt-in-live pattern already used by
app.adapters (threat-intel enrichment): nothing here ever makes a real
external call unless settings.external_tools_live_mode is explicitly true
AND a matching, enabled Integration row exists. Out of the box (the demo
config) every tool call is safely simulated.
"""

import os
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.integration import Integration
from app.models.tool_policy import AIActionLog, ToolAccessPolicy
from app.services import audit

settings = get_settings()

# Conservative, narrowly-scoped defaults seeded on startup (idempotent — see
# ensure_default_policies). An operator can tighten or widen these later via
# GET/PUT /admin/tool-policies; nothing here grants more than the one action
# each corresponding module actually needs.
DEFAULT_POLICIES: dict[str, dict[str, Any]] = {
    "github": {
        "allowed_actions": ["create_pr"],
        "scope": "Pull-request creation only. No push-to-main, no delete, no admin scope.",
    },
    "secret_provider": {
        "allowed_actions": ["revoke"],
        "scope": "Single-secret revocation only, and only when status=='approved' server-side.",
    },
}


class ToolInvocationBlocked(Exception):
    """Raised when a tool call is refused by policy. Callers must not treat
    this as a transient error — it means the action is not currently
    allowed and requires an admin to change policy, not a retry."""


def ensure_default_policies(db: Session) -> None:
    existing = {p.tool_name for p in db.execute(select(ToolAccessPolicy)).scalars().all()}
    for tool_name, cfg in DEFAULT_POLICIES.items():
        if tool_name in existing:
            continue
        db.add(
            ToolAccessPolicy(
                tool_name=tool_name,
                allowed_actions=cfg["allowed_actions"],
                scope=cfg["scope"],
                updated_by="system",
            )
        )
    db.commit()


def _summarize(params: dict) -> dict:
    """Never let a params dict carry a raw secret into the log — this is a
    log of *what was attempted*, not a place credentials pass through."""
    redacted = {}
    for k, v in params.items():
        if any(tok in k.lower() for tok in ("token", "secret", "password", "key")):
            redacted[k] = "[redacted]"
        else:
            redacted[k] = v
    return redacted


def _mock_github_create_pr(db: Session, params: dict) -> dict:
    repo = params.get("repo_full_name", "unknown/repo")
    return {
        "mode": "mocked",
        "pr_url": f"https://github.com/{repo}/pull/0000-mock-not-a-real-pr",
        "note": "EXTERNAL_TOOLS_LIVE_MODE is off (default) — no real GitHub call was made.",
    }


def _live_github_create_pr(db: Session, params: dict) -> dict:
    integration = (
        db.execute(select(Integration).where(Integration.type == "github", Integration.enabled.is_(True)))
        .scalars()
        .first()
    )
    if not integration:
        raise ToolInvocationBlocked("Live mode is on but no enabled 'github' Integration is configured.")
    token = os.environ.get(integration.config_ref)
    if not token:
        raise ToolInvocationBlocked(
            f"Live mode is on but env var '{integration.config_ref}' referenced by the github "
            "Integration is not set."
        )
    # A real implementation would call the GitHub Contents + Pulls REST API
    # here with `token` (scoped to pull-request creation only, per the
    # Integration's own documented scope). Intentionally not implemented
    # against a live repo in this portfolio build — this is the single spot
    # where that call would be made.
    raise NotImplementedError(
        "Live GitHub PR creation is wired for policy/config but not implemented against a real "
        "repo in this build. Implement the REST call here before enabling EXTERNAL_TOOLS_LIVE_MODE."
    )


def _mock_secret_provider_revoke(db: Session, params: dict) -> dict:
    return {
        "mode": "mocked",
        "revoked": True,
        "note": "EXTERNAL_TOOLS_LIVE_MODE is off (default) — no real provider call was made.",
    }


def _live_secret_provider_revoke(db: Session, params: dict) -> dict:
    provider = params.get("provider", "")
    integration = (
        db.execute(select(Integration).where(Integration.type == provider, Integration.enabled.is_(True)))
        .scalars()
        .first()
    )
    if not integration:
        raise ToolInvocationBlocked(f"Live mode is on but no enabled Integration for provider '{provider}'.")
    raise NotImplementedError(
        f"Live revocation against provider '{provider}' is wired for policy/config but not "
        "implemented in this build. Implement the provider's revoke call here before enabling "
        "EXTERNAL_TOOLS_LIVE_MODE."
    )


_EXECUTORS: dict[tuple[str, str], tuple[Callable, Callable]] = {
    ("github", "create_pr"): (_mock_github_create_pr, _live_github_create_pr),
    ("secret_provider", "revoke"): (_mock_secret_provider_revoke, _live_secret_provider_revoke),
}


def invoke_tool(
    db: Session,
    *,
    tool_name: str,
    action: str,
    params: dict,
    actor: str = "ai",
) -> dict:
    policy = (
        db.execute(select(ToolAccessPolicy).where(ToolAccessPolicy.tool_name == tool_name)).scalars().first()
    )
    allowed = bool(policy and action in policy.allowed_actions)

    log_entry = AIActionLog(
        tool_name=tool_name,
        requested_action=action,
        params_summary=_summarize(params),
        allowed=allowed,
        policy_rule_matched=str(policy.id) if (policy and allowed) else None,
    )
    db.add(log_entry)

    audit.record(
        db,
        actor=actor,
        action=f"gateway.{tool_name}.{action}",
        target=f"tool:{tool_name}",
        reason=(
            "Policy allows this action." if allowed else "Blocked — not present in tool_access_policies."
        ),
        details={"params": _summarize(params), "allowed": allowed},
        commit=False,
    )
    db.commit()

    if not allowed:
        raise ToolInvocationBlocked(f"{tool_name}.{action} is not allowed by current policy.")

    mock_fn, live_fn = _EXECUTORS.get((tool_name, action), (None, None))
    if mock_fn is None:
        return {"mode": "no_executor_registered"}

    if settings.external_tools_live_mode:
        return live_fn(db, params)
    return mock_fn(db, params)
