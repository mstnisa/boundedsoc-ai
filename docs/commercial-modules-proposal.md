# Commercial Module Proposal — Now Implemented

Status: **IMPLEMENTED.** All five modules below were approved and built in
this order: MCP/API Security Gateway → ML Prefilter → Compliance Mapper →
Remediation Drafting Agent → Credential Exposure Response, each with its own
backend tests (`backend/tests/api/test_commercial_modules.py`, 6 tests, all
passing alongside the original 55) and a corresponding UI tab or page. This
document is kept as the design record; anywhere it originally said "will"
now means "does."

Every module below follows the three guarantees already built into this
repo, and none of them may be relaxed:

1. An AI-generated action is *proposed*, never *executed*, until a human
   approves it (`analyst_reviews`, same pattern as MITRE/severity today).
2. Every AI claim must resolve to real evidence or it's dropped before
   persistence (`EvidenceItem`, same guardrail as today).
3. Every consequential action — proposed, approved, rejected, or executed —
   is written to the append-only `audit_logs` table.

---

## 1. Remediation Drafting Agent

**What it does:** for a code-level finding tied to an incident, drafts a
fix on a new branch and opens a GitHub Pull Request for a developer to
review. It never merges anything itself.

**Data model** (new tables, same style as `mitre_suggestions`):

```
remediation_suggestions
  id, incident_id, repo_full_name, file_path,
  vulnerable_snippet, proposed_patch, cwe_ref,
  confidence, rationale, evidence_refs (json),
  status (pending | approved | edited | rejected),
  pr_url (nullable), created_at
```

`Integration` (existing table) gains a `github` type row per repo, holding
a fine-grained PAT scoped to **pull-request creation only** — no push-to-main,
no delete, no admin scope.

**API:**

- `POST /incidents/{id}/remediation-suggestions` — AI drafts a suggestion (proposal only, no GitHub call yet)
- `POST /incidents/{id}/remediation-suggestions/{rid}/review` — reuses the existing review endpoint (approve/edit/reject)
- `POST /incidents/{id}/remediation-suggestions/{rid}/create-pr` — **separate, explicit action**, only callable when status is `approved`; this is the one call that actually writes to GitHub

Splitting "approve" and "create PR" into two distinct human actions (not
one) is deliberate — an analyst approving a suggestion in the review queue
should never silently trigger a write to a company's source repo.

**UI:** a new "Remediation" tab on Incident Detail, shown only when a
finding has a linked repo. Same card pattern as MITRE suggestions
(rationale + evidence), with a before/after code diff, Approve/Edit/Reject,
and a "Create Pull Request" button that only appears after approval.

---

## 2. Credential Exposure Response

**What it does:** when a leaked secret is detected, prepares a revocation
request. An analyst must approve it before anything is revoked — no
autonomous revocation, for the reasons discussed (false-positive blast
radius, and it becomes a denial-of-service vector if automated).

**Data model:**

```
secret_exposure_alerts
  id, incident_id, secret_type (api_key | aws_token | db_password | generic),
  masked_value (prefix/hash only — the raw secret is never stored),
  source_ref, provider, status (pending | approved | revoked | rejected),
  approved_by, approved_at, revoked_at,
  escalation_deadline (nullable), created_at
```

**API:**

- `POST /incidents/{id}/secret-exposure` — AI/detector creates the alert (pending)
- `POST /incidents/{id}/secret-exposure/{sid}/review` — approve/reject (existing pattern)
- `POST /incidents/{id}/secret-exposure/{sid}/revoke` — **server-side enforces `status == 'approved'`** before calling the provider's revoke API; this check happens in the service layer, not just the UI, so it can't be bypassed by a direct API call either

An optional escalation timer can page an on-call analyst if a critical
alert sits un-reviewed too long — but even escalation only *notifies*, it
never auto-revokes. That line doesn't move.

**UI:** a red-bordered alert card, "Revoke Now" button appears only after
approval; masked value shown, never the real secret.

---

## 3. MCP / API Security Gateway

**What it does:** a policy-enforcing choke point that every AI-initiated
tool call (GitHub writes from Module 1, provider calls from Module 2, any
future tool) must pass through. This is what makes "the AI can only do
what we've explicitly allowed" a structural guarantee instead of a promise.

**Data model:**

```
tool_access_policies
  id, tool_name, allowed_actions (json list),
  scope (e.g. repo allowlist), updated_by, updated_at

ai_action_log
  id, tool_name, requested_action, params_summary,
  allowed (bool), policy_rule_matched, timestamp
```

**Service:** `services/mcp_gateway.py` exposes one function,
`invoke_tool(tool_name, action, params, actor="ai")`, that every other
service (github_integration, provider revocation calls) must route
through. It checks the policy table, logs every attempt — allowed or
blocked — and refuses anything not explicitly allow-listed.

**API:** `GET /admin/tool-policies`, `PUT /admin/tool-policies/{tool_name}`
— admin-role-gated, same RBAC pattern as the existing `/integrations` write endpoint.

**UI:** an "AI Tool Policies" panel under the Integrations page (admin only).

---

## 4. Compliance Mapper

**What it does:** maps already-approved findings to OWASP Top 10, PCI DSS,
ISO 27001, and GDPR controls. **Labeled everywhere as informational
mapping, not a certification** — an external auditor certifies compliance,
this tool helps prepare evidence for that audit.

**Data model:**

```
compliance_mappings
  id, finding_type, finding_id, framework,
  control_id, control_title, confidence, rationale,
  evidence_refs (json), created_at
```

Reference data ships as static JSON (same pattern as `data/mitre/attack_subset.json`):
`data/compliance/{owasp_top10,pci_dss,iso27001,gdpr}.json`.

**API:**

- `POST /incidents/{id}/compliance-mapping` — maps this incident's approved findings
- `GET /incidents/{id}/compliance-report?framework=pci_dss`
- `GET /compliance/coverage` — org-wide aggregate

**UI:** a "Compliance" tab on Incident Detail, plus a new sidebar item
showing an org-wide coverage dashboard (reuses the Dashboard KPI-tile/chart
pattern already built).

---

## 5. Lightweight ML Prefilter

**What it does:** a small classical model (Random Forest to start) scores
incoming alerts as "routine" (port scans, brute-force patterns already
seen many times) vs. "needs review" *before* anything reaches the LLM
reasoning layer — cutting AI cost/latency without silently discarding
anything a human can't see.

**Data model:** extend `alerts` / `incidents` with
`ml_triage_label` (routine | needs_review), `ml_confidence`, `ml_model_version`.

**Where it plugs in:** a new step in the ingestion pipeline, right after
`normalization.py` and before the AI reasoning graph is invoked. "Routine"
alerts still get created and stay fully visible/reversible in the queue —
never silently dropped — just deprioritized and skipped for expensive LLM
analysis unless an analyst manually requests it.

**Training data honesty:** the shipped model is trained on public/synthetic
data (not live customer traffic), documented plainly in the Limitations
section — same honesty pattern the README already uses for the mock LLM
provider.

**UI:** a small "ML: routine" / "ML: escalated" badge on the Dashboard and
Incident Queue rows.

---

## Suggested build order

1. **MCP/API Security Gateway** first — it's the foundation everything
   else (Module 1 and 2's tool calls) should route through from day one,
   rather than retrofitting the gate later.
2. **ML Prefilter** — self-contained, no new external integrations, fastest to ship and demo.
3. **Compliance Mapper** — self-contained, high commercial visibility, no write access to anything external.
4. **Remediation Drafting Agent** — needs the Gateway (step 1) and a GitHub integration.
5. **Credential Exposure Response** — needs the Gateway and a provider-revocation integration (start with one provider, e.g. GitHub token revocation, before adding AWS/others).

This order ships something demoable after every step, and the two modules
with real external write-access (4 and 5) come last, once the gateway that
constrains them already exists.
