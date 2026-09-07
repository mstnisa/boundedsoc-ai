# Security Policy

## Scope and intent

This is a portfolio/research project, not a production security product. It
processes **synthetic data only** by design (see the project's core
principle: no real customer data, ever). That said, it is built the way a
production tool would be, and this document is written the way a real
security policy would be.

## Reporting a vulnerability

This is a personal open-source project. If you find a security issue,
please open a GitHub issue tagged `security` or contact the maintainer
directly rather than filing a public exploit write-up. There is no bug
bounty.

## Secrets handling

- No secret, API key, or credential is ever hard-coded anywhere in this
  repository. `.env.example` documents every expected variable with
  placeholder values; the real `.env` is git-ignored (see `.gitignore`).
- Threat-intelligence and LLM provider API keys are only ever read from
  environment variables at runtime (`app/core/config.py`), never logged, and
  never included in `audit_logs`, `evidence_items`, or exported reports.
  `integrations.config_ref` stores the *name* of the environment variable
  that holds a secret, never the secret's value.
- `APP_SECRET_KEY` and `JWT_SECRET_KEY` in `.env.example` are placeholder
  values (`change-me...`). Never deploy with the example values.

## AuthN/AuthZ

- Default local/demo config runs in `AUTH_SINGLE_USER_MODE=true`: every
  request resolves to a fixed local analyst identity with no login step,
  matching the brief ("single-user mode may skip JWT initially").
- Setting `AUTH_SINGLE_USER_MODE=false` turns on real JWT bearer auth
  (`app/core/security.py`, PyJWT) with three roles (`analyst`,
  `senior_analyst`, `admin`). `require_role(...)` gates the two endpoints
  where it matters most: submitting an analyst review decision
  (`POST /incidents/{id}/review`) and configuring integrations
  (`POST /integrations`, admin-only).
- Passwords are hashed with bcrypt (via passlib) and never stored or logged
  in plaintext.

## Prompt-injection defense

Every piece of ingested alert/log text is untrusted by construction. See
`app/ai/guardrails.py` and `app/ai/context.py`:

- Raw ingested text is never placed in an LLM **system**-role prompt — only
  in the user message, and only inside an explicitly delimited
  `--- BEGIN UNTRUSTED ... --- END UNTRUSTED ...` block that instructs the
  model to treat it as inert data.
- Known injection patterns ("ignore previous instructions", role-switch
  markers like `</system><system>`, etc.) are detected and flagged into the
  audit trail (not silently dropped — visibility matters more than
  filtering for this threat).
- Every AI claim (severity, MITRE technique, report section) must cite at
  least one `evidence_id` that was actually present in the context handed
  to the model. A claim whose evidence doesn't resolve to a real
  `EvidenceItem` is dropped before it ever reaches the database, and the
  drop itself is recorded in `audit_logs` with the reason. See
  `tests/adversarial/test_prompt_injection.py`, including a test that swaps
  in a deliberately hallucinating provider to prove the drop path works.

## Dependency management

- `pip-audit` (backend) and `npm audit` (frontend) run in CI on every push
  (`.github/workflows/ci.yml`), non-blocking (`|| true`) so a new
  advisory doesn't silently break deploys, but visible in every CI run.
- **Known accepted risk, tracked**: `starlette` (a FastAPI dependency) has
  several CVE advisories whose fix versions (`1.0.1`+) are not yet
  compatible with the pinned FastAPI release this project uses
  (`fastapi>=0.118,<0.119` requires `starlette<0.49`). This is an
  upstream-ecosystem lag, not a choice made in this codebase — revisit by
  bumping FastAPI once it supports Starlette 1.x.
- **Known accepted risk, tracked**: `ecdsa` (a transitive dependency
  previously pulled in by `python-jose`) has an unfixed timing-attack
  advisory. This project no longer depends on `python-jose` at all — JWT
  handling was moved to `PyJWT` (`app/core/security.py`) specifically to
  drop this dependency chain.
- The frontend has one remaining advisory (`esbuild`/`vite` dev-server
  cross-origin request handling, moderate severity) that only affects the
  local `vite dev` server, not the built production bundle served by
  Docker/`serve`. Fixing it requires a Vite major-version bump; tracked as
  a roadmap item rather than applied blind given the breaking-change scope.

## Human-in-the-loop as a security control

The product's core safety property is also a security property: the AI
layer (`app/ai/`, `app/services/ai_orchestration.py`) never calls any
response/remediation API, never has network or shell tool access, and never
transitions an incident to a closed/actioned state on its own — every
consequential state change requires a human review decision
(`app/services/review.py`). There is no code path, anywhere in this
repository, that lets a model output result in isolating a host, blocking
an IP, or deleting evidence. See `docs/threat-model.md` for the full
analysis.

## Audit logging

`audit_logs` is append-only by construction: `app/models/audit_log.py` and
`app/services/audit.py` are the only writer, and no route or service in the
codebase ever issues an `UPDATE` or `DELETE` against that table. Every
ingestion, extraction, enrichment, AI suggestion (including dropped ones),
review decision, and export is recorded with actor/action/target/reason.
