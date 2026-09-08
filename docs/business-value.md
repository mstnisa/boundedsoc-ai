# Business Value — Why This Matters to Banks and Corporate Security Teams

This document translates the technical architecture of AI SOC Workbench into
the language a hiring manager, CISO, or bank IT-security auditor actually
cares about. It is written to sit alongside the technical README, not
replace it — every claim here traces back to a real, working part of the
codebase (see the "Where this lives in the code" line under each point).

**Positioning in one line:** a working demonstration of how a bank or
corporate SOC can use AI to cut analyst triage time, without ever letting a
model autonomously block, isolate, or close anything — which is exactly the
posture regulators and risk committees in the financial sector require.

---

## The problem banks and corporates actually have

A SOC (Security Operations Center) inside a bank or large corporate handles
a high volume of repetitive alerts — failed logins, suspicious script
execution, unusual outbound traffic — most of which are noise, a few of
which are real. Two pressures pull in opposite directions:

- **Speed pressure**: analysts are expected to triage faster, and "add AI"
  is the obvious answer.
- **Control pressure**: a bank cannot let an AI model autonomously lock an
  account, isolate a production server, or close an incident — one wrong
  automated action against a core banking system is a bigger operational
  risk than the alert it was reacting to. This is why frameworks banks are
  actually held to (Bangladesh Bank's ICT Security Guideline, PCI DSS for
  card data, SWIFT's Customer Security Programme, ISO 27001) all converge on
  the same requirement: a human accountable for the decision, and a
  complete, tamper-evident record of who decided what and why.

Most "AI SOC" demos optimize for the first pressure and ignore the second.
This project is built the other way around: the human-approval boundary is
the design, not a policy note added afterward.

## How the architecture maps to what a bank's risk/compliance function checks for

| What a bank's auditor or risk committee asks | How this project answers it | Where it lives in the code |
|---|---|---|
| "Can the system take action on its own?" | No — there is no code path that isolates a host, blocks an IP, or closes an incident automatically. The AI proposes; a named human approves, edits, or rejects. | `services/review.py`, `models/analyst_review.py` |
| "Can we prove an AI claim isn't fabricated?" | Every AI-generated claim (severity, MITRE technique, report line) must resolve to real evidence that exists in the system, or it is dropped before it's ever stored — and the drop itself is logged. | `models/evidence_item.py`, adversarial test suite (`tests/adversarial/`) |
| "Do we have a complete audit trail for regulators?" | Every consequential action — proposed, approved, rejected, or exported — writes to an append-only audit log: who, what, when, why. | `services/audit.py`, `models/audit_log.py` |
| "How do we know the AI's reasoning, not just its answer?" | Every suggestion carries a plain-language rationale and links to the specific event/IOC evidence it's based on — an analyst can click through and verify it, not just trust a score. | Incident Detail → MITRE Suggestions tab |
| "What happens with a prompt-injection attempt inside a malicious log line?" | Untrusted alert text is never placed in a system-role prompt; there's a dedicated adversarial test suite that stress-tests this specifically, not just a claim in a document. | `tests/adversarial/`, `docs/threat-model.md` |
| "Is data handling reversible / non-destructive?" | Nothing is deleted. Rejected suggestions stay visible with their rejection reasoning, not silently removed. | Audit Trail page |

This table is also, functionally, a map of exactly what a bank's SOC
engineering interview will ask about — which is the practical reason it
belongs in a CV-facing project.

## Where this fits operationally in a bank's SOC

- **Alert triage acceleration**: the correlation, IOC extraction, and
  enrichment layers do in seconds what a Tier-1 analyst does manually —
  group related log lines into one incident, pull out IPs/domains/hashes,
  and check them against threat intelligence.
- **MITRE ATT&CK mapping for reporting**: banks increasingly have to report
  incidents against MITRE ATT&CK for regulators and cyber-insurance —
  this is drafted automatically and then signed off by a human, instead of
  written from scratch under time pressure.
- **Audit-ready by default**: the append-only log is the kind of artifact a
  bank's internal audit or an external SWIFT CSP assessor asks for directly
  — this project produces it as a byproduct of normal use, not as a
  separate reporting exercise.

## For your CV / recruiter conversations

Framed honestly, this project demonstrates exactly the skill set banking
and corporate security teams hire for: building AI-assisted tools that
respect a human-approval boundary, evidence-based reasoning instead of
black-box scoring, and audit-first engineering. Suggested CV phrasing:

- Designed and built an AI-assisted SOC investigation platform (FastAPI,
  PostgreSQL, LangGraph, React) implementing evidence-gated AI reasoning
  and human-in-the-loop approval — the same control pattern financial-sector
  security teams require before adopting AI in a SOC.
- Implemented a structural (not policy-based) guardrail ensuring 0% of
  persisted AI claims lack a verifiable evidence reference, validated by a
  dedicated adversarial test suite covering prompt-injection and
  hallucination scenarios.
- Built an append-only audit-logging architecture covering every AI
  suggestion and every human decision, matching the accountability
  requirements of frameworks such as ISO 27001 and Bangladesh Bank's ICT
  Security Guideline.

## A short pitch for LinkedIn / a portfolio page

> AI SOC Workbench is a working demonstration of how banks and large
> corporates can bring AI into security operations without giving up
> control: every AI-generated finding — severity, MITRE technique mapping,
> incident report — must cite real evidence and is held pending until a
> human analyst approves it. Built end-to-end (FastAPI/PostgreSQL backend,
> LangGraph reasoning layer, React dashboard) with an append-only audit
> trail and an adversarial test suite that specifically targets
> prompt-injection and AI-hallucination scenarios — because in a banking
> SOC, "the AI said so" is never an acceptable answer on its own.

## Honest boundaries (read this before pitching it as bank-ready)

Being credible with a technical interviewer or auditor means not
overstating this, so say it plainly, same as the README does:

- This is a **portfolio-grade demonstration**, not an audited or
  bank-certified product. No claim here should be read as "this meets
  PCI DSS" or "this is SWIFT CSP-compliant" — it is built in a way that is
  *architecturally consistent* with what those frameworks require
  (human approval, audit trail, evidence-based claims), which is a true and
  valuable thing to say, and a different thing from certification.
- The default AI "reasoning" is a deterministic mock, not a live LLM —
  swapping in a real model is a one-line config change, but the numbers in
  this repo were produced against the mock, and that's stated wherever
  those numbers appear.
- Authentication is single-user demo mode by default; multi-user RBAC
  exists in the code but real production auth (SSO/MFA integration a bank
  would require) is not built.
- All data used and shown is synthetic. No real bank, customer, or
  production system data has ever touched this project.

Say this upfront in an interview rather than waiting to be asked — it is
what makes the rest of the pitch credible instead of inflated.
