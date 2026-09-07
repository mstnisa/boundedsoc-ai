# Benchmark Results (measured)

Run at `2026-09-07T06:01:44Z` against `http://localhost:8000`, over 5 hand-labeled synthetic cases (`data/eval/eval_cases.json`), using the default mocked TI providers and the mock LLM provider (`LLM_PROVIDER=mock`).

**These are real measured numbers from an actual run of this script (`scripts/benchmark.py`) against a live backend -- not projections.**

## Timing (assisted workflow, measured)

- Time-to-triage (ingest -> AI severity suggestion): mean 0.091s, median 0.049s
- Time-to-report-draft (ingest -> AI report draft): mean 0.121s, median 0.075s
- IOC enrichment latency (mocked TI adapters): mean 0.008s

These are local, single-process, mocked-provider timings (no real network TI calls, no real LLM API latency) -- they measure the orchestration/DB overhead of the pipeline itself, not what a live deployment with real providers would see.

## MITRE ATT&CK suggestion accuracy (measured vs. hand-labeled ground truth)

- Mean precision: 0.80
- Mean recall: 0.80
- Mean F1: 0.80

## Incident-level classification (malicious vs. benign, vs. hand-labeled ground truth)

- Confusion matrix: {'TP': 3, 'FP': 1, 'TN': 1, 'FN': 0}
- Accuracy: 0.80
- False positive rate: 0.50
- False negative rate: 0.00

*'Predicted malicious' = AI severity suggestion was high/critical OR at least one MITRE technique was suggested. This is a simple, transparent rule chosen for this benchmark -- it is not the product's own decision logic, which never auto-labels an incident at all (see the human-review requirement).*

## API reliability

- Total API requests made during this run: 35
- Failed (>=400) requests: 0
- Failure rate: 0.00%

## Evidence / hallucination guardrail stats

- Total AI suggestion attempts (severity + MITRE): 10
- Accepted (evidence-backed): 10
- Dropped (missing/hallucinated evidence): 0
- Drop rate: 0.00%

A 'drop' means a claim was rejected before ever reaching the database because it lacked a valid evidence_ref -- this is the guardrail working, not a hallucination that leaked through. With the default mock LLM provider, the drop rate is structurally 0% because the mock only ever echoes evidence_id tokens it was actually given (see tests/adversarial/test_prompt_injection.py for a test using a deliberately hallucinating provider, which confirms the drop path itself works).

## What is explicitly NOT measured here

- **Human correction rate**: NOT MEASURED. This requires real analysts using the review endpoint over time; no live analyst usage has occurred yet. The review/audit infrastructure to measure this (analyst_reviews.decision counts vs total AI suggestions) is implemented and ready -- see app.api.routes.incidents:submit_incident_review and GET /audit-logs -- but the number itself does not exist until real analysts generate it. Treat this as a roadmap item, not an omitted result.
- **Manual-workflow timing**: Manual-workflow figures are a DOCUMENTED STEP COUNT, not a timed duration -- no human analysts were available to time a fully manual investigation of these cases. See MANUAL_STEPS_PER_CASE and ASSISTED_ANALYST_ACTIONS_PER_CASE in this script. Do not read the numbers below as a measured time-savings claim.

## Manual (documented, unmeasured) vs. assisted (measured) step count

| | Manual (documented estimate) | Assisted (this tool) |
|---|---|---|
| Analyst actions per case | read alert, extract IOCs by hand, one TI lookup per IOC, map to MITRE manually, reconstruct timeline manually, draft report, peer review = 6 fixed steps + 1 per IOC | 6 fixed dashboard actions, regardless of IOC count |

## Per-case detail

| Case | Confusion | Severity (pred / expected band) | MITRE F1 | Time-to-report (s) |
|---|---|---|---|---|
| malicious-powershell-c2 | TP | high / ['high', 'critical'] | 1.00 | 0.298 |
| malicious-credential-dumping | TP | medium / ['high', 'critical'] | 1.00 | 0.075 |
| benign-admin-powershell | TN | low / ['low', 'unknown'] | 1.00 | 0.068 |
| benign-single-failed-logon | FP | low / ['low', 'unknown'] | 0.00 | 0.071 |
| malicious-brute-force-only | TP | low / ['medium', 'high'] | 1.00 | 0.093 |

---

Re-run this benchmark yourself: `python scripts/benchmark.py` (backend must be running locally, e.g. via `docker-compose up`). Re-running overwrites this file with a fresh, equally-real measurement.
