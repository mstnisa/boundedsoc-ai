# Demo Walkthrough

This is a real run of `data/synthetic/demo_incident_powershell.json` through
the live API, captured directly from a running backend (no fabricated
responses — every JSON block below is a real response with real generated
IDs; yours will differ, the shape and content won't).

## The scenario

Six synthetic Wazuh-style alerts on host `WKSTN-FIN-07`: three failed
logons for `j.rahman` from `185.220.101.47`, then a successful logon, then
Sysmon-observed encoded PowerShell (`-enc ...`) that decodes to a
`DownloadString` call against `http://evil-c2.badguy.net/payload.ps1`, then
an outbound network connection to that same domain. This is a textbook
brute-force -> account-takeover -> C2 payload-download chain.

## 1. Ingest

```bash
curl -X POST http://localhost:8000/alerts \
  -H "Content-Type: application/json" \
  -d @data/synthetic/demo_incident_powershell.json
```

```json
{
  "ingested": 6,
  "alert_ids": ["63deff47-...", "5bf7641d-...", "75fef30c-...", "e3f35c30-...", "7a8be111-...", "ca8bd41b-..."],
  "incident_id": "acf936cf-2f13-4d9a-89cb-5c9832665f27"
}
```

`correlation.find_or_create_incident()` grouped all six alerts into one
incident because they share a host (`WKSTN-FIN-07`) and fall inside the
2-hour correlation window — no manual grouping step.

## 2. Extract IOCs

```bash
curl -X POST http://localhost:8000/incidents/acf936cf-.../extract-iocs
```

```json
{
  "extracted": 4,
  "iocs": [
    {"type": "ip", "value": "185.220.101.47"},
    {"type": "username", "value": "j.rahman"},
    {"type": "url", "value": "http://evil-c2.badguy.net/payload.ps1"},
    {"type": "domain", "value": "evil-c2.badguy.net"}
  ]
}
```

Four IOCs, all correct — no false positives on this scenario (this exact
extraction step is what the "j.rahman shouldn't look like a domain" and
"powershell.exe shouldn't look like a domain" bugs were caught and fixed
against during development; see `docs/architecture.md` on IOC extraction).

## 3. Enrich

```bash
curl -X POST http://localhost:8000/incidents/acf936cf-.../enrich
```

Four enrichment results came back (mock VirusTotal on the IP, URL, and
domain; mock AbuseIPDB on the IP) — every one flagged `malicious`, each
labeled unambiguously as mocked:

```json
{
  "provider": "mock_virustotal",
  "verdict": "malicious",
  "confidence": 0.9,
  "evidence": {
    "note": "MOCKED response — deterministic hash-seeded, not a real VirusTotal call.",
    "lookup_type": "ip",
    "lookup_value": "185.220.101.47",
    "simulated_engines_total": 70,
    "simulated_engines_flagged": 25
  },
  "is_mocked": true
}
```

The mock adapters are deterministic (hash-seeded on the lookup value), not
random — the same IOC always gets the same mocked verdict, which is what
makes the benchmark reproducible.

## 4. Timeline

```bash
curl http://localhost:8000/incidents/acf936cf-.../timeline
```

Six events, ordered by timestamp, each carrying its original raw alert data
and MITRE hints straight from the source alert (`T1110` on the failed
logons, `T1078` on the success, `T1059.001`/`T1027` on the PowerShell
execution, `T1071.001`/`T1105` on the outbound connection) — this is
`timeline_builder.build_timeline()`, pure ordering and formatting, no AI
involved.

## 5. AI severity suggestion

```bash
curl -X POST http://localhost:8000/incidents/acf936cf-.../severity-suggestion
```

```json
{
  "severity": "high",
  "confidence": 0.78,
  "rationale": "Derived from 4 malicious-verdict enrichment result(s), 1 suspicious-verdict result(s), and rule severity signals present in the correlated events for this incident.",
  "evidence_refs": [
    "event:fcbced7a-...", "event:f60b8812-...", "event:1319dc91-...",
    "event:1faa27b6-...", "event:8d5ca45d-...", "event:afc47765-...",
    "enrichment:7cdb9bf5-...", "enrichment:168a4cd5-...",
    "enrichment:9303fff2-...", "enrichment:5dcc0062-..."
  ]
}
```

Every one of those `evidence_refs` resolves to a real event or enrichment
row an analyst can open. This response would have been silently dropped
before it ever reached this JSON if even one ref didn't resolve — see
`app/ai/guardrails.py` and `tests/adversarial/test_prompt_injection.py`.

## 6. AI MITRE technique suggestions

```bash
curl -X POST http://localhost:8000/incidents/acf936cf-.../mitre-suggestions
```

Three suggestions came back, each independently evidence-backed:

| Technique | Name | Confidence | Matched on |
|---|---|---|---|
| T1059.001 | Command and Scripting Interpreter: PowerShell | 0.62 | keyword `powershell` in correlated events |
| T1110 | Brute Force | 0.74 | keywords `failed logon`, `4625` |
| T1078 | Valid Accounts | 0.62 | keyword `successful logon` |

Ground truth for this exact scenario shape (`eval_cases.json`'s
`malicious-powershell-c2` case) is `T1059.001, T1110, T1078` — all three
matched here, which is why this case scored MITRE F1 = 1.00 in the
benchmark (see `docs/benchmark_results.md`). The demo file's own alerts
also embed MITRE hints (`rule.mitre.id`) as a second, independent signal
that happens to agree — worth noting as a sanity check, not as the
mechanism the suggestion endpoint actually uses (it reasons from the
correlated event/enrichment text, not from the hint field, so it isn't
just echoing the input).

## 7. AI report draft

```bash
curl -X POST http://localhost:8000/incidents/acf936cf-.../report-draft
```

The response is a full Markdown report, generated with version `1`,
`status: "draft"`, `generated_by: "ai"`. The document itself opens with:

> **This report was drafted by an AI system and has not been reviewed or
> approved by a human analyst. Do not use it to justify a response
> action.**

Every section (Executive Summary, Severity Assessment, Indicators of
Compromise, MITRE ATT&CK Mapping, Recommended Next Steps) either states a
fact the reader can verify against the incident's own data or is followed
by an explicit `_Evidence: event:..., enrichment:..._` line. Nothing in the
report recommends an automated action — "Recommended Next Steps" is
scoped explicitly to "for analyst judgment, not automated action."

## 8. Human review

This is the step nothing above is allowed to skip. Two example review
decisions from this run:

```bash
curl -X POST http://localhost:8000/incidents/acf936cf-.../review \
  -H "Content-Type: application/json" \
  -d '{"target_entity_type": "mitre_suggestion", "target_entity_id": "6406e9b5-...",
       "decision": "approve", "comment": "Confirmed against Sysmon process-creation log."}'
```

```bash
curl -X POST http://localhost:8000/incidents/acf936cf-.../review \
  -H "Content-Type: application/json" \
  -d '{"target_entity_type": "mitre_suggestion", "target_entity_id": "b6ee4010-...",
       "decision": "reject",
       "comment": "Successful logon was the legitimate account owner recovering access after the attacker-driven failures; not itself an ATT&CK technique worth reporting here."}'
```

The analyst approved `T1059.001` (clearly correct — the Sysmon log is
unambiguous) and rejected `T1078` (Valid Accounts) as not worth reporting
on its own in this context — a real, defensible analyst judgment call the
AI can't make for them, which is the entire point of the review step.
Both decisions are now permanent, separate `analyst_reviews` rows sitting
alongside the AI's original, unmodified suggestion — nothing was overwritten.

## 9. Export

```bash
curl "http://localhost:8000/incidents/acf936cf-.../export?format=markdown"
# or ?format=pdf, ?format=json
```

Returns the same evidence-cited Markdown report as a downloadable file (PDF
and JSON export use the same underlying report content).

## 10. Audit trail

```bash
curl http://localhost:8000/audit-logs?limit=8
```

Every step above left exactly one row, in order, each with `actor`,
`action`, `target`, and `reason`:

```
incident.export        actor=local-analyst@soc-workbench.local  target=incident:acf936cf-...
review.reject           actor=local-analyst@soc-workbench.local  target=mitre_suggestion:b6ee4010-...
review.approve          actor=local-analyst@soc-workbench.local  target=mitre_suggestion:6406e9b5-...
incident.report.draft   actor=ai:mock/mock-soc-analyst-v1        target=incident:acf936cf-...
incident.mitre.suggest  actor=ai:mock/mock-soc-analyst-v1        target=incident:acf936cf-...
incident.severity.suggest actor=ai:mock/mock-soc-analyst-v1      target=incident:acf936cf-...
```

Note the `actor` field distinguishes AI-attributed actions
(`ai:mock/mock-soc-analyst-v1` — provider and model name, not a person) from
human-attributed ones (`local-analyst@soc-workbench.local`) at the audit
level, not just in the UI. This is what a reviewer or an incident
post-mortem would actually query.

## Doing this from the dashboard instead of curl

The same nine steps are available as buttons/tabs in the React dashboard
(`frontend/src/pages/IncidentDetail.tsx`): the incident queue lists the new
incident right after ingest; opening it shows tabs for Overview, IOCs
(with enrichment verdicts inline), Timeline, MITRE (with approve/reject
buttons per suggestion), and Report (with a draft/export view). The Audit
Trail page (`frontend/src/pages/AuditTrail.tsx`) shows the same log shown
above, rendered as a table.
