# Dashboard Screenshots

Real screenshots of the React dashboard (`frontend/src/`), captured against
a live backend running the demo scenario
(`data/synthetic/demo_incident_powershell.json`) — not mockups.

| File | Shows |
|---|---|
| `01_incident_queue.png` | The incident queue — one row per correlated incident, with severity/status badges |
| `02_incident_overview.png` | Incident overview tab, including the AI severity suggestion (high, confidence 0.78) with its evidence citation and Approve/Edit/Reject controls, and the persistent banner reminding the analyst the severity isn't final until reviewed |
| `03_incident_iocs.png` | Extracted IOCs (IP, username, URL, domain) and their enrichment verdicts — each one labeled `yes (synthetic)` to make clear these are mocked provider responses, not real threat-intel lookups |
| `04_incident_timeline.png` | The chronological event timeline built from the correlated alerts |
| `05_incident_mitre.png` | AI-suggested MITRE ATT&CK techniques (T1059.001, T1110, T1078), each with its rationale, evidence references, and independent Approve/Edit/Reject controls per technique |
| `06_incident_report.png` | The AI-drafted incident report, clearly labeled as a draft pending human approval, with per-section evidence citations and export buttons (Markdown/PDF/JSON) |
| `07_audit_trail.png` | The append-only audit trail view, showing both AI-attributed actions (`ai:mock/mock-soc-analyst-v1`) and human-attributed actions (`local-analyst@soc-workbench.local`) |

Every AI-facing panel repeats the same pattern visible across these
screenshots: a suggestion, its evidence, and independent
approve/edit/reject controls — never a suggestion presented as already
final.
