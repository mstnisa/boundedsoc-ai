import { useEffect, useState, useCallback } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type {
  ComplianceFramework,
  ComplianceMapping,
  EnrichmentResult,
  IOC,
  IncidentDetail as IncidentDetailType,
  MitreSuggestion,
  RemediationSuggestion,
  ReportOut,
  SecretExposureAlert,
  SeveritySuggestion,
  TimelineOut,
} from "../types";

type Tab = "overview" | "iocs" | "timeline" | "mitre" | "remediation" | "credentials" | "compliance" | "report";

const FRAMEWORKS: ComplianceFramework[] = ["owasp_top10", "pci_dss", "iso27001", "gdpr"];
const FRAMEWORK_LABEL: Record<ComplianceFramework, string> = {
  owasp_top10: "OWASP Top 10",
  pci_dss: "PCI DSS",
  iso27001: "ISO 27001",
  gdpr: "GDPR",
};

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [tab, setTab] = useState<Tab>("overview");
  const [incident, setIncident] = useState<IncidentDetailType | null>(null);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [enrichments, setEnrichments] = useState<EnrichmentResult[]>([]);
  const [timeline, setTimeline] = useState<TimelineOut | null>(null);
  const [mitre, setMitre] = useState<MitreSuggestion[]>([]);
  const [report, setReport] = useState<ReportOut | null>(null);
  const [severitySuggestion, setSeveritySuggestion] = useState<SeveritySuggestion | null>(null);
  const [remediations, setRemediations] = useState<RemediationSuggestion[]>([]);
  const [secretAlerts, setSecretAlerts] = useState<SecretExposureAlert[]>([]);
  const [complianceFramework, setComplianceFramework] = useState<ComplianceFramework>("pci_dss");
  const [complianceMappings, setComplianceMappings] = useState<ComplianceMapping[]>([]);
  const [busy, setBusy] = useState<string | null>(null);

  const refreshIncident = useCallback(() => {
    if (!id) return;
    api.getIncident(id).then(setIncident);
  }, [id]);

  useEffect(refreshIncident, [refreshIncident]);

  const run = async (key: string, fn: () => Promise<void>) => {
    setBusy(key);
    try {
      await fn();
    } catch (e) {
      alert(String(e));
    } finally {
      setBusy(null);
    }
  };

  const doExtract = () =>
    run("extract", async () => {
      const res = await api.extractIocs(id!);
      setIocs(res.iocs);
      refreshIncident();
    });

  const doEnrich = () =>
    run("enrich", async () => {
      const res = await api.enrich(id!);
      setEnrichments(res.results);
    });

  const doTimeline = () =>
    run("timeline", async () => {
      setTimeline(await api.getTimeline(id!));
    });

  const doSeverity = () =>
    run("severity", async () => {
      setSeveritySuggestion(await api.suggestSeverity(id!));
      refreshIncident();
    });

  const doMitre = () =>
    run("mitre", async () => {
      const res = await api.mitreSuggestions(id!);
      setMitre(res.suggestions);
    });

  const doReport = () =>
    run("report", async () => {
      setReport(await api.reportDraft(id!));
    });

  const doDraftRemediation = () =>
    run("remediation-draft", async () => {
      const suggestion = await api.draftRemediation(id!, "example-org/example-repo");
      if (suggestion) setRemediations((prev) => [suggestion, ...prev]);
      else alert("No approved MITRE finding has a known remediation template yet — approve one on the MITRE tab first.");
    });

  const doCreatePr = (rid: string) =>
    run(`create-pr-${rid}`, async () => {
      const updated = await api.createRemediationPr(id!, rid);
      setRemediations((prev) => prev.map((r) => (r.id === rid ? updated : r)));
    });

  const reviewRemediation = (rid: string, decision: "approve" | "edit" | "reject") =>
    run(`review-remediation-${rid}`, async () => {
      let correction: string | undefined;
      if (decision === "edit") {
        correction = prompt("Enter corrected patch text:") || undefined;
        if (!correction) return;
      }
      await api.submitReview(id!, {
        target_entity_type: "remediation_suggestion",
        target_entity_id: rid,
        decision,
        correction,
      });
      setRemediations((prev) =>
        prev.map((r) =>
          r.id === rid
            ? { ...r, status: decision === "approve" ? "approved" : decision === "edit" ? "edited" : "rejected", proposed_patch: correction || r.proposed_patch }
            : r
        )
      );
    });

  const doScanSecrets = () =>
    run("secret-scan", async () => {
      const found = await api.scanSecretExposure(id!);
      setSecretAlerts((prev) => [...found, ...prev]);
    });

  const reviewSecretAlert = (sid: string, decision: "approve" | "reject") =>
    run(`review-secret-${sid}`, async () => {
      const comment = decision === "reject" ? prompt("Optional comment (why?):") || undefined : undefined;
      await api.submitReview(id!, {
        target_entity_type: "secret_exposure_alert",
        target_entity_id: sid,
        decision,
        comment,
      });
      setSecretAlerts((prev) =>
        prev.map((a) => (a.id === sid ? { ...a, status: decision === "approve" ? "approved" : "rejected" } : a))
      );
    });

  const doRevokeSecret = (sid: string) =>
    run(`revoke-secret-${sid}`, async () => {
      const updated = await api.revokeSecretExposure(id!, sid);
      setSecretAlerts((prev) => prev.map((a) => (a.id === sid ? updated : a)));
    });

  const doMapCompliance = () =>
    run("compliance-map", async () => {
      const res = await api.createComplianceMapping(id!, complianceFramework);
      setComplianceMappings(res.mappings);
    });

  const review = (
    targetType: string,
    targetId: string,
    decision: "approve" | "edit" | "reject",
    afterEdit?: () => void
  ) =>
    run(`review-${targetId}`, async () => {
      let correction: string | undefined;
      let comment: string | undefined;
      if (decision === "edit") {
        correction = prompt("Enter corrected value:") || undefined;
        if (!correction) return;
      } else {
        comment = prompt("Optional comment (why?):") || undefined;
      }
      await api.submitReview(id!, {
        target_entity_type: targetType,
        target_entity_id: targetId,
        decision,
        comment,
        correction,
      });
      afterEdit?.();
      refreshIncident();
    });

  if (!incident) return <p className="muted">Loading incident…</p>;

  return (
    <div>
      <div className="muted" style={{ fontSize: "0.78rem", marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}>
        <Link to="/queue">Incident Queue</Link>
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--muted-2)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="9 18 15 12 9 6" />
        </svg>
        <span>{incident.title}</span>
      </div>
      <div className="card">
        <div className="section-title">
          {incident.title}
          <span className={`badge ${incident.severity}`}>{incident.severity}</span>
          <span className="pill">source: {incident.severity_source}</span>
          <span className="pill">{incident.status}</span>
        </div>
        <p className="muted">
          {incident.alert_count} alert(s) · {incident.event_count} event(s) · {incident.ioc_count} IOC(s) ·
          created {new Date(incident.created_at).toLocaleString()}
        </p>

        {incident.severity_source !== "analyst" && (
          <div className="ai-disclaimer">
            Severity is currently {incident.severity_source === "ai" ? "an AI suggestion" : "unset"} —
            confirm or correct it via Overview → Review Severity before treating this incident as final.
          </div>
        )}
      </div>

      <div className="tabs">
        {(["overview", "iocs", "timeline", "mitre", "remediation", "credentials", "compliance", "report"] as Tab[]).map((t) => (
          <div key={t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
            {t === "iocs"
              ? "IOCs & Enrichment"
              : t === "mitre"
              ? "MITRE Suggestions"
              : t === "credentials"
              ? "Credential Exposure"
              : t[0].toUpperCase() + t.slice(1)}
          </div>
        ))}
      </div>

      {tab === "overview" && (
        <div className="card">
          <div className="section-title">Severity Suggestion (AI)</div>
          <button onClick={doSeverity} disabled={busy === "severity"}>
            {busy === "severity" ? "Running…" : "Suggest Severity"}
          </button>
          {severitySuggestion && severitySuggestion.suggested && (
            <div style={{ marginTop: 10 }}>
              <p>
                Suggested: <span className={`badge ${severitySuggestion.severity}`}>{severitySuggestion.severity}</span>{" "}
                (confidence {severitySuggestion.confidence?.toFixed(2)})
              </p>
              <p className="muted">{severitySuggestion.rationale}</p>
              <div className="evidence-refs">Evidence: {severitySuggestion.evidence_refs?.join(", ")}</div>
              <button onClick={() => review("incident_severity", incident.id, "approve")}>Approve</button>
              <button
                className="secondary"
                onClick={() => review("incident_severity", incident.id, "edit")}
              >
                Edit / Override
              </button>
              <button className="danger" onClick={() => review("incident_severity", incident.id, "reject")}>
                Reject
              </button>
            </div>
          )}
          {severitySuggestion && !severitySuggestion.suggested && (
            <p className="muted">
              No evidence-backed severity claim could be produced — see the Audit Trail for why it was
              dropped (errors: {severitySuggestion.errors?.join(", ")}).
            </p>
          )}
        </div>
      )}

      {tab === "iocs" && (
        <div className="card">
          <div className="section-title">Indicators of Compromise & Enrichment</div>
          <button onClick={doExtract} disabled={busy === "extract"}>
            {busy === "extract" ? "Extracting…" : "Extract IOCs"}
          </button>
          <button className="secondary" onClick={doEnrich} disabled={busy === "enrich"}>
            {busy === "enrich" ? "Enriching…" : "Enrich IOCs"}
          </button>

          {iocs.length > 0 && (
            <table style={{ marginTop: 12 }}>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>First Seen</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((i) => (
                  <tr key={i.id}>
                    <td>{i.type}</td>
                    <td className="mono">{i.value}</td>
                    <td className="muted">{new Date(i.first_seen).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {enrichments.length > 0 && (
            <>
              <div className="section-title" style={{ marginTop: 18 }}>
                Enrichment Results
              </div>
              <table>
                <thead>
                  <tr>
                    <th>Provider</th>
                    <th>Verdict</th>
                    <th>Confidence</th>
                    <th>Mocked?</th>
                    <th>Fetched</th>
                  </tr>
                </thead>
                <tbody>
                  {enrichments.map((e) => (
                    <tr key={e.id}>
                      <td>{e.provider}</td>
                      <td>
                        <span className={`badge verdict-${e.verdict}`}>{e.verdict}</span>
                      </td>
                      <td>{e.confidence.toFixed(2)}</td>
                      <td className="muted">{e.is_mocked ? "yes (synthetic)" : "no (live)"}</td>
                      <td className="muted">{new Date(e.fetched_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}

      {tab === "timeline" && (
        <div className="card">
          <div className="section-title">Chronological Timeline</div>
          <button onClick={doTimeline} disabled={busy === "timeline"}>
            {busy === "timeline" ? "Building…" : "Build / Refresh Timeline"}
          </button>
          {timeline && (
            <table style={{ marginTop: 12 }}>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Time</th>
                  <th>Event Type</th>
                  <th>Host</th>
                </tr>
              </thead>
              <tbody>
                {timeline.events.map((e) => (
                  <tr key={e.event_id}>
                    <td className="muted">{e.sequence}</td>
                    <td>{new Date(e.timestamp).toLocaleString()}</td>
                    <td>{e.event_type}</td>
                    <td className="mono muted">{e.source_host}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === "mitre" && (
        <div className="card">
          <div className="section-title">MITRE ATT&CK Suggestions (AI)</div>
          <div className="ai-disclaimer">
            Each suggestion requires evidence references and analyst approval before it is treated
            as confirmed attribution.
          </div>
          <button onClick={doMitre} disabled={busy === "mitre"}>
            {busy === "mitre" ? "Analyzing…" : "Generate MITRE Suggestions"}
          </button>
          {mitre.map((m) => {
            const statusClass =
              m.status === "approved" || m.status === "edited"
                ? "status-approved"
                : m.status === "rejected"
                ? "status-rejected"
                : "status-pending";
            return (
              <div
                key={m.id}
                className="card"
                style={m.status === "rejected" ? { opacity: 0.75 } : undefined}
              >
                <div className="section-title" style={{ marginBottom: 8 }}>
                  <strong style={{ fontSize: "0.94rem", color: "var(--text)" }}>
                    {m.technique_id} — {m.technique_name}
                  </strong>
                  <span className={`pill ${statusClass}`}>
                    {(m.status === "approved" || m.status === "edited") && (
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#0d7a2e" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                    )}
                    {m.status === "rejected" && (
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--critical)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="18" y1="6" x2="6" y2="18" />
                        <line x1="6" y1="6" x2="18" y2="18" />
                      </svg>
                    )}
                    {m.status}
                  </span>
                  <span className="pill">confidence {m.confidence.toFixed(2)}</span>
                </div>
                <p className="muted" style={{ fontSize: "0.82rem" }}>{m.rationale}</p>
                <div className="evidence-refs">Evidence: {m.evidence_refs.join(", ")}</div>
                {m.status === "pending" && (
                  <div style={{ marginTop: 10 }}>
                    <button onClick={() => review("mitre_suggestion", m.id, "approve")}>Approve</button>
                    <button className="secondary" onClick={() => review("mitre_suggestion", m.id, "edit")}>
                      Edit
                    </button>
                    <button className="danger" onClick={() => review("mitre_suggestion", m.id, "reject")}>
                      Reject
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {tab === "remediation" && (
        <div className="card">
          <div className="section-title">Remediation Drafting Agent (AI)</div>
          <div className="ai-disclaimer">
            Illustrative fix pattern tied to an analyst-approved MITRE finding — not a scan of a real
            repository. Approving a suggestion here never creates a pull request by itself: "Create
            Pull Request" is a separate, explicit action that only appears once approved.
          </div>
          <button onClick={doDraftRemediation} disabled={busy === "remediation-draft"}>
            {busy === "remediation-draft" ? "Drafting…" : "Draft Remediation Suggestion"}
          </button>
          {remediations.map((r) => {
            const statusClass =
              r.status === "approved" || r.status === "edited"
                ? "status-approved"
                : r.status === "rejected"
                ? "status-rejected"
                : "status-pending";
            return (
              <div key={r.id} className="card" style={r.status === "rejected" ? { opacity: 0.75 } : undefined}>
                <div className="section-title" style={{ marginBottom: 8 }}>
                  <strong style={{ fontSize: "0.94rem", color: "var(--text)" }}>
                    {r.file_path} {r.cwe_ref && `(${r.cwe_ref})`}
                  </strong>
                  <span className={`pill ${statusClass}`}>{r.status}</span>
                  <span className="pill">confidence {r.confidence.toFixed(2)}</span>
                </div>
                <p className="muted" style={{ fontSize: "0.82rem" }}>{r.rationale}</p>
                <pre className="report-content" style={{ fontSize: "0.78rem" }}>
                  {"- " + r.vulnerable_snippet + "\n\n+ " + r.proposed_patch}
                </pre>
                <div className="evidence-refs">Evidence: {r.evidence_refs.join(", ")}</div>
                {r.status === "pending" && (
                  <div style={{ marginTop: 10 }}>
                    <button onClick={() => reviewRemediation(r.id, "approve")}>Approve</button>
                    <button className="secondary" onClick={() => reviewRemediation(r.id, "edit")}>Edit</button>
                    <button className="danger" onClick={() => reviewRemediation(r.id, "reject")}>Reject</button>
                  </div>
                )}
                {(r.status === "approved" || r.status === "edited") && !r.pr_url && (
                  <div style={{ marginTop: 10 }}>
                    <button onClick={() => doCreatePr(r.id)} disabled={busy === `create-pr-${r.id}`}>
                      {busy === `create-pr-${r.id}` ? "Creating…" : "Create Pull Request"}
                    </button>
                  </div>
                )}
                {r.pr_url && (
                  <p style={{ marginTop: 10 }}>
                    <a href={r.pr_url} target="_blank" rel="noreferrer">{r.pr_url}</a>
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}

      {tab === "credentials" && (
        <div className="card">
          <div className="section-title">Credential Exposure Response</div>
          <div className="ai-disclaimer">
            Deterministic pattern scan over correlated events — the raw secret value is never stored,
            only a masked prefix + hash. Revocation is blocked server-side until an analyst approves
            it; escalation (if configured) only notifies, it never auto-revokes.
          </div>
          <button onClick={doScanSecrets} disabled={busy === "secret-scan"}>
            {busy === "secret-scan" ? "Scanning…" : "Scan for Exposed Credentials"}
          </button>
          {secretAlerts.map((a) => (
            <div
              key={a.id}
              className="card"
              style={{ borderColor: "var(--critical)", opacity: a.status === "rejected" ? 0.75 : 1 }}
            >
              <div className="section-title" style={{ marginBottom: 8 }}>
                <strong style={{ fontSize: "0.94rem", color: "var(--text)" }}>
                  {a.secret_type} ({a.provider})
                </strong>
                <span
                  className={`pill ${
                    a.status === "revoked"
                      ? "status-approved"
                      : a.status === "rejected"
                      ? "status-rejected"
                      : a.status === "approved"
                      ? "status-approved"
                      : "status-pending"
                  }`}
                >
                  {a.status}
                </span>
              </div>
              <p className="mono muted" style={{ fontSize: "0.82rem" }}>masked value: {a.masked_value}</p>
              <div className="evidence-refs">Source: {a.source_ref}</div>
              {a.status === "pending" && (
                <div style={{ marginTop: 10 }}>
                  <button onClick={() => reviewSecretAlert(a.id, "approve")}>Approve</button>
                  <button className="danger" onClick={() => reviewSecretAlert(a.id, "reject")}>Reject</button>
                </div>
              )}
              {a.status === "approved" && (
                <div style={{ marginTop: 10 }}>
                  <button className="danger" onClick={() => doRevokeSecret(a.id)} disabled={busy === `revoke-secret-${a.id}`}>
                    {busy === `revoke-secret-${a.id}` ? "Revoking…" : "Revoke Now"}
                  </button>
                </div>
              )}
              {a.status === "revoked" && <p className="muted" style={{ fontSize: "0.8rem" }}>Revoked {a.revoked_at && new Date(a.revoked_at).toLocaleString()}</p>}
            </div>
          ))}
        </div>
      )}

      {tab === "compliance" && (
        <div className="card">
          <div className="section-title">Compliance Mapper</div>
          <div className="ai-disclaimer">
            Maps analyst-approved MITRE findings to framework controls. Informational mapping only —
            not a compliance certification.
          </div>
          <select value={complianceFramework} onChange={(e) => setComplianceFramework(e.target.value as ComplianceFramework)}>
            {FRAMEWORKS.map((f) => (
              <option key={f} value={f}>{FRAMEWORK_LABEL[f]}</option>
            ))}
          </select>{" "}
          <button onClick={doMapCompliance} disabled={busy === "compliance-map"}>
            {busy === "compliance-map" ? "Mapping…" : "Map Approved Findings"}
          </button>
          {complianceMappings.length > 0 && (
            <table style={{ marginTop: 12 }}>
              <thead>
                <tr>
                  <th>Control</th>
                  <th>Title</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {complianceMappings.map((m) => (
                  <tr key={m.id}>
                    <td className="mono">{m.control_id}</td>
                    <td>{m.control_title}</td>
                    <td>{m.confidence.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === "report" && (
        <div className="card">
          <div className="section-title">Incident Report Draft (AI-generated)</div>
          <button onClick={doReport} disabled={busy === "report"}>
            {busy === "report" ? "Drafting…" : "Generate Report Draft"}
          </button>
          {report && (
            <>
              <div style={{ margin: "10px 0" }}>
                <span className="pill">v{report.version}</span>{" "}
                <span className="pill">{report.status}</span>{" "}
                <span className="pill">by {report.generated_by}</span>
              </div>
              <pre className="report-content">{report.content}</pre>
              <div style={{ marginTop: 10 }}>
                <button onClick={() => review("report", report.id, "approve")}>Approve Report</button>
                <button className="secondary" onClick={() => review("report", report.id, "edit")}>
                  Edit
                </button>
                <button className="danger" onClick={() => review("report", report.id, "reject")}>
                  Reject
                </button>
              </div>
              <div style={{ marginTop: 14 }}>
                <a href={api.exportUrl(incident.id, "markdown")} target="_blank" rel="noreferrer">
                  <button className="secondary">Export Markdown</button>
                </a>
                <a href={api.exportUrl(incident.id, "pdf")} target="_blank" rel="noreferrer">
                  <button className="secondary">Export PDF</button>
                </a>
                <a href={api.exportUrl(incident.id, "json")} target="_blank" rel="noreferrer">
                  <button className="secondary">Export JSON</button>
                </a>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
