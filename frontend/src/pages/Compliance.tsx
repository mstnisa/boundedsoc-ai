import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { ComplianceCoverageOut } from "../types";

const FRAMEWORK_LABEL: Record<string, string> = {
  owasp_top10: "OWASP Top 10",
  pci_dss: "PCI DSS",
  iso27001: "ISO 27001",
  gdpr: "GDPR",
};

export default function Compliance() {
  const [coverage, setCoverage] = useState<ComplianceCoverageOut | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .complianceCoverage()
      .then(setCoverage)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <div className="section-title" style={{ marginBottom: 4 }}>
        Compliance Coverage
      </div>
      <div className="ai-disclaimer" style={{ marginBottom: 16 }}>
        Informational mapping only — this shows which framework controls have at least one
        analyst-approved finding tied to them. It is not a compliance certification; an external
        auditor certifies compliance, this view helps prepare evidence for that audit. See{" "}
        <code>docs/business-value.md</code> for the full honesty note.
      </div>

      {loading && <p className="muted">Loading…</p>}

      {!loading && coverage && (
        <div className="kpi-grid">
          {Object.entries(coverage.coverage).map(([framework, stats]) => (
            <div className="kpi-card" key={framework}>
              <div className="kpi-icon blue">
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M9 12 11 14 15 9" />
                  <path d="M12 2 L4 5 V11 C4 16.2 7.4 20.1 12 22 C16.6 20.1 20 16.2 20 11 V5 Z" />
                </svg>
              </div>
              <div className="kpi-value">
                {stats.controls_with_evidence}/{stats.total_controls}
              </div>
              <div className="kpi-label">{FRAMEWORK_LABEL[framework] || framework} controls with evidence</div>
              <div className="muted" style={{ fontSize: "0.72rem", marginTop: 4 }}>
                {stats.mapping_count} mapping(s) total
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="card" style={{ marginTop: 4 }}>
        <div className="section-title">How mappings are created</div>
        <p className="muted" style={{ fontSize: "0.85rem" }}>
          Open an incident → MITRE Suggestions → approve a technique → Compliance tab → map it to a
          framework. Only analyst-approved findings are ever mapped; nothing here runs off an
          unreviewed AI claim.
        </p>
      </div>
    </div>
  );
}
