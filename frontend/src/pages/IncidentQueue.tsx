import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { IncidentSummary } from "../types";

export default function IncidentQueue() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const load = () => {
    setLoading(true);
    api
      .listIncidents({ severity: severityFilter || undefined, status: statusFilter || undefined })
      .then(setIncidents)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(load, [severityFilter, statusFilter]);

  return (
    <div>
      <div className="card">
        <div className="section-title">Alert Queue / Incidents</div>
        <p className="muted" style={{ marginTop: -6 }}>
          Grouped, correlated cases awaiting or under investigation. Severity shown here may be an
          AI suggestion pending analyst confirmation — check the "source" column.
        </p>
        <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            <option value="">All severities</option>
            {["low", "medium", "high", "critical", "unknown"].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="">All statuses</option>
            {["new", "triaging", "investigating", "pending_review", "closed_true_positive", "closed_false_positive"].map(
              (s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              )
            )}
          </select>
          <button className="secondary" onClick={load}>
            Refresh
          </button>
        </div>

        {loading && <p className="muted">Loading…</p>}
        {error && <p style={{ color: "var(--critical)" }}>{error}</p>}
        {!loading && !error && incidents.length === 0 && (
          <p className="muted">
            No incidents yet. POST a Wazuh-style alert bundle to <code>/alerts</code> (see the
            demo scenario in <code>data/synthetic/</code>) to see one appear here.
          </p>
        )}

        {incidents.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Status</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((inc) => (
                <tr key={inc.id}>
                  <td>
                    <Link to={`/incidents/${inc.id}`}>{inc.title}</Link>
                  </td>
                  <td>
                    <span className={`badge ${inc.severity}`}>{inc.severity}</span>
                  </td>
                  <td className="mono muted">{inc.severity_source}</td>
                  <td>{inc.status}</td>
                  <td className="muted">{new Date(inc.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
