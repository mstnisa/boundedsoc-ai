import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { IncidentSummary, Severity } from "../types";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "unknown"];
const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#d03b3b",
  high: "#ec835a",
  medium: "#eda100",
  low: "#0ca30c",
  unknown: "#c3c7d1",
};

const STATUS_ORDER = ["new", "triaging", "investigating", "pending_review", "closed_true_positive", "closed_false_positive"] as const;
const STATUS_LABEL: Record<(typeof STATUS_ORDER)[number], string> = {
  new: "New",
  triaging: "Triaging",
  investigating: "Investigating",
  pending_review: "Pending Review",
  closed_true_positive: "Closed (TP)",
  closed_false_positive: "Closed (FP)",
};
const STATUS_COLOR: Record<(typeof STATUS_ORDER)[number], string> = {
  new: "#2a78d6",
  triaging: "#eb6834",
  investigating: "#1baf7a",
  pending_review: "#eda100",
  closed_true_positive: "#4a3aa7",
  closed_false_positive: "#c3c7d1",
};

function conicGradient(segments: { value: number; color: string }[]): string {
  const total = segments.reduce((s, x) => s + x.value, 0);
  if (total === 0) return "conic-gradient(#eef0f4 0% 100%)";
  let acc = 0;
  const stops = segments
    .filter((s) => s.value > 0)
    .map((s) => {
      const from = (acc / total) * 100;
      acc += s.value;
      const to = (acc / total) * 100;
      return `${s.color} ${from}% ${to}%`;
    });
  return `conic-gradient(${stops.join(", ")})`;
}

export default function Dashboard() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => {
    api
      .listIncidents()
      .then(setIncidents)
      .finally(() => setLoading(false));
  }, []);

  const openCount = incidents.filter((i) => !i.status.startsWith("closed_")).length;
  const pendingReview = incidents.filter((i) => i.status === "pending_review").length;
  const highCritical = incidents.filter((i) => i.severity === "high" || i.severity === "critical").length;
  const closedCount = incidents.filter((i) => i.status.startsWith("closed_")).length;

  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    incidents.forEach((i) => counts[i.severity]++);
    return counts;
  }, [incidents]);

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    STATUS_ORDER.forEach((s) => (counts[s] = 0));
    incidents.forEach((i) => {
      if (counts[i.status] !== undefined) counts[i.status]++;
    });
    return counts;
  }, [incidents]);

  const maxStatusCount = Math.max(1, ...Object.values(statusCounts));

  const donutSegments = SEVERITY_ORDER.map((s) => ({ value: severityCounts[s], color: SEVERITY_COLOR[s] }));

  const filtered = search
    ? incidents.filter((i) => i.title.toLowerCase().includes(search.toLowerCase()))
    : incidents;
  const recent = filtered.slice(0, 8);

  return (
    <div>
      <div className="section-title" style={{ justifyContent: "space-between", marginBottom: 18 }}>
        <div>
          <div style={{ fontSize: "0.68rem", fontWeight: 800, letterSpacing: "0.1em", color: "var(--accent)", textTransform: "uppercase" }}>
            Overview
          </div>
          <div style={{ fontSize: "1.15rem", fontWeight: 700, color: "var(--text)" }}>Security Operations Dashboard</div>
        </div>
        <div className="searchbox" style={{ width: 220 }}>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--muted-2)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="11" cy="11" r="7" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search incidents…"
            style={{ border: "none", background: "transparent", outline: "none", font: "inherit", color: "var(--text)", width: "100%" }}
          />
        </div>
      </div>

      {loading && <p className="muted">Loading…</p>}

      {!loading && (
        <>
          <div className="kpi-grid">
            <div className="kpi-card">
              <div className="kpi-icon blue">
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="4" y1="6" x2="20" y2="6" />
                  <line x1="4" y1="12" x2="20" y2="12" />
                  <line x1="4" y1="18" x2="14" y2="18" />
                </svg>
              </div>
              <div className="kpi-value">{openCount}</div>
              <div className="kpi-label">Open Incidents</div>
            </div>
            <div className="kpi-card">
              <div className="kpi-icon amber">
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="var(--medium)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="9" />
                  <polyline points="12 7 12 12 15 14" />
                </svg>
              </div>
              <div className="kpi-value" style={{ color: "var(--medium)" }}>{pendingReview}</div>
              <div className="kpi-label">Pending Review</div>
            </div>
            <div className="kpi-card">
              <div className="kpi-icon red">
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="var(--critical)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 3 L22 20 H2 Z" />
                  <line x1="12" y1="9" x2="12" y2="14" />
                </svg>
              </div>
              <div className="kpi-value" style={{ color: "var(--critical)" }}>{highCritical}</div>
              <div className="kpi-label">High / Critical</div>
            </div>
            <div className="kpi-card">
              <div className="kpi-icon green">
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="var(--low)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </div>
              <div className="kpi-value" style={{ color: "var(--low)" }}>{closedCount}</div>
              <div className="kpi-label">Closed</div>
            </div>
          </div>

          <div className="charts-row">
            <div className="card">
              <div className="chart-card-title">Incidents by Severity</div>
              <div className="donut-row">
                <div className="donut" style={{ background: conicGradient(donutSegments) }}>
                  <div className="donut-hole">
                    <div className="donut-hole-value">{incidents.length}</div>
                    <div className="donut-hole-label">total</div>
                  </div>
                </div>
                <div className="legend">
                  {SEVERITY_ORDER.map((s) => (
                    <div className="legend-row" key={s}>
                      <span className="legend-dot" style={{ background: SEVERITY_COLOR[s] }} />
                      <span className="label" style={{ textTransform: "capitalize" }}>{s}</span>
                      <span className="value">{severityCounts[s]}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="card">
              <div className="chart-card-title">Incidents by Status</div>
              <div className="barlist">
                {STATUS_ORDER.map((s) => (
                  <div className="barlist-row" key={s}>
                    <div className="barlist-label">{STATUS_LABEL[s]}</div>
                    <div className="barlist-track">
                      <div
                        className="barlist-fill"
                        style={{ width: `${(statusCounts[s] / maxStatusCount) * 100}%`, background: STATUS_COLOR[s] }}
                      />
                    </div>
                    <div className="barlist-value">{statusCounts[s]}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="card">
            <div className="section-title" style={{ justifyContent: "space-between" }}>
              <span>Alert Queue / Incidents</span>
              <Link to="/queue" style={{ fontSize: "0.8rem", fontWeight: 600 }}>
                View all →
              </Link>
            </div>

            {incidents.length === 0 && (
              <p className="muted">
                No incidents yet. POST a Wazuh-style alert bundle to <code>/alerts</code> (see the demo
                scenario in <code>data/synthetic/</code>) to see one appear here.
              </p>
            )}

            {recent.length > 0 && (
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
                  {recent.map((inc) => (
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
        </>
      )}
    </div>
  );
}
