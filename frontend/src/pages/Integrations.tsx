import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { AIActionLogEntry, IntegrationOut, ToolAccessPolicy } from "../types";

export default function Integrations() {
  const [integrations, setIntegrations] = useState<IntegrationOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [policies, setPolicies] = useState<ToolAccessPolicy[]>([]);
  const [actionLog, setActionLog] = useState<AIActionLogEntry[]>([]);
  const [policiesLoading, setPoliciesLoading] = useState(true);

  useEffect(() => {
    api
      .listIntegrations()
      .then(setIntegrations)
      .finally(() => setLoading(false));
  }, []);

  const loadPolicies = () => {
    setPoliciesLoading(true);
    Promise.all([api.listToolPolicies(), api.listAiActionLog()])
      .then(([p, log]) => {
        setPolicies(p);
        setActionLog(log);
      })
      .finally(() => setPoliciesLoading(false));
  };

  useEffect(loadPolicies, []);

  return (
    <div>
      <div className="card">
        <div className="section-title">Integrations</div>
        <p className="muted" style={{ marginTop: -6 }}>
          Configured data-source and threat-intel adapters. Toggling these on requires an admin role
          once single-user demo mode is turned off.
        </p>
        {loading && <p className="muted">Loading…</p>}
        {!loading && integrations.length === 0 && (
          <p className="muted">No integrations configured yet.</p>
        )}
        {integrations.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Config Ref</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {integrations.map((i) => (
                <tr key={i.id}>
                  <td>{i.name}</td>
                  <td className="mono muted">{i.type}</td>
                  <td className="mono muted">{i.config_ref}</td>
                  <td>
                    <span className={`pill ${i.enabled ? "status-approved" : "status-rejected"}`}>
                      {i.enabled ? "enabled" : "disabled"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <div className="section-title">AI Tool Policies</div>
        <div className="ai-disclaimer" style={{ marginBottom: 12 }}>
          The MCP/API Security Gateway's allow-list. Every AI-initiated external tool call (GitHub PR
          creation, secret-provider revocation) is checked against this table before anything runs —
          nothing not listed here is ever reachable, whatever a prompt or an approved suggestion says.
        </div>
        {policiesLoading && <p className="muted">Loading…</p>}
        {!policiesLoading && (
          <table>
            <thead>
              <tr>
                <th>Tool</th>
                <th>Allowed Actions</th>
                <th>Scope</th>
                <th>Updated By</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id}>
                  <td className="mono">{p.tool_name}</td>
                  <td>
                    {p.allowed_actions.length === 0 ? (
                      <span className="pill status-rejected">none — all calls blocked</span>
                    ) : (
                      p.allowed_actions.map((a) => (
                        <span key={a} className="pill status-approved" style={{ marginRight: 4 }}>
                          {a}
                        </span>
                      ))
                    )}
                  </td>
                  <td className="muted" style={{ fontSize: "0.8rem" }}>
                    {p.scope}
                  </td>
                  <td className="mono muted">{p.updated_by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <div className="section-title">AI Action Log</div>
        <p className="muted" style={{ marginTop: -6, fontSize: "0.82rem" }}>
          Every attempted AI-initiated tool call, allowed or blocked — separate from the main Audit
          Trail so "what did the AI try to reach outside this system" can be reviewed on its own.
        </p>
        {!policiesLoading && actionLog.length === 0 && (
          <p className="muted">No tool calls attempted yet.</p>
        )}
        {actionLog.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Tool</th>
                <th>Action</th>
                <th>Result</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {actionLog.map((e) => (
                <tr key={e.id}>
                  <td className="mono">{e.tool_name}</td>
                  <td className="mono muted">{e.requested_action}</td>
                  <td>
                    <span className={`pill ${e.allowed ? "status-approved" : "status-rejected"}`}>
                      {e.allowed ? "allowed" : "blocked"}
                    </span>
                  </td>
                  <td className="muted">{new Date(e.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
