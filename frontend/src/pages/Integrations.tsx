import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { IntegrationOut } from "../types";

export default function Integrations() {
  const [integrations, setIntegrations] = useState<IntegrationOut[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .listIntegrations()
      .then(setIntegrations)
      .finally(() => setLoading(false));
  }, []);

  return (
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
  );
}
