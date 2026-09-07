import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { AuditLogOut } from "../types";

export default function AuditTrail() {
  const [logs, setLogs] = useState<AuditLogOut[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .auditLogs({ limit: 200 })
      .then(setLogs)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="card">
      <div className="section-title">Audit Trail (append-only)</div>
      <p className="muted" style={{ marginTop: -6 }}>
        Who / what / when / why for every consequential action — ingestion, extraction,
        enrichment, every AI suggestion (including ones dropped for lacking evidence), and every
        analyst review decision.
      </p>
      {loading && <p className="muted">Loading…</p>}
      {!loading && (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr key={log.id}>
                <td className="muted">{new Date(log.timestamp).toLocaleString()}</td>
                <td className="mono">{log.actor}</td>
                <td className="mono">{log.action}</td>
                <td className="mono muted">{log.target}</td>
                <td>{log.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
