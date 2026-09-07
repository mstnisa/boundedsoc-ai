import type {
  AuditLogOut,
  EnrichmentResult,
  IOC,
  IncidentDetail,
  IncidentSummary,
  MitreSuggestion,
  ReportOut,
  SeveritySuggestion,
  TimelineOut,
} from "../types";

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text || res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  listIncidents: (params?: { status?: string; severity?: string }) => {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.severity) qs.set("severity", params.severity);
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return request<IncidentSummary[]>(`/incidents${suffix}`);
  },
  getIncident: (id: string) => request<IncidentDetail>(`/incidents/${id}`),
  extractIocs: (id: string) =>
    request<{ incident_id: string; extracted: number; iocs: IOC[] }>(`/incidents/${id}/extract-iocs`, {
      method: "POST",
    }),
  enrich: (id: string) =>
    request<{ incident_id: string; results: EnrichmentResult[] }>(`/incidents/${id}/enrich`, {
      method: "POST",
    }),
  getTimeline: (id: string) => request<TimelineOut>(`/incidents/${id}/timeline`),
  suggestSeverity: (id: string) =>
    request<SeveritySuggestion>(`/incidents/${id}/severity-suggestion`, { method: "POST" }),
  mitreSuggestions: (id: string) =>
    request<{ incident_id: string; suggestions: MitreSuggestion[] }>(`/incidents/${id}/mitre-suggestions`, {
      method: "POST",
    }),
  reportDraft: (id: string) => request<ReportOut>(`/incidents/${id}/report-draft`, { method: "POST" }),
  submitReview: (
    incidentId: string,
    payload: {
      target_entity_type: string;
      target_entity_id: string;
      decision: "approve" | "edit" | "reject";
      comment?: string;
      correction?: string;
    }
  ) =>
    request(`/incidents/${incidentId}/review`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  exportUrl: (id: string, format: "markdown" | "pdf" | "json") =>
    `${BASE_URL}/incidents/${id}/export?format=${format}`,
  auditLogs: (params?: { target?: string; limit?: number }) => {
    const qs = new URLSearchParams();
    if (params?.target) qs.set("target", params.target);
    if (params?.limit) qs.set("limit", String(params.limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return request<AuditLogOut[]>(`/audit-logs${suffix}`);
  },
  ingestDemo: (payload: unknown) =>
    request<{ ingested: number; alert_ids: string[]; incident_id: string }>(`/alerts`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
};
