import type {
  AIActionLogEntry,
  AuditLogOut,
  ComplianceCoverageOut,
  ComplianceFramework,
  ComplianceMappingResponse,
  EnrichmentResult,
  IOC,
  IncidentDetail,
  IncidentSummary,
  IntegrationOut,
  MitreSuggestion,
  RemediationSuggestion,
  ReportOut,
  SecretExposureAlert,
  SeveritySuggestion,
  TimelineOut,
  ToolAccessPolicy,
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
  listIntegrations: () => request<IntegrationOut[]>(`/integrations`),
  ingestDemo: (payload: unknown) =>
    request<{ ingested: number; alert_ids: string[]; incident_id: string }>(`/alerts`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // --- Remediation Drafting Agent ---
  draftRemediation: (incidentId: string, repoFullName: string) =>
    request<RemediationSuggestion | null>(`/incidents/${incidentId}/remediation-suggestions`, {
      method: "POST",
      body: JSON.stringify({ repo_full_name: repoFullName }),
    }),
  createRemediationPr: (incidentId: string, rid: string) =>
    request<RemediationSuggestion>(`/incidents/${incidentId}/remediation-suggestions/${rid}/create-pr`, {
      method: "POST",
    }),

  // --- Credential Exposure Response ---
  scanSecretExposure: (incidentId: string) =>
    request<SecretExposureAlert[]>(`/incidents/${incidentId}/secret-exposure`, { method: "POST" }),
  revokeSecretExposure: (incidentId: string, sid: string) =>
    request<SecretExposureAlert>(`/incidents/${incidentId}/secret-exposure/${sid}/revoke`, {
      method: "POST",
    }),

  // --- Compliance Mapper ---
  createComplianceMapping: (incidentId: string, framework: ComplianceFramework) =>
    request<ComplianceMappingResponse>(`/incidents/${incidentId}/compliance-mapping`, {
      method: "POST",
      body: JSON.stringify({ framework }),
    }),
  complianceCoverage: () => request<ComplianceCoverageOut>(`/compliance/coverage`),

  // --- MCP/API Security Gateway (admin) ---
  listToolPolicies: () => request<ToolAccessPolicy[]>(`/admin/tool-policies`),
  updateToolPolicy: (toolName: string, allowedActions: string[], scope: string) =>
    request<ToolAccessPolicy>(`/admin/tool-policies/${toolName}`, {
      method: "PUT",
      body: JSON.stringify({ allowed_actions: allowedActions, scope }),
    }),
  listAiActionLog: () => request<AIActionLogEntry[]>(`/admin/ai-action-log`),
};
