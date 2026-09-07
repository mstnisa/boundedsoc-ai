export type Severity = "unknown" | "low" | "medium" | "high" | "critical";
export type IncidentStatus =
  | "new"
  | "triaging"
  | "investigating"
  | "pending_review"
  | "closed_true_positive"
  | "closed_false_positive";

export interface IncidentSummary {
  id: string;
  title: string;
  severity: Severity;
  severity_source: string;
  status: IncidentStatus;
  created_at: string;
  closed_at: string | null;
}

export interface IncidentDetail extends IncidentSummary {
  alert_count: number;
  event_count: number;
  ioc_count: number;
}

export interface IOC {
  id: string;
  incident_id: string;
  type: string;
  value: string;
  first_seen: string;
}

export interface EnrichmentResult {
  id: string;
  ioc_id: string;
  provider: string;
  verdict: string;
  confidence: number;
  evidence: Record<string, unknown>;
  fetched_at: string;
  is_mocked: boolean;
}

export interface TimelineEventOut {
  sequence: number;
  event_id: string;
  event_type: string;
  source_host: string | null;
  timestamp: string;
  raw_data: Record<string, unknown>;
}

export interface TimelineOut {
  id: string;
  incident_id: string;
  generated_at: string;
  events: TimelineEventOut[];
}

export interface MitreSuggestion {
  id: string;
  incident_id: string;
  technique_id: string;
  technique_name: string;
  rationale: string;
  confidence: number;
  evidence_refs: string[];
  status: string;
  model_metadata: Record<string, unknown>;
}

export interface ReportOut {
  id: string;
  incident_id: string;
  version: number;
  content: string;
  status: string;
  generated_by: string;
  generated_at: string;
  model_metadata: Record<string, unknown>;
}

export interface AuditLogOut {
  id: string;
  actor: string;
  action: string;
  target: string;
  reason: string;
  details: Record<string, unknown>;
  timestamp: string;
}

export interface IntegrationOut {
  id: string;
  name: string;
  type: string;
  config_ref: string;
  enabled: boolean;
}

export interface SeveritySuggestion {
  suggested: boolean;
  severity?: Severity;
  confidence?: number;
  rationale?: string;
  evidence_refs?: string[];
  errors?: string[];
}
