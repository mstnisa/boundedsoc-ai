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
  ml_triage_label: "routine" | "needs_review" | null;
  ml_confidence: number | null;
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

// --- Commercial modules -----------------------------------------------------

export interface RemediationSuggestion {
  id: string;
  incident_id: string;
  repo_full_name: string;
  file_path: string;
  vulnerable_snippet: string;
  proposed_patch: string;
  cwe_ref: string | null;
  confidence: number;
  rationale: string;
  evidence_refs: string[];
  status: string;
  pr_url: string | null;
  created_at: string;
}

export interface SecretExposureAlert {
  id: string;
  incident_id: string;
  secret_type: string;
  masked_value: string;
  source_ref: string;
  provider: string;
  status: string;
  approved_by: string | null;
  approved_at: string | null;
  revoked_at: string | null;
  escalation_deadline: string | null;
  created_at: string;
}

export type ComplianceFramework = "owasp_top10" | "pci_dss" | "iso27001" | "gdpr";

export interface ComplianceMapping {
  id: string;
  incident_id: string;
  finding_type: string;
  finding_id: string;
  framework: string;
  control_id: string;
  control_title: string;
  confidence: number;
  rationale: string;
  evidence_refs: string[];
  created_at: string;
}

export interface ComplianceMappingResponse {
  incident_id: string;
  framework: string;
  mappings: ComplianceMapping[];
}

export interface ComplianceCoverageOut {
  coverage: Record<string, { total_controls: number; controls_with_evidence: number; mapping_count: number }>;
}

export interface ToolAccessPolicy {
  id: string;
  tool_name: string;
  allowed_actions: string[];
  scope: string;
  updated_by: string;
  updated_at: string;
}

export interface AIActionLogEntry {
  id: string;
  tool_name: string;
  requested_action: string;
  params_summary: Record<string, unknown>;
  allowed: boolean;
  policy_rule_matched: string | null;
  timestamp: string;
}
