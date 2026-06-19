export interface ScanRecord {
  id: string;
  target: string;
  targets?: string[];
  start_time: string;
  end_time?: string;
  status: "running" | "queued" | "paused" | "saved" | "finished" | "stopped" | "failed";
  phase: string;
  progress: number;
  findings: FindingSummary[];
  events: ScanEvent[];
  scan_mode?: string;
  phases?: string[];
  preset?: string;
  workers?: number;
  env_vars?: Record<string, string>;
  resource_limits?: Record<string, number>;
  notes?: string[];
  duration?: string;
  current_phase?: number;
  sub_scans?: SubScanSummary[];
  sub_scan_total?: number;
  sub_scan_completed?: number;
  sub_scan_running?: number;
  sub_scan_remaining?: number;
}

export interface ScanListItem {
  id: string;
  target: string;
  start_time: string;
  status: string;
  phase: string;
  progress: number;
  findings_count: number;
}

export interface SubScanSummary {
  id: string;
  target: string;
  started_at?: string;
  finished_at?: string;
  status: string;
  vuln_count: number;
  total_tokens: number;
}

export interface ScanPreset {
  name: string;
  description: string;
  phases: string[];
  scan_mode: string;
}

export interface Phase22Info {
  id: number;
  name: string;
  description?: string;
}

export interface ScanModeInfo {
  id: string;
  name: string;
  description: string;
}

export interface ScanPresetsResponse {
  presets: ScanPreset[];
  phases: Phase22Info[];
  scanModes: ScanModeInfo[];
}

export interface ScanSubmitRequest {
  target: string;
  targets?: string[];
  preset?: string;
  scanProfile?: string;
  workers?: number;
  phases?: string[];
  scanMode?: string;
  envVars?: Record<string, string>;
  outOfScope?: string[];
  resourceLimits?: Record<string, number>;
  severityFilter?: string[];
  model?: string;
  displayName?: string;
  companyName?: string;
  logoPath?: string;
}

export interface FindingSummary {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  endpoint: string;
  status: string;
  project?: string;
  discoveredAt: string;
  cvssScore?: number;
  scan_id?: string;
  cve?: string;
}

export interface FindingDetailRecord {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  endpoint: string;
  status: string;
  project?: string;
  discoveredAt: string;
  cvssScore?: number;
  description: string;
  impact: string;
  remediation: string;
  poc?: string;
  cve?: string;
  mitreMapping?: { tactic: string; technique: string; id: string }[];
  complianceMapping?: { framework: string; controlId: string }[];
  verificationChain?: { round: number; result: string; timestamp: string }[];
  scan_id?: string;
}

export interface ScanEvent {
  type: string;
  content?: string;
  tool_name?: string;
  tool_args?: Record<string, string>;
  output?: string;
  error?: string;
  agent_id?: string;
  instance_id?: string;
  timestamp?: string;
  vulns?: FindingSummary[];
  current_phase?: number;
}

export interface MetricData {
  totalScans: number;
  scansDelta: string;
  criticalFindings: number;
  criticalUnresolved: number;
  targetsCovered: number;
  targetProjects: number;
  verifiedRate: number;
  rateLabel: string;
}

export interface ActiveScan {
  target: string;
  status: string;
  progress: number;
  phase: string;
  id?: string;
}

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface TopVulnCategory {
  name: string;
  count: number;
}

export interface ScanQueue {
  running: number;
  queued: number;
  completedToday: number;
  workersAvailable: number;
  workersTotal: number;
}

export interface Project {
  id: string;
  name: string;
  target: string;
  severity: string;
  totalFindings: number;
  lastScan: string;
  status: string;
}

export interface ReportItem {
  name: string;
  size: string;
  modified: string;
  format: string;
  scan_id?: string;
  findings?: number;
}

export interface ReportConfig {
  clientName: string;
  tester: string;
  engagementRef: string;
  classification: string;
  logoUrl: string;
}

export interface Schedule {
  id: string;
  name: string;
  target: string;
  cron_expr: string;
  enabled: boolean;
  created_by: string;
  created_at?: string;
  last_run?: string;
  next_run?: string;
}

export interface ComplianceReport {
  framework: string;
  score: number;
  controlsPassed: number;
  controlsFailed: number;
  gapsCritical: number;
  gapsHigh: number;
  lastAssessed: string;
}

export interface ComplianceFinding {
  framework: string;
  controlId: string;
  status: string;
  severity: string;
  description: string;
  evidence: string;
  remediation: string;
}

export interface BountyReport {
  id: string;
  platform: string;
  title: string;
  severity: string;
  target: string;
  researcher: string;
  status: string;
  bounty?: number;
  created_at: string;
}

export interface BountyPlatform {
  platform: string;
  api_token?: string;
  username: string;
  enabled: boolean;
  reports?: number;
  bounty_earned?: number;
  auto_sync?: boolean;
}

export interface ScopeEntry {
  id: string;
  target: string;
  tags: string[];
  authorized: boolean;
}

export interface TeamMember {
  name: string;
  role: string;
  lastActive: string;
}

export interface SettingsData {
  instanceName: string;
  maxWorkers: number;
  evidenceRetention: string;
  confidenceGate: number;
}

export interface WebhookSettings {
  url: string;
  secret: string;
  events: string[];
}

export interface LLMSettings {
  provider: string;
  model: string;
  baseURL: string;
}

export interface EnvironmentSettings {
  [key: string]: string;
}

export interface QueueStatus {
  running: number;
  queued: number;
  completedToday: number;
  total: number;
  status: string;
}

export interface ScanInstance {
  id: string;
  target: string;
  status: string;
  phase: string;
  progress: number;
  findings_count: number;
  iterations: number;
  tokens: number;
  start_time: string;
  duration?: string;
}

export interface InstancesResponse {
  instances: ScanInstance[];
  total: number;
  resource?: {
    cpu: number;
    memory: number;
    disk: number;
    level: string;
    reason: string;
  };
}

export interface CloudScanRecord {
  id: string;
  path: string;
  status: string;
  findings: FindingSummary[];
  error?: string;
  start_time: string;
  end_time?: string;
}

export interface RedTeamAssessment {
  assessment_id: string;
  status: string;
  target_url: string;
  results?: RedTeamResult;
}

export interface RedTeamResult {
  total_payloads: number;
  successful_injections: number;
  refused: number;
  unclear: number;
  findings: FindingSummary[];
}

export interface RedTeamPayload {
  prompt_injections: string[];
  data_extractions: string[];
  jailbreaks: string[];
  total: number;
}

export interface AttackGraphExport {
  nodes: { id: string; label: string; type: string; severity?: string }[];
  edges: { source: string; target: string; label: string }[];
  chains: { id: string; name: string; steps: string[]; severity: string }[];
  statistics: { total_nodes: number; total_edges: number; total_chains: number };
}

export interface AttackChain {
  id: string;
  name: string;
  steps: string[];
  severity: string;
}

export interface APIDiscoveryResult {
  scan_id: string;
  target: string;
  status: "completed" | "running";
  result?: {
    endpoints: { path: string; method: string; auth: boolean }[];
    schemas: Record<string, unknown>;
  };
  error?: string;
  created_at: string;
  done_at?: string;
}

export interface WSEvent {
  type: string;
  content?: string;
  tool_name?: string;
  tool_args?: Record<string, string>;
  output?: string;
  error?: string;
  agent_id?: string;
  instance_id?: string;
  timestamp?: string;
  vulns?: FindingSummary[];
  current_phase?: number;
}

export interface VersionInfo {
  version: string;
  commit?: string;
  build_time?: string;
}

export interface RateLimitSettings {
  requestsPerWindow: number;
  windowSeconds: number;
}

export interface DiscordSettings {
  webhookUrl: string;
  minimumSeverity: string;
}

export interface AgentMailSettings {
  pod: string;
  apiKey: string;
  hasApiKey?: boolean;
}

export interface LLMSettingsExtended {
  provider: string;
  model: string;
  baseURL: string;
  apiKey?: string;
  reasoningEffort?: string;
  llmMaxRetries?: number;
  memoryCompressorTimeout?: number;
  maxIterations?: number;
  geminiApiKey?: string;
}

export interface EnvVarDefinition {
  key: string;
  label: string;
  category: string;
  description: string;
  defaultValue?: string;
  placeholder?: string;
  inputType: "text" | "url" | "path" | "secret" | "number" | "boolean" | "select";
  options?: string[];
  sensitive: boolean;
  requiresRestart: boolean;
  value: string;
  hasValue: boolean;
}

export interface EnvironmentSettingsExtended {
  envFile: string;
  variables: EnvVarDefinition[];
  restartRequired?: boolean;
}

export interface ExposureFinding {
  id: string;
  type: string;
  severity: string;
  title: string;
  description: string;
  source: string;
  target: string;
  details?: Record<string, string>;
  discovered: string;
  status: string;
  remediation?: string;
}

export interface ExposureResponse {
  findings: ExposureFinding[];
  total: number;
}

export interface ApprovalRequest {
  id: string;
  type: string;
  status: string;
  requester: string;
  target: string;
  reason: string;
  details?: Record<string, string>;
  created_at: string;
  expires_at: string;
  approved_by?: string;
  approved_at?: string;
  denied_by?: string;
  denied_at?: string;
  deny_reason?: string;
}

export interface ApprovalListResponse {
  approvals: ApprovalRequest[];
  total: number;
}

export interface EStopStatus {
  active: boolean;
  reason: string;
  triggered_at: string;
}

export interface RiskAsset {
  id: string;
  name: string;
  type: string;
  criticality: string;
  business_value: number;
  owner: string;
  compliance?: string[];
}

export interface BusinessImpact {
  asset_id: string;
  impact_score: number;
  financial_impact: number;
  reputational: number;
  regulatory: number;
  operational: number;
  calculated_at: string;
}

export interface RiskTrend {
  date: string;
  avg_score: number;
  max_score: number;
  total_open: number;
}

export interface SLAEntry {
  id: string;
  finding_id: string;
  policy_id: string;
  detected_at: string;
  remediated_at?: string;
  due_by: string;
  overdue: boolean;
}

export interface SSOConfig {
  provider: string;
  issuer_url: string;
  sso_url: string;
  entity_id: string;
  certificate?: string;
  metadata_url?: string;
  groups_attr?: string;
  email_attr?: string;
  name_id_format?: string;
}

export interface SCIMUser {
  id: string;
  userName: string;
  name?: string;
  email?: string;
  role?: string;
  active: boolean;
  groups?: string[];
}

export interface EvidenceRecord {
  id: string;
  finding_id: string;
  content_hash: string;
  signing_key_id: string;
  signature: string;
  timestamp: string;
  previous_id?: string;
  chain_root?: string;
  created_by: string;
  action: string;
}

export interface ChainOfCustodyEntry {
  id: string;
  evidence_id: string;
  action: string;
  performed_by: string;
  timestamp: string;
  notes: string;
  previous_hash: string;
  hash: string;
}

export interface ImmutableLogEntry {
  id: string;
  timestamp: string;
  level: string;
  message: string;
  previous_hash: string;
  hash: string;
  data?: string;
}

export interface TamperCheckResult {
  tampered: boolean;
  issues: string[];
}

export interface KGEntity {
  id: string;
  type: string;
  name: string;
  properties?: Record<string, unknown>;
  risk_score?: number;
  criticality?: string;
  created_at: string;
  updated_at: string;
}

export interface KGRelationship {
  id: string;
  source_id: string;
  target_id: string;
  type: string;
  properties?: Record<string, unknown>;
  weight?: number;
  created_at: string;
}

export interface KGAttackPath {
  path: KGEntity[];
  relationships: KGRelationship[];
  total_risk: number;
  steps: number;
  description: string;
}

export interface KGStats {
  total_entities: number;
  total_relationships: number;
  entities_by_type: Record<string, number>;
  average_risk_score: number;
}

export interface ValidationTask {
  id: string;
  finding_id: string;
  target: string;
  vulnerability_type: string;
  original_evidence: string;
  status: string;
  attempts: number;
  max_attempts: number;
  last_result?: string;
  created_at: string;
  last_checked_at?: string;
  resolved_at?: string;
}

export interface ValidationStats {
  [key: string]: number;
}

export interface PurpleTeamSimulation {
  id: string;
  type: string;
  name: string;
  status: string;
  target: string;
  techniques?: string[];
  detection_sources?: string[];
  results?: SimulationResult[];
  created_at: string;
  completed_at?: string;
}

export interface SimulationResult {
  technique: string;
  detected: boolean;
  detection_source: string;
  alert_name?: string;
  response_time?: string;
  notes?: string;
}

export interface CoverageReport {
  total_simulations: number;
  detection_coverage: Record<string, number>;
  detected_by_source: Record<string, number>;
  total_by_source: Record<string, number>;
}

export interface CopilotQuery {
  query: string;
  context?: string;
}

export interface CopilotResponse {
  answer: string;
  sql?: string;
  data?: unknown;
  confidence: number;
  suggested_actions?: string[];
}

export interface CopilotHistoryEntry {
  question: string;
  answer: string;
  timestamp: string;
}

export interface ASMAsset {
  id: string;
  type: string;
  name: string;
  discovered_at: string;
  last_seen_at: string;
  exposure: string;
  services?: string[];
  cloud_provider?: string;
  region?: string;
  tags?: string[];
}

export interface ASMStats {
  total_assets: number;
  by_type: Record<string, number>;
  by_exposure: Record<string, number>;
  last_discovered: string;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  description: string;
  controls: ComplianceControl[];
  created_at: string;
  updated_at: string;
}

export interface ComplianceControl {
  id: string;
  framework_id: string;
  control_id: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  mapping?: string[];
  tests?: string[];
}

export interface CollaborationComment {
  id: string;
  target_id: string;
  target_type: string;
  author: string;
  content: string;
  created_at: string;
  updated_at: string;
}

export interface CollaborationAssignment {
  id: string;
  target_id: string;
  target_type: string;
  assignee: string;
  assigned_by: string;
  status: string;
  due_date?: string;
  created_at: string;
  completed_at?: string;
}

export interface EvidenceReview {
  id: string;
  finding_id: string;
  reviewer: string;
  status: string;
  notes?: string;
  created_at: string;
  reviewed_at?: string;
}

export interface DeployedAgent {
  id: string;
  name: string;
  type: string;
  status: string;
  version: string;
  hostname: string;
  ip_address: string;
  os: string;
  network_segment: string;
  capabilities?: string[];
  last_heartbeat: string;
  deployed_at: string;
  tags?: Record<string, string>;
}

export interface AgentStats {
  total_agents: number;
  online_agents: number;
  offline_agents: number;
  scanning_agents: number;
  by_type: Record<string, number>;
  by_segment: Record<string, number>;
  total_tasks: number;
}
