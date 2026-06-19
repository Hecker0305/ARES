import type {
  ScanRecord,
  ScanListItem,
  ScanPresetsResponse,
  ScanSubmitRequest,
  FindingSummary,
  FindingDetailRecord,
  MetricData,
  ActiveScan,
  SeverityBreakdown,
  TopVulnCategory,
  ScanQueue,
  Project,
  ReportItem,
  Schedule,
  ComplianceReport,
  ComplianceFinding,
  BountyReport,
  BountyPlatform,
  ScopeEntry,
  TeamMember,
  SettingsData,
  WebhookSettings,
  LLMSettings,
  EnvironmentSettings,
  QueueStatus,
  InstancesResponse,
  CloudScanRecord,
  RedTeamAssessment,
  RedTeamPayload,
  AttackGraphExport,
  AttackChain,
  APIDiscoveryResult,
  RateLimitSettings,
  DiscordSettings,
  AgentMailSettings,
  ExposureResponse,
  ApprovalRequest,
  ApprovalListResponse,
  EStopStatus,
  RiskAsset,
  BusinessImpact,
  RiskTrend,
  SLAEntry,
  SSOConfig,
  SCIMUser,
  EvidenceRecord,
  ChainOfCustodyEntry,
  ImmutableLogEntry,
  TamperCheckResult,
  KGEntity,
  KGRelationship,
  KGAttackPath,
  KGStats,
  ValidationTask,
  ValidationStats,
  PurpleTeamSimulation,
  CoverageReport,
  CopilotQuery,
  CopilotResponse,
  CopilotHistoryEntry,
  ASMAsset,
  ASMStats,
  ComplianceFramework,
  ComplianceControl,
  CollaborationComment,
  CollaborationAssignment,
  EvidenceReview,
  DeployedAgent,
  AgentStats,
} from "@/api/types";

const API_BASE = import.meta.env.VITE_API_BASE || "";

class HttpError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    public body?: unknown,
  ) {
    super(`HTTP ${status}: ${statusText}`);
    this.name = "HttpError";
  }
}

async function fetchAPI<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> | undefined),
  };

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "same-origin",
  });

  if (!res.ok) {
    const body = await res.text().catch(() => null);
    throw new HttpError(res.status, res.statusText, body);
  }

  const contentType = res.headers.get("content-type");
  if (contentType?.includes("application/json")) {
    return res.json() as Promise<T>;
  }

  return (await res.text()) as unknown as T;
}

export { HttpError, fetchAPI };

export const api = {
  metrics: (): Promise<MetricData> => fetchAPI("/api/metrics"),

  activeScans: (): Promise<ActiveScan[]> => fetchAPI("/api/scans/active"),

  severityBreakdown: (): Promise<SeverityBreakdown> =>
    fetchAPI("/api/stats/severity"),

  vulnCategories: (): Promise<TopVulnCategory[]> =>
    fetchAPI("/api/stats/vuln-categories"),

  scanQueue: (): Promise<ScanQueue> => fetchAPI("/api/stats/scan-queue"),

  criticalFindings: (): Promise<FindingSummary[]> =>
    fetchAPI("/api/findings/critical/recent"),

  listScans: async (): Promise<ScanListItem[]> => {
    const res = await fetchAPI("/api/scans");
    if (Array.isArray(res)) return res;
    return (res as { data: ScanListItem[] }).data ?? [];
  },

  getScan: (id: string): Promise<ScanRecord> => fetchAPI(`/api/scans/${id}`),

  deleteScan: (id: string): Promise<{ status: string }> =>
    fetchAPI(`/api/scans/${id}/stop`, { method: "POST" }),

  stopScan: (id: string): Promise<{ status: string }> =>
    fetchAPI(`/api/scans/${id}/stop`, { method: "POST" }),

  getScanFindings: async (id: string): Promise<FindingSummary[]> => {
    const res = await fetchAPI(`/api/scans/${id}/findings`);
    if (Array.isArray(res)) return res;
    return (res as { data: FindingSummary[] }).data ?? [];
  },

  getScanReport: (id: string): Promise<unknown> =>
    fetchAPI(`/api/scans/${id}/report`),

  addScanNote: (
    id: string,
    note: string,
  ): Promise<{ status: string }> =>
    fetchAPI(`/api/scans/${id}/note`, {
      method: "POST",
      body: JSON.stringify({ note }),
    }),

  scanPresets: (): Promise<ScanPresetsResponse> =>
    fetchAPI("/api/scans/presets"),

  submitScan: (
    req: ScanSubmitRequest,
  ): Promise<{ status: string; scan_id: string; scan_mode: string }> =>
    fetchAPI("/api/scans/submit", {
      method: "POST",
      body: JSON.stringify(req),
    }),

  listFindings: async (): Promise<FindingSummary[]> => {
    const res = await fetchAPI("/api/findings");
    if (Array.isArray(res)) return res;
    return (res as { data: FindingSummary[] }).data ?? [];
  },

  getFinding: (id: string): Promise<FindingDetailRecord> =>
    fetchAPI(`/api/findings/${id}`),

  updateFindingStatus: (
    id: string,
    status: string,
  ): Promise<{ status: string }> =>
    fetchAPI(`/api/findings/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ id, status }),
    }),

  deleteFinding: (id: string): Promise<{ status: string }> =>
    fetchAPI(`/api/findings/${id}`, { method: "DELETE" }),

  exportFindings: (
    ids: string[],
  ): Promise<{ status: string; url: string }> =>
    fetchAPI("/api/findings/export", {
      method: "POST",
      body: JSON.stringify({ ids }),
    }),

  verifyFinding: (id: string): Promise<unknown> =>
    fetchAPI(`/api/findings/${id}/verify`, { method: "POST" }),

  listProjects: (): Promise<Project[]> => fetchAPI("/api/projects"),

  listReports: (): Promise<ReportItem[]> =>
    fetchAPI("/api/reports/generate"),

  exportReport: (
    format: string,
  ): Promise<{ status: string; format: string; url: string; findings: number }> =>
    fetchAPI("/api/reports/export", {
      method: "POST",
      body: JSON.stringify({ format }),
    }),

  generateReport: (
    scanId: string,
    format: string,
  ): Promise<{ status: string; path: string; format: string }> =>
    fetchAPI("/api/reports/generate", {
      method: "POST",
      body: JSON.stringify({ scan_id: scanId, format }),
    }),

  deleteReport: (name: string): Promise<{ status: string }> =>
    fetchAPI(`/api/reports/generate?name=${encodeURIComponent(name)}`, {
      method: "DELETE",
    }),

  listSchedules: (): Promise<Schedule[]> => fetchAPI("/api/schedules"),

  createSchedule: (
    data: Omit<Schedule, "id" | "created_at">,
  ): Promise<Schedule> =>
    fetchAPI("/api/schedules", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateSchedule: (
    id: string,
    data: Partial<Schedule>,
  ): Promise<Schedule> =>
    fetchAPI(`/api/schedules/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  deleteSchedule: (id: string): Promise<{ status: string }> =>
    fetchAPI(`/api/schedules/${id}`, { method: "DELETE" }),

  toggleSchedule: (
    id: string,
    action: "pause" | "resume",
  ): Promise<Schedule> =>
    fetchAPI(`/api/schedules/${id}/${action}`, { method: "POST" }),

  listComplianceReports: (): Promise<ComplianceReport[]> =>
    fetchAPI("/api/compliance/reports"),

  listComplianceFindings: (
    framework?: string,
  ): Promise<ComplianceFinding[]> => {
    const q = framework
      ? `?framework=${encodeURIComponent(framework)}`
      : "";
    return fetchAPI(`/api/compliance/findings${q}`);
  },

  listBountyReports: (
    platform?: string,
    status?: string,
  ): Promise<{ reports: BountyReport[]; total: number }> => {
    const params = new URLSearchParams();
    if (platform) params.set("platform", platform);
    if (status) params.set("status", status);
    const q = params.toString() ? `?${params.toString()}` : "";
    return fetchAPI(`/api/bounty/reports${q}`);
  },

  listBountyPlatforms: (): Promise<{
    platforms: BountyPlatform[];
    total: number;
  }> => fetchAPI("/api/bounty/platforms"),

  addBountyPlatform: (
    data: BountyPlatform,
  ): Promise<{ status: string; platform: string }> =>
    fetchAPI("/api/bounty/platforms", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  deleteBountyPlatform: (
    platform: string,
  ): Promise<{ status: string }> =>
    fetchAPI(`/api/bounty/platforms/${platform}`, { method: "DELETE" }),

  syncBountyPlatform: (
    platform: string,
  ): Promise<{ status: string; platform: string; fetched: number; new: number }> =>
    fetchAPI(`/api/bounty/platforms/${platform}/sync`, { method: "POST" }),

  syncAllBounty: (): Promise<{ status: string; new_reports: number }> =>
    fetchAPI("/api/bounty/sync", { method: "POST" }),

  ingestBountyReport: (
    data: BountyReport,
  ): Promise<unknown> =>
    fetchAPI("/api/bounty/ingest", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  listScope: (): Promise<ScopeEntry[]> => fetchAPI("/api/scope"),

  addScope: (
    data: { target: string; tags: string[] },
  ): Promise<ScopeEntry> =>
    fetchAPI("/api/scope", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  deleteScope: (id: string): Promise<{ status: string }> =>
    fetchAPI(`/api/scope/${id}/delete`, { method: "POST" }),

  getSettings: (): Promise<SettingsData> => fetchAPI("/api/settings"),

  saveSettings: (data: SettingsData): Promise<{ status: string }> =>
    fetchAPI("/api/settings", {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  getWebhookSettings: (): Promise<WebhookSettings> =>
    fetchAPI("/api/settings/webhook"),

  saveWebhookSettings: (
    data: WebhookSettings,
  ): Promise<{ status: string }> =>
    fetchAPI("/api/settings/webhook", {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  testWebhook: (): Promise<{ status: string }> =>
    fetchAPI("/api/settings/webhook/test", { method: "POST" }),

  getLLMSettings: (): Promise<LLMSettings> =>
    fetchAPI("/api/settings/llm"),

  saveLLMSettings: (data: LLMSettings): Promise<{ status: string }> =>
    fetchAPI("/api/settings/llm", {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  getTeam: (): Promise<TeamMember[]> =>
    fetchAPI("/api/settings/team"),

  inviteTeamMember: (
    data: { email: string; role: string },
  ): Promise<{ status: string; email: string; role: string }> =>
    fetchAPI("/api/settings/team", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getEnvironmentSettings: (): Promise<EnvironmentSettings> =>
    fetchAPI("/api/settings/env"),

  saveEnvironmentSettings: (
    data: EnvironmentSettings,
  ): Promise<{ status: string }> =>
    fetchAPI("/api/settings/env", {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  getRateLimitSettings: (): Promise<RateLimitSettings> =>
    fetchAPI("/api/settings/rate-limit"),

  saveRateLimitSettings: (data: RateLimitSettings): Promise<{ status: string }> =>
    fetchAPI("/api/settings/rate-limit", {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  getDiscordSettings: (): Promise<DiscordSettings> =>
    fetchAPI("/api/settings/discord"),

  saveDiscordSettings: (data: DiscordSettings): Promise<{ status: string }> =>
    fetchAPI("/api/settings/discord", {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  getAgentMailSettings: (): Promise<AgentMailSettings> =>
    fetchAPI("/api/settings/agentmail"),

  saveAgentMailSettings: (data: AgentMailSettings): Promise<{ status: string }> =>
    fetchAPI("/api/settings/agentmail", {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  queueStatus: (): Promise<QueueStatus> => fetchAPI("/api/queue/status"),

  queueResume: (
    scanId?: string,
  ): Promise<{ status: string; scan_id?: string }> =>
    fetchAPI("/api/queue/resume", {
      method: "POST",
      body: JSON.stringify(scanId ? { scan_id: scanId } : {}),
    }),

  queueClear: (): Promise<{ status: string; cleared: number }> =>
    fetchAPI("/api/queue/clear", { method: "POST" }),

  listInstances: (): Promise<InstancesResponse> =>
    fetchAPI("/api/instances/"),

  pauseInstance: (id: string): Promise<{ status: string; id: string }> =>
    fetchAPI(`/api/instances/${id}/pause`, { method: "POST" }),

  resumeInstance: (id: string): Promise<{ status: string; id: string }> =>
    fetchAPI(`/api/instances/${id}/resume`, { method: "POST" }),

  restartInstance: (
    id: string,
  ): Promise<{ status: string; new_scan_id: string }> =>
    fetchAPI(`/api/instances/${id}/restart`, { method: "POST" }),

  uploadLogo: (file: File): Promise<{ status: string; path: string }> => {
    const form = new FormData();
    form.append("logo", file);
    return fetch(`${API_BASE}/api/upload-logo`, {
      method: "POST",
      body: form,
      credentials: "same-origin",
    }).then((r) => r.json());
  },

  uploadTargets: (
    fileOrJson: File | { targets: string[] },
  ): Promise<{ status: string; scan_ids: string[]; count: number }> => {
    if (fileOrJson instanceof File) {
      const form = new FormData();
      form.append("file", fileOrJson);
      return fetch(`${API_BASE}/api/upload-targets`, {
        method: "POST",
        body: form,
        credentials: "same-origin",
      }).then((r) => r.json());
    }
    return fetchAPI("/api/upload-targets", {
      method: "POST",
      body: JSON.stringify(fileOrJson),
    });
  },

  startCloudScan: (
    path: string,
  ): Promise<{ scan_id: string; status: string; path: string }> =>
    fetchAPI("/api/cloud/scan", {
      method: "POST",
      body: JSON.stringify({ path }),
    }),

  getCloudScan: (id: string): Promise<CloudScanRecord> =>
    fetchAPI(`/api/cloud/scan/${id}`),

  validateCloudConfig: (
    line: string,
  ): Promise<{ input: string; findings: unknown[]; safe: boolean }> =>
    fetchAPI("/api/cloud/validate", {
      method: "POST",
      body: JSON.stringify({ line }),
    }),

  startRedTeamAssessment: (
    targetUrl: string,
    concurrency = 5,
    maxPayloads = 50,
  ): Promise<{ assessment_id: string; status: string; target_url: string }> =>
    fetchAPI("/api/redteam/assess", {
      method: "POST",
      body: JSON.stringify({
        target_url: targetUrl,
        concurrency,
        max_payloads: maxPayloads,
      }),
    }),

  getRedTeamAssessment: (
    id: string,
  ): Promise<RedTeamAssessment> =>
    fetchAPI(`/api/redteam/assess/${id}`),

  getRedTeamPayloads: (): Promise<RedTeamPayload> =>
    fetchAPI("/api/redteam/payloads"),

  testRedTeamPayload: (
    targetUrl: string,
    payload: string,
    testType: string,
  ): Promise<{
    success: boolean;
    classification: string;
    payload: string;
    response: unknown;
  }> =>
    fetchAPI("/api/redteam/custom", {
      method: "POST",
      body: JSON.stringify({
        target_url: targetUrl,
        payload,
        test_type: testType,
      }),
    }),

  exportAttackGraph: (): Promise<AttackGraphExport> =>
    fetchAPI("/api/graph/export"),

  getAttackChains: (
    limit = 10,
  ): Promise<AttackChain[]> =>
    fetchAPI(`/api/graph/chains?limit=${limit}`),

  startAPIDiscovery: (
    target: string,
  ): Promise<{
    scan_id: string;
    target: string;
    status: string;
    check_url: string;
    created_at: string;
  }> =>
    fetchAPI("/api/discover", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  getAPIDiscoveryResults: (
    scanId: string,
  ): Promise<APIDiscoveryResult> =>
    fetchAPI(`/api/discover/${scanId}/results`),

  reportUrl: (scanId: string, reportName?: string): string =>
    `${API_BASE}/api/reports/generate${reportName ? `?name=${encodeURIComponent(reportName)}` : ""}`,

  listExposureFindings: (): Promise<ExposureResponse> =>
    fetchAPI("/api/exposure"),

  listExposureFindingsByType: (type: string): Promise<ExposureResponse> =>
    fetchAPI(`/api/exposure/${type}`),

  listApprovals: (): Promise<ApprovalListResponse> =>
    fetchAPI("/api/approvals"),

  createApproval: (data: Partial<ApprovalRequest>): Promise<{ id: string }> =>
    fetchAPI("/api/approvals", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  approveRequest: (id: string): Promise<{ status: string }> =>
    fetchAPI(`/api/approvals/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ approver: "admin" }),
    }),

  denyRequest: (
    id: string,
    reason: string,
  ): Promise<{ status: string }> =>
    fetchAPI(`/api/approvals/${id}/deny`, {
      method: "POST",
      body: JSON.stringify({ denier: "admin", reason }),
    }),

  getEStopStatus: (): Promise<EStopStatus> =>
    fetchAPI("/api/emergency-stop"),

  triggerEStop: (reason: string): Promise<{ status: string }> =>
    fetchAPI("/api/emergency-stop", {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),

  clearEStop: (): Promise<{ status: string }> =>
    fetchAPI("/api/emergency-stop", { method: "DELETE" }),

  getRiskProfile: () => fetchAPI("/api/risk"),

  listRiskAssets: (): Promise<RiskAsset[]> =>
    fetchAPI("/api/risk/assets"),

  registerRiskAsset: (asset: RiskAsset): Promise<RiskAsset> =>
    fetchAPI("/api/risk/assets", {
      method: "POST",
      body: JSON.stringify(asset),
    }),

  getBusinessImpact: (assetId: string): Promise<BusinessImpact> =>
    fetchAPI(`/api/risk/impact/${assetId}`),

  calculateBusinessImpact: (
    assetId: string,
    score: number,
    exploitability: number,
  ): Promise<BusinessImpact> =>
    fetchAPI(`/api/risk/impact/${assetId}`, {
      method: "POST",
      body: JSON.stringify({
        vulnerability_score: score,
        exploitability,
      }),
    }),

  getRiskTrends: (days = 30): Promise<RiskTrend[]> =>
    fetchAPI(`/api/risk/trends?days=${days}`),

  getOverdueSLA: (): Promise<{ overdue: SLAEntry[]; total: number }> =>
    fetchAPI("/api/risk/sla"),

  getSLACompliance: (): Promise<{ compliance_rate: number }> =>
    fetchAPI("/api/risk/sla/compliance"),

  getSSOConfigs: (): Promise<SSOConfig[]> =>
    fetchAPI("/api/saml/config"),

  saveSSOConfig: (cfg: SSOConfig): Promise<SSOConfig> =>
    fetchAPI("/api/saml/config", {
      method: "POST",
      body: JSON.stringify(cfg),
    }),

  listSCIMUsers: (): Promise<{ Resources: SCIMUser[]; totalResults: number }> =>
    fetchAPI("/api/scim/Users"),

  createSCIMUser: (user: SCIMUser): Promise<SCIMUser> =>
    fetchAPI("/api/scim/Users", {
      method: "POST",
      body: JSON.stringify(user),
    }),

  signEvidence: (
    findingId: string,
    content: unknown,
    createdBy: string,
  ): Promise<EvidenceRecord> =>
    fetchAPI("/api/evidence/sign", {
      method: "POST",
      body: JSON.stringify({
        finding_id: findingId,
        content,
        created_by: createdBy,
      }),
    }),

  verifyEvidence: (
    record: EvidenceRecord,
  ): Promise<{ valid: boolean }> =>
    fetchAPI("/api/evidence/verify", {
      method: "POST",
      body: JSON.stringify(record),
    }),

  getEvidenceChain: (): Promise<ChainOfCustodyEntry[]> =>
    fetchAPI("/api/evidence/chain"),

  getImmutableLog: (): Promise<ImmutableLogEntry[]> =>
    fetchAPI("/api/evidence/log"),

  checkTampering: (): Promise<TamperCheckResult> =>
    fetchAPI("/api/evidence/tamper"),

  getKGStats: (): Promise<KGStats> =>
    fetchAPI("/api/knowledge-graph/stats"),

  getKGEntities: (): Promise<KGEntity[]> =>
    fetchAPI("/api/knowledge-graph/entities"),

  addKGEntity: (entity: KGEntity): Promise<{ id: string }> =>
    fetchAPI("/api/knowledge-graph/entities", {
      method: "POST",
      body: JSON.stringify(entity),
    }),

  getKGRelationships: (entityId: string): Promise<KGRelationship[]> =>
    fetchAPI(`/api/knowledge-graph/relationships?entity_id=${entityId}`),

  addKGRelationship: (
    rel: KGRelationship,
  ): Promise<{ id: string }> =>
    fetchAPI("/api/knowledge-graph/relationships", {
      method: "POST",
      body: JSON.stringify(rel),
    }),

  getKGPaths: (
    start: string,
    end: string,
    maxDepth = 5,
  ): Promise<KGAttackPath[]> =>
    fetchAPI(
      `/api/knowledge-graph/paths?start=${start}&end=${end}&max_depth=${maxDepth}`,
    ),

  getKGExposure: (assetId: string): Promise<KGAttackPath[]> =>
    fetchAPI(`/api/knowledge-graph/exposure?asset_id=${assetId}`),

  getKGByType: (type: string): Promise<KGEntity[]> =>
    fetchAPI(`/api/knowledge-graph/type/${type}`),

  listValidationTasks: (): Promise<{ tasks: ValidationTask[]; total: number }> =>
    fetchAPI("/api/validation-loops/tasks"),

  createValidationTask: (data: {
    finding_id: string;
    target: string;
    vulnerability_type: string;
    evidence: string;
  }): Promise<{ id: string }> =>
    fetchAPI("/api/validation-loops/tasks", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getValidationStats: (): Promise<ValidationStats> =>
    fetchAPI("/api/validation-loops/stats"),

  listPurpleTeamSimulations: (): Promise<PurpleTeamSimulation[]> =>
    fetchAPI("/api/purple-team/simulations"),

  createPurpleTeamSimulation: (
    sim: PurpleTeamSimulation,
  ): Promise<{ id: string }> =>
    fetchAPI("/api/purple-team/simulations", {
      method: "POST",
      body: JSON.stringify(sim),
    }),

  startPurpleTeamSimulation: (
    id: string,
  ): Promise<{ status: string }> =>
    fetchAPI(`/api/purple-team/simulations/${id}/start`, {
      method: "POST",
    }),

  getPurpleTeamCoverage: (): Promise<CoverageReport> =>
    fetchAPI("/api/purple-team/coverage"),

  copilotQuery: (query: CopilotQuery): Promise<CopilotResponse> =>
    fetchAPI("/api/copilot/query", {
      method: "POST",
      body: JSON.stringify(query),
    }),

  copilotHistory: (): Promise<CopilotHistoryEntry[]> =>
    fetchAPI("/api/copilot/history"),

  copilotSuggestions: (): Promise<{ suggestions: string[] }> =>
    fetchAPI("/api/copilot/suggestions"),

  listASMAssets: (): Promise<ASMAsset[]> =>
    fetchAPI("/api/asm/assets"),

  addASMAsset: (asset: ASMAsset): Promise<{ id: string }> =>
    fetchAPI("/api/asm/assets", {
      method: "POST",
      body: JSON.stringify(asset),
    }),

  getASMStats: (): Promise<ASMStats> =>
    fetchAPI("/api/asm/stats"),

  listComplianceFrameworks: (): Promise<ComplianceFramework[]> =>
    fetchAPI("/api/compliance-frameworks"),

  getComplianceFramework: (id: string): Promise<ComplianceFramework> =>
    fetchAPI(`/api/compliance-frameworks/frameworks/${id}`),

  createComplianceFramework: (
    fw: ComplianceFramework,
  ): Promise<{ id: string }> =>
    fetchAPI("/api/compliance-frameworks", {
      method: "POST",
      body: JSON.stringify(fw),
    }),

  addComplianceControl: (
    frameworkId: string,
    control: ComplianceControl,
  ): Promise<{ id: string }> =>
    fetchAPI(`/api/compliance-frameworks/frameworks/${frameworkId}/controls`, {
      method: "POST",
      body: JSON.stringify(control),
    }),

  addCollaborationComment: (data: {
    target_id: string;
    target_type: string;
    author: string;
    content: string;
  }): Promise<{ id: string }> =>
    fetchAPI("/api/collaboration/comments", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getCollaborationComments: (
    targetId: string,
  ): Promise<CollaborationComment[]> =>
    fetchAPI(`/api/collaboration/comments/${targetId}`),

  createAssignment: (data: {
    target_id: string;
    target_type: string;
    assignee: string;
    assigned_by: string;
  }): Promise<{ id: string }> =>
    fetchAPI("/api/collaboration/assignments", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getAssignments: (
    assignee?: string,
  ): Promise<CollaborationAssignment[]> =>
    fetchAPI(
      `/api/collaboration/assignments${assignee ? `?assignee=${assignee}` : ""}`,
    ),

  getEvidenceReviews: (status?: string): Promise<EvidenceReview[]> =>
    fetchAPI(
      `/api/collaboration/reviews${status ? `?status=${status}` : ""}`,
    ),

  approveEvidenceReview: (
    id: string,
    notes?: string,
  ): Promise<{ status: string }> =>
    fetchAPI(`/api/collaboration/reviews/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ notes }),
    }),

  listAgents: (segment?: string): Promise<DeployedAgent[]> =>
    fetchAPI(`/api/agents${segment ? `?segment=${segment}` : ""}`),

  registerAgent: (agent: DeployedAgent): Promise<{ id: string }> =>
    fetchAPI("/api/agents/register", {
      method: "POST",
      body: JSON.stringify(agent),
    }),

  getAgent: (id: string): Promise<DeployedAgent> =>
    fetchAPI(`/api/agents/${id}`),

  agentHeartbeat: (id: string): Promise<{ status: string }> =>
    fetchAPI(`/api/agents/heartbeat/${id}`, { method: "POST" }),

  assignAgentScan: (
    agentId: string,
    target: string,
    scanType = "quick",
  ): Promise<{ task_id: string }> =>
    fetchAPI(`/api/agents/scan/${agentId}`, {
      method: "POST",
      body: JSON.stringify({ target, scan_type: scanType }),
    }),

  getAgentTasks: (agentId?: string) =>
    fetchAPI(`/api/agents/tasks${agentId ? `?agent_id=${agentId}` : ""}`),

  removeAgent: (id: string): Promise<void> =>
    fetchAPI(`/api/agents/${id}`, { method: "DELETE" }),

  getAgentStats: (): Promise<AgentStats> =>
    fetchAPI("/api/agents/stats"),
};

export type ApiClient = typeof api;
