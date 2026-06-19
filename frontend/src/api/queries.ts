import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "@/api/client";

const qk = {
  metrics: ["metrics"] as const,
  activeScans: ["activeScans"] as const,
  severity: ["severity"] as const,
  vulnCategories: ["vulnCategories"] as const,
  scanQueue: ["scanQueue"] as const,
  criticalFindings: ["criticalFindings"] as const,
  scans: ["scans"] as const,
  scan: (id: string) => ["scan", id] as const,
  scanFindings: (id: string) => ["scanFindings", id] as const,
  findings: ["findings"] as const,
  finding: (id: string) => ["finding", id] as const,
  projects: ["projects"] as const,
  reports: ["reports"] as const,
  schedules: ["schedules"] as const,
  complianceReports: ["complianceReports"] as const,
  complianceFindings: (fw?: string) =>
    ["complianceFindings", fw] as const,
  bountyReports: (platform?: string, status?: string) =>
    ["bountyReports", platform, status] as const,
  bountyPlatforms: ["bountyPlatforms"] as const,
  scope: ["scope"] as const,
  settings: ["settings"] as const,
  webhookSettings: ["webhookSettings"] as const,
  llmSettings: ["llmSettings"] as const,
  team: ["team"] as const,
  envSettings: ["envSettings"] as const,
  queueStatus: ["queueStatus"] as const,
  instances: ["instances"] as const,
  cloudScans: ["cloudScans"] as const,
  redTeamPayloads: ["redTeamPayloads"] as const,
  attackGraph: ["attackGraph"] as const,
  attackChains: ["attackChains"] as const,
  rateLimitSettings: ["rateLimitSettings"] as const,
  discordSettings: ["discordSettings"] as const,
  agentMailSettings: ["agentMailSettings"] as const,
  exposure: ["exposure"] as const,
  approvals: ["approvals"] as const,
  riskProfile: ["riskProfile"] as const,
  riskAssets: ["riskAssets"] as const,
  riskTrends: (days: number) => ["riskTrends", days] as const,
  slaCompliance: ["slaCompliance"] as const,
  ssoConfigs: ["ssoConfigs"] as const,
  scimUsers: ["scimUsers"] as const,
  evidenceChain: ["evidenceChain"] as const,
  evidenceLog: ["evidenceLog"] as const,
  tamperCheck: ["tamperCheck"] as const,
  kgStats: ["kgStats"] as const,
  kgEntities: ["kgEntities"] as const,
  validationTasks: ["validationTasks"] as const,
  validationStats: ["validationStats"] as const,
  purpleTeamSims: ["purpleTeamSims"] as const,
  ptCoverage: ["ptCoverage"] as const,
  copilotHistory: ["copilotHistory"] as const,
  copilotSuggestions: ["copilotSuggestions"] as const,
  asmAssets: ["asmAssets"] as const,
  asmStats: ["asmStats"] as const,
  complianceFrameworks: ["complianceFrameworks"] as const,
  comments: (id: string) => ["comments", id] as const,
  assignments: (user: string) => ["assignments", user] as const,
  reviews: (status: string) => ["reviews", status] as const,
  agents: ["agents"] as const,
  agentStats: ["agentStats"] as const,
};

export { qk };

export function useMetrics() {
  return useQuery({
    queryKey: qk.metrics,
    queryFn: api.metrics,
    refetchInterval: 10000,
  });
}

export function useActiveScans() {
  return useQuery({
    queryKey: qk.activeScans,
    queryFn: api.activeScans,
    refetchInterval: 5000,
  });
}

export function useSeverityBreakdown() {
  return useQuery({
    queryKey: qk.severity,
    queryFn: api.severityBreakdown,
    refetchInterval: 15000,
  });
}

export function useVulnCategories() {
  return useQuery({
    queryKey: qk.vulnCategories,
    queryFn: api.vulnCategories,
    refetchInterval: 30000,
  });
}

export function useScanQueue() {
  return useQuery({
    queryKey: qk.scanQueue,
    queryFn: api.scanQueue,
    refetchInterval: 10000,
  });
}

export function useCriticalFindings() {
  return useQuery({
    queryKey: qk.criticalFindings,
    queryFn: api.criticalFindings,
    refetchInterval: 15000,
  });
}

export function useScansList() {
  return useQuery({
    queryKey: qk.scans,
    queryFn: api.listScans,
    refetchInterval: 15000,
  });
}

export function useScan(id?: string) {
  return useQuery({
    queryKey: qk.scan(id || ""),
    queryFn: () => api.getScan(id!),
    enabled: !!id,
    refetchInterval: (query) =>
      query.state.data?.status === "running" ? 2000 : false,
  });
}

export function useScanFindings(id?: string) {
  return useQuery({
    queryKey: qk.scanFindings(id || ""),
    queryFn: () => api.getScanFindings(id!),
    enabled: !!id,
    refetchInterval: 5000,
  });
}

export function useFindings() {
  return useQuery({
    queryKey: qk.findings,
    queryFn: api.listFindings,
    refetchInterval: 15000,
  });
}

export function useFinding(id?: string) {
  return useQuery({
    queryKey: qk.finding(id || ""),
    queryFn: () => api.getFinding(id!),
    enabled: !!id,
  });
}

export function useProjects() {
  return useQuery({
    queryKey: qk.projects,
    queryFn: api.listProjects,
    refetchInterval: 30000,
  });
}

export function useReports() {
  return useQuery({
    queryKey: qk.reports,
    queryFn: api.listReports,
    refetchInterval: 30000,
  });
}

export function useSchedules() {
  return useQuery({
    queryKey: qk.schedules,
    queryFn: api.listSchedules,
    refetchInterval: 15000,
  });
}

export function useComplianceReports() {
  return useQuery({
    queryKey: qk.complianceReports,
    queryFn: api.listComplianceReports,
    refetchInterval: 60000,
  });
}

export function useComplianceFindings(framework?: string) {
  return useQuery({
    queryKey: qk.complianceFindings(framework),
    queryFn: () => api.listComplianceFindings(framework),
    refetchInterval: 30000,
  });
}

export function useBountyReports(platform?: string, status?: string) {
  return useQuery({
    queryKey: ["bountyReports", platform, status],
    queryFn: () => api.listBountyReports(platform, status),
    refetchInterval: 30000,
  });
}

export function useBountyPlatforms() {
  return useQuery({
    queryKey: qk.bountyPlatforms,
    queryFn: api.listBountyPlatforms,
    refetchInterval: 60000,
  });
}

export function useScope() {
  return useQuery({
    queryKey: qk.scope,
    queryFn: api.listScope,
    refetchInterval: 60000,
  });
}

export function useSettings() {
  return useQuery({
    queryKey: qk.settings,
    queryFn: api.getSettings,
    refetchInterval: 60000,
  });
}

export function useWebhookSettings() {
  return useQuery({
    queryKey: qk.webhookSettings,
    queryFn: api.getWebhookSettings,
    refetchInterval: 60000,
  });
}

export function useLLMSettings() {
  return useQuery({
    queryKey: qk.llmSettings,
    queryFn: api.getLLMSettings,
    refetchInterval: 60000,
  });
}

export function useTeam() {
  return useQuery({
    queryKey: qk.team,
    queryFn: api.getTeam,
    refetchInterval: 60000,
  });
}

export function useEnvironmentSettings() {
  return useQuery({
    queryKey: qk.envSettings,
    queryFn: api.getEnvironmentSettings,
    refetchInterval: 60000,
  });
}

export function useQueueStatus() {
  return useQuery({
    queryKey: qk.queueStatus,
    queryFn: api.queueStatus,
    refetchInterval: 10000,
  });
}

export function useInstances() {
  return useQuery({
    queryKey: qk.instances,
    queryFn: api.listInstances,
    refetchInterval: 8000,
  });
}

export function useScanPresets() {
  return useQuery({
    queryKey: ["scanPresets"],
    queryFn: api.scanPresets,
    staleTime: 300000,
  });
}

export function useAttackGraph() {
  return useQuery({
    queryKey: qk.attackGraph,
    queryFn: api.exportAttackGraph,
    refetchInterval: 30000,
  });
}

export function useAttackChains(limit = 10) {
  return useQuery({
    queryKey: qk.attackChains,
    queryFn: () => api.getAttackChains(limit),
    refetchInterval: 30000,
  });
}

export function useRedTeamPayloads() {
  return useQuery({
    queryKey: qk.redTeamPayloads,
    queryFn: api.getRedTeamPayloads,
    staleTime: 300000,
  });
}

export function useRateLimitSettings() {
  return useQuery({
    queryKey: qk.rateLimitSettings,
    queryFn: api.getRateLimitSettings,
    refetchInterval: 60000,
  });
}

export function useDiscordSettings() {
  return useQuery({
    queryKey: qk.discordSettings,
    queryFn: api.getDiscordSettings,
    refetchInterval: 60000,
  });
}

export function useAgentMailSettings() {
  return useQuery({
    queryKey: qk.agentMailSettings,
    queryFn: api.getAgentMailSettings,
    refetchInterval: 60000,
  });
}

export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.submitScan,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.scans });
      qc.invalidateQueries({ queryKey: ["scan"] });
      qc.invalidateQueries({ queryKey: qk.instances });
      qc.invalidateQueries({ queryKey: qk.metrics });
    },
  });
}

export function useStopScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.stopScan,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.scans });
      qc.invalidateQueries({ queryKey: ["scan"] });
      qc.invalidateQueries({ queryKey: qk.instances });
      qc.invalidateQueries({ queryKey: qk.metrics });
    },
  });
}

export function useDeleteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.deleteScan,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.scans });
      qc.invalidateQueries({ queryKey: ["scan"] });
      qc.invalidateQueries({ queryKey: qk.instances });
      qc.invalidateQueries({ queryKey: qk.metrics });
    },
  });
}

export function useUpdateFindingStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.updateFindingStatus(id, status),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.findings });
      qc.invalidateQueries({ queryKey: qk.metrics });
    },
  });
}

export function useDeleteFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.deleteFinding,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.findings });
      qc.invalidateQueries({ queryKey: qk.metrics });
    },
  });
}

export function useCreateSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.createSchedule,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.schedules });
    },
  });
}

export function useDeleteSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.deleteSchedule,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.schedules });
    },
  });
}

export function useToggleSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, action }: { id: string; action: "pause" | "resume" }) =>
      api.toggleSchedule(id, action),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.schedules });
    },
  });
}

export function useSaveSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.saveSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.settings });
    },
  });
}

export function useSaveWebhookSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.saveWebhookSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.webhookSettings });
    },
  });
}

export function useSaveLLMSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.saveLLMSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.llmSettings });
    },
  });
}

export function useSaveEnvironmentSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.saveEnvironmentSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.envSettings });
    },
  });
}

export function useInviteTeamMember() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.inviteTeamMember,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.team });
    },
  });
}

export function useAddScope() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.addScope,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.scope });
    },
  });
}

export function useDeleteScope() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.deleteScope,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.scope });
    },
  });
}

export function usePauseInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.pauseInstance,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.instances });
      qc.invalidateQueries({ queryKey: ["scan"] });
    },
  });
}

export function useResumeInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.resumeInstance,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.instances });
      qc.invalidateQueries({ queryKey: ["scan"] });
    },
  });
}

export function useRestartInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.restartInstance,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.instances });
      qc.invalidateQueries({ queryKey: qk.scans });
      qc.invalidateQueries({ queryKey: ["scan"] });
    },
  });
}

export function useQueueResume() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.queueResume,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.queueStatus });
      qc.invalidateQueries({ queryKey: qk.instances });
    },
  });
}

export function useQueueClear() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.queueClear,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.queueStatus });
    },
  });
}

export function useGenerateReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ scanId, format }: { scanId: string; format: string }) =>
      api.generateReport(scanId, format),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.reports });
    },
  });
}

export function useDeleteReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.deleteReport,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.reports });
    },
  });
}

export function useExportReport() {
  return useMutation({
    mutationFn: api.exportReport,
  });
}

export function useTestWebhook() {
  return useMutation({
    mutationFn: api.testWebhook,
  });
}

export function useVerifyFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.verifyFinding,
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: qk.finding(id) });
    },
  });
}

export function useStartCloudScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.startCloudScan,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.cloudScans });
    },
  });
}

export function useStartRedTeamAssessment() {
  return useMutation({
    mutationFn: ({ targetUrl, concurrency, maxPayloads }: { targetUrl: string; concurrency?: number; maxPayloads?: number }) =>
      api.startRedTeamAssessment(targetUrl, concurrency, maxPayloads),
  });
}

export function useTestRedTeamPayload() {
  return useMutation({
    mutationFn: ({ targetUrl, payload, testType }: { targetUrl: string; payload: string; testType: string }) =>
      api.testRedTeamPayload(targetUrl, payload, testType),
  });
}

export function useStartAPIDiscovery() {
  return useMutation({
    mutationFn: api.startAPIDiscovery,
  });
}

export function useAddBountyPlatform() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.addBountyPlatform,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.bountyPlatforms });
    },
  });
}

export function useDeleteBountyPlatform() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.deleteBountyPlatform,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.bountyPlatforms });
    },
  });
}

export function useSyncBountyPlatform() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.syncBountyPlatform,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["bountyPlatforms"] });
      qc.invalidateQueries({ queryKey: ["bountyReports"] });
    },
  });
}

export function useSyncAllBounty() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.syncAllBounty,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["bountyPlatforms"] });
      qc.invalidateQueries({ queryKey: ["bountyReports"] });
    },
  });
}

export function useSaveRateLimitSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.saveRateLimitSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.rateLimitSettings });
    },
  });
}

export function useSaveDiscordSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.saveDiscordSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.discordSettings });
    },
  });
}

export function useSaveAgentMailSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.saveAgentMailSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.agentMailSettings });
    },
  });
}

export function useExposureFindings() {
  return useQuery({
    queryKey: qk.exposure,
    queryFn: api.listExposureFindings,
    refetchInterval: 60000,
  });
}

export function useApprovals() {
  return useQuery({
    queryKey: qk.approvals,
    queryFn: api.listApprovals,
    refetchInterval: 10000,
  });
}

export function useCreateApproval() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.createApproval,
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.approvals }),
  });
}

export function useApproveRequest() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id }: { id: string }) => api.approveRequest(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.approvals }),
  });
}

export function useDenyRequest() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.denyRequest(id, reason),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.approvals }),
  });
}

export function useEStopStatus() {
  return useQuery({
    queryKey: ["eStop"],
    queryFn: api.getEStopStatus,
    refetchInterval: 5000,
  });
}

export function useRiskProfile() {
  return useQuery({
    queryKey: qk.riskProfile,
    queryFn: api.getRiskProfile,
    refetchInterval: 30000,
  });
}

export function useRiskAssets() {
  return useQuery({
    queryKey: qk.riskAssets,
    queryFn: api.listRiskAssets,
  });
}

export function useRiskTrends(days = 30) {
  return useQuery({
    queryKey: qk.riskTrends(days),
    queryFn: () => api.getRiskTrends(days),
  });
}

export function useSLACompliance() {
  return useQuery({
    queryKey: qk.slaCompliance,
    queryFn: api.getSLACompliance,
    refetchInterval: 60000,
  });
}

export function useSSOConfigs() {
  return useQuery({
    queryKey: qk.ssoConfigs,
    queryFn: api.getSSOConfigs,
  });
}

export function useSCIMUsers() {
  return useQuery({
    queryKey: qk.scimUsers,
    queryFn: api.listSCIMUsers,
  });
}

export function useEvidenceChain() {
  return useQuery({
    queryKey: qk.evidenceChain,
    queryFn: api.getEvidenceChain,
  });
}

export function useImmutableLog() {
  return useQuery({
    queryKey: qk.evidenceLog,
    queryFn: api.getImmutableLog,
  });
}

export function useTamperCheck() {
  return useQuery({
    queryKey: qk.tamperCheck,
    queryFn: api.checkTampering,
  });
}

export function useKGStats() {
  return useQuery({
    queryKey: qk.kgStats,
    queryFn: api.getKGStats,
    refetchInterval: 30000,
  });
}

export function useKGEntities() {
  return useQuery({
    queryKey: qk.kgEntities,
    queryFn: api.getKGEntities,
  });
}

export function useValidationTasks() {
  return useQuery({
    queryKey: qk.validationTasks,
    queryFn: api.listValidationTasks,
    refetchInterval: 15000,
  });
}

export function useValidationStats() {
  return useQuery({
    queryKey: qk.validationStats,
    queryFn: api.getValidationStats,
    refetchInterval: 15000,
  });
}

export function usePurpleTeamSimulations() {
  return useQuery({
    queryKey: qk.purpleTeamSims,
    queryFn: api.listPurpleTeamSimulations,
    refetchInterval: 10000,
  });
}

export function usePurpleTeamCoverage() {
  return useQuery({
    queryKey: qk.ptCoverage,
    queryFn: api.getPurpleTeamCoverage,
    refetchInterval: 30000,
  });
}

export function useCopilotHistory() {
  return useQuery({
    queryKey: qk.copilotHistory,
    queryFn: api.copilotHistory,
  });
}

export function useCopilotSuggestions() {
  return useQuery({
    queryKey: qk.copilotSuggestions,
    queryFn: api.copilotSuggestions,
    staleTime: 600000,
  });
}

export function useASMAssets() {
  return useQuery({
    queryKey: qk.asmAssets,
    queryFn: api.listASMAssets,
    refetchInterval: 60000,
  });
}

export function useASMStats() {
  return useQuery({
    queryKey: qk.asmStats,
    queryFn: api.getASMStats,
    refetchInterval: 60000,
  });
}

export function useComplianceFrameworks() {
  return useQuery({
    queryKey: qk.complianceFrameworks,
    queryFn: api.listComplianceFrameworks,
  });
}

export function useAgents(segment?: string) {
  return useQuery({
    queryKey: [...qk.agents, segment],
    queryFn: () => api.listAgents(segment),
    refetchInterval: 10000,
  });
}

export function useAgentStats() {
  return useQuery({
    queryKey: qk.agentStats,
    queryFn: api.getAgentStats,
    refetchInterval: 15000,
  });
}
