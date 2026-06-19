import { createBrowserRouter } from "react-router-dom";
import { AppShell } from "@/layout/app-shell";
import { OverviewPage } from "@/pages/overview";
import { ScansPage } from "@/pages/scans";
import { ScanDetailPage } from "@/pages/scan-detail";
import { NewScanPage } from "@/pages/new-scan";
import { FindingsPage } from "@/pages/findings";
import { FindingDetailPage } from "@/pages/finding-detail";
import { LivePage } from "@/pages/live";
import { ReportsPage } from "@/pages/reports";
import { InstancesPage } from "@/pages/instances";
import { SettingsPage } from "@/pages/settings";
import { SchedulesPage } from "@/pages/schedules";
import { CompliancePage } from "@/pages/compliance";
import { BountyPage } from "@/pages/bounty";
import { ProjectsPage } from "@/pages/projects";
import { CloudScannerPage } from "@/pages/cloud-scanner";
import { RedTeamPage } from "@/pages/red-team";
import { AttackGraphPage } from "@/pages/attack-graph";
import { NotFoundPage } from "@/pages/not-found";
import { IntegrationsPage } from "@/pages/integrations";
import { EmailTriagePage } from "@/pages/email-triage";
import { ExposureMonitoringPage } from "@/pages/exposure-monitoring";
import { ApprovalsPage } from "@/pages/approvals";
import { ExecutiveRiskPage } from "@/pages/executive-risk";
import { EnterpriseIdentityPage } from "@/pages/enterprise-identity";
import { EvidenceIntegrityPage } from "@/pages/evidence-integrity";
import { KnowledgeGraphPage } from "@/pages/knowledge-graph";
import { ValidationLoopsPage } from "@/pages/validation-loops";
import { PurpleTeamPage } from "@/pages/purple-team";
import { CopilotPage } from "@/pages/copilot";
import { ExternalASMPage } from "@/pages/external-asm";
import { ComplianceFrameworksPage } from "@/pages/compliance-frameworks";
import { CollaborationPage } from "@/pages/collaboration";
import { InternalAgentsPage } from "@/pages/internal-agents";
import { MalwarePage } from "@/pages/malware";
import { RansomwarePage } from "@/pages/ransomware";
import { PacketInjectionPage } from "@/pages/packet-injection";
import { C2AdvPage } from "@/pages/c2-advanced";
import { NetworkSimPage } from "@/pages/network-simulation";

export const router = createBrowserRouter([
  {
    element: <AppShell />,
    children: [
      { path: "/", element: <OverviewPage /> },
      { path: "/scans", element: <ScansPage /> },
      { path: "/scans/new", element: <NewScanPage /> },
      { path: "/scans/:id", element: <ScanDetailPage /> },
      { path: "/findings", element: <FindingsPage /> },
      { path: "/findings/:id", element: <FindingDetailPage /> },
      { path: "/live", element: <LivePage /> },
      { path: "/reports", element: <ReportsPage /> },
      { path: "/instances", element: <InstancesPage /> },
      { path: "/settings", element: <SettingsPage /> },
      { path: "/schedules", element: <SchedulesPage /> },
      { path: "/compliance", element: <CompliancePage /> },
      { path: "/bounty", element: <BountyPage /> },
      { path: "/projects", element: <ProjectsPage /> },
      { path: "/cloud-scanner", element: <CloudScannerPage /> },
      { path: "/red-team", element: <RedTeamPage /> },
      { path: "/attack-graph", element: <AttackGraphPage /> },
      { path: "/integrations", element: <IntegrationsPage /> },
      { path: "/email", element: <EmailTriagePage /> },
      { path: "/exposure-monitoring", element: <ExposureMonitoringPage /> },
      { path: "/approvals", element: <ApprovalsPage /> },
      { path: "/executive-risk", element: <ExecutiveRiskPage /> },
      { path: "/enterprise-identity", element: <EnterpriseIdentityPage /> },
      { path: "/evidence-integrity", element: <EvidenceIntegrityPage /> },
      { path: "/knowledge-graph", element: <KnowledgeGraphPage /> },
      { path: "/validation-loops", element: <ValidationLoopsPage /> },
      { path: "/purple-team", element: <PurpleTeamPage /> },
      { path: "/copilot", element: <CopilotPage /> },
      { path: "/external-asm", element: <ExternalASMPage /> },
      { path: "/internal-agents", element: <InternalAgentsPage /> },
      { path: "/compliance-frameworks", element: <ComplianceFrameworksPage /> },
      { path: "/collaboration", element: <CollaborationPage /> },
      { path: "/malware", element: <MalwarePage /> },
      { path: "/ransomware", element: <RansomwarePage /> },
      { path: "/packet-injection", element: <PacketInjectionPage /> },
      { path: "/c2-advanced", element: <C2AdvPage /> },
      { path: "/network-simulation", element: <NetworkSimPage /> },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
]);
