import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  useMetrics,
  useActiveScans,
  useCriticalFindings,
  useSeverityBreakdown,
  useScanQueue,
  useScansList,
  useInstances,
  useQueueStatus,
} from "@/api/queries";
import { MetricCard } from "@/components/metric-card";
import { SeverityBadge } from "@/components/severity-badge";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { LiveFeed } from "@/components/live-feed";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/states";
import {
  Activity,
  AlertOctagon,
  ArrowRight,
  BarChart3,
  Cpu,
  HardDrive,
  Layers,
  Plus,
  Radio,
  ShieldAlert,
  Target,
  Radar,
} from "lucide-react";
import { timeAgo, severityDot, severityColor, cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_BASE || "";

function useStatusQuery() {
  return useQuery({
    queryKey: ["status"],
    queryFn: () =>
      fetch(`${API_BASE}/api/status`).then((r) => r.json()) as Promise<{ current_phase: number }>,
    refetchInterval: 10000,
  });
}

function Row({ icon, label, value }: { icon: React.ReactNode; label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-1.5">
      <div className="flex items-center gap-2 text-sm">
        {icon}
        <span className="text-muted-foreground">{label}</span>
      </div>
      <div className="font-medium text-sm">{value}</div>
    </div>
  );
}

export function OverviewPage() {
  const { data: metrics, isLoading: metricsLoading } = useMetrics();
  const { data: activeScans, isLoading: activeLoading } = useActiveScans();
  const { data: criticalFindings, isLoading: criticalLoading } = useCriticalFindings();
  const { data: severity, isLoading: severityLoading } = useSeverityBreakdown();
  const { data: queue, isLoading: queueLoading } = useScanQueue();
  const { data: scans, isLoading: scansLoading } = useScansList();
  const { data: instancesData, isLoading: instancesLoading } = useInstances();
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { data: queueStatus } = useQueueStatus();
  const { data: statusData } = useStatusQuery();

  const resource = instancesData?.resource;
  const currentPhase = statusData?.current_phase ?? 0;

  const sevMap = (severity ?? {}) as unknown as Record<string, number>;
  const totalSeverity = (sevMap.critical || 0) + (sevMap.high || 0) + (sevMap.medium || 0) + (sevMap.low || 0) + (sevMap.info || 0);
  const allSeverities = ["critical", "high", "medium", "low", "info"] as const;

  const completedCount = Array.isArray(scans) ? scans.filter((s) => s.status === "finished" || s.status === "completed").length : 0;

  if (metricsLoading || activeLoading || severityLoading) {
    return (
      <div className="p-6 space-y-6">
        <Skeleton className="h-8 w-72" />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-28 rounded-lg" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Overview</h1>
          <p className="text-sm text-muted-foreground">Command center for scans, findings, and live activity.</p>
        </div>
        <Button asChild>
          <Link to="/scans/new">
            <Plus className="mr-1.5 h-4 w-4" /> New Scan
          </Link>
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Active"
          value={activeScans?.length || 0}
          hint={activeScans?.[0] ? activeScans[0].target : undefined}
          icon={Radar}
          accent={activeScans?.length ? "warning" : "default"}
          link="/scans"
        />
        <MetricCard
          label="Findings Total"
          value={totalSeverity}
          icon={ShieldAlert}
          accent="default"
          link="/findings"
        />
        <MetricCard
          label="Crit / High"
          value={(sevMap.critical || 0) + (sevMap.high || 0)}
          hint={`${sevMap.critical || 0} critical, ${sevMap.high || 0} high`}
          icon={AlertOctagon}
          accent={(sevMap.critical || 0) > 0 ? "critical" : "default"}
          link="/findings"
        />
        <MetricCard
          label="Targets"
          value={metrics?.targetsCovered || 0}
          hint={metrics?.targetProjects ? `${metrics.targetProjects} hosts` : undefined}
          icon={Target}
          accent="success"
          link="/projects"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base">Recent Scans</CardTitle>
                <Button variant="ghost" size="sm" asChild>
                  <Link to="/scans">View all <ArrowRight className="ml-1 h-3 w-3" /></Link>
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {scansLoading ? (
                <div className="space-y-3">
                  {[1, 2, 3].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
                </div>
              ) : !Array.isArray(scans) || scans.length === 0 ? (
                <EmptyState
                  title="No scans yet"
                  description="Launch your first scan to see results here."
                  action={{ label: "New Scan", onClick: () => { window.location.href = "/scans/new"; } }}
                />
              ) : (
                <div className="space-y-1">
                  {scans.slice(0, 5).map((scan) => (
                    <Link
                      key={scan.id}
                      to={`/scans/${scan.id}`}
                      className="flex items-center justify-between rounded-md p-2 hover:bg-muted/50 transition-colors"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <Radar className="h-4 w-4 text-muted-foreground shrink-0" />
                        <div className="min-w-0">
                          <p className="text-sm font-medium truncate">{scan.target}</p>
                          <p className="text-xs text-muted-foreground">
                            {scan.start_time ? timeAgo(scan.start_time) : ""}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        <ScanStatusPill status={scan.status} />
                        {scan.findings_count > 0 && (
                          <Badge variant="outline" className="text-xs">{scan.findings_count} findings</Badge>
                        )}
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base flex items-center gap-2">
                  <Activity className="h-4 w-4" /> Live Activity
                </CardTitle>
                <Button variant="ghost" size="sm" asChild>
                  <Link to="/live">Open feed</Link>
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <div className="h-64 border-t"><LiveFeed /></div>
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <BarChart3 className="h-4 w-4" /> Finding Mix
              </CardTitle>
            </CardHeader>
            <CardContent>
              {severityLoading ? (
                <Skeleton className="h-32 w-full" />
              ) : totalSeverity === 0 ? (
                <EmptyState title="No findings" description="No findings recorded yet." />
              ) : (
                <div className="space-y-3">
                  <div className="flex items-baseline justify-between">
                    <span className="text-sm text-muted-foreground">Total findings</span>
                    <span className="text-lg font-bold">{totalSeverity}</span>
                  </div>
                  {allSeverities.map((sev) => {
                    const count = sevMap[sev] || 0;
                    const pct = totalSeverity > 0 ? (count / totalSeverity) * 100 : 0;
                    return (
                      <div key={sev} className="space-y-1">
                        <div className="flex items-center justify-between text-sm">
                          <span className="flex items-center gap-2">
                            <span className={cn("h-2 w-2 rounded-full", severityDot(sev))} />
                            <span className={cn("capitalize", severityColor(sev))}>{sev}</span>
                          </span>
                          <span className="text-muted-foreground">{count}</span>
                        </div>
                        <div className="h-2 rounded-full bg-muted overflow-hidden">
                          <div
                            className={cn("h-full rounded-full transition-all", severityDot(sev))}
                            style={{ width: `${Math.max(pct, count > 0 ? 2 : 0)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Activity className="h-4 w-4" /> System Health
              </CardTitle>
            </CardHeader>
            <CardContent>
              {instancesLoading ? (
                <div className="space-y-3">{[1, 2, 3].map((i) => <Skeleton key={i} className="h-5 w-full" />)}</div>
              ) : !resource ? (
                <EmptyState title="No data" description="System resource data unavailable." />
              ) : (
                <div className="space-y-1">
                  <Row icon={<Cpu className="h-4 w-4 text-muted-foreground" />} label="CPU Load" value={`${resource.cpu.toFixed(1)}%`} />
                  <Row icon={<HardDrive className="h-4 w-4 text-muted-foreground" />} label="RAM Available" value={`${resource.memory.toFixed(1)}%`} />
                  <Row icon={<HardDrive className="h-4 w-4 text-muted-foreground" />} label="Disk Free" value={`${resource.disk.toFixed(1)}%`} />
                  <Row
                    icon={<Layers className="h-4 w-4 text-muted-foreground" />}
                    label="Resource Level"
                    value={
                      <span className={cn({
                        "text-severity-critical": resource.level === "critical",
                        "text-warning": resource.level === "warning",
                        "text-success": resource.level === "ok",
                      })}>
                        {resource.level.charAt(0).toUpperCase() + resource.level.slice(1)}
                      </span>
                    }
                  />
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Radio className="h-4 w-4" /> Operations
              </CardTitle>
            </CardHeader>
            <CardContent>
              {queueLoading ? (
                <div className="space-y-3">{[1, 2, 3].map((i) => <Skeleton key={i} className="h-5 w-full" />)}</div>
              ) : (
                <div className="space-y-1">
                  <Row icon={<Radar className="h-4 w-4 text-muted-foreground" />} label="Running" value={queue?.running ?? 0} />
                  <Row icon={<Layers className="h-4 w-4 text-muted-foreground" />} label="Queue" value={queue?.queued ?? 0} />
                  <Row icon={<Radio className="h-4 w-4 text-muted-foreground" />} label="Current Phase" value={currentPhase} />
                  <Row icon={<BarChart3 className="h-4 w-4 text-muted-foreground" />} label="Completed" value={completedCount} />
                  {scans && scans.length > 0 && (
                    <Row
                      icon={<ArrowRight className="h-4 w-4 text-muted-foreground" />}
                      label="Latest Scan"
                      value={
                        <Link to={`/scans/${scans[0].id}`} className="text-primary hover:underline truncate max-w-[140px] inline-block">
                          {scans[0].target}
                        </Link>
                      }
                    />
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base">Critical Findings</CardTitle>
                <Button variant="ghost" size="sm" asChild>
                  <Link to="/findings">View all <ArrowRight className="ml-1 h-3 w-3" /></Link>
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {criticalLoading ? (
                <div className="space-y-3">{[1, 2, 3].map((i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
              ) : !criticalFindings || criticalFindings.length === 0 ? (
                <EmptyState title="No critical findings" description="No critical severity findings detected." />
              ) : (
                <div className="space-y-1">
                  {criticalFindings.map((f) => (
                    <Link
                      key={f.id}
                      to={`/findings/${f.id}`}
                      className="block rounded-md p-2 hover:bg-muted/50 transition-colors"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <p className="text-sm font-medium truncate">{f.title}</p>
                          <p className="text-xs text-muted-foreground truncate">{f.endpoint}</p>
                        </div>
                        <SeverityBadge severity={f.severity} />
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
