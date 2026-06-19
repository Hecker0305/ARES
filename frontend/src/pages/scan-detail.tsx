import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { useScan, useScanFindings, useStopScan } from "@/api/queries";
import { useWSStore } from "@/store/ws";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { SeverityBadge } from "@/components/severity-badge";
import { PhaseProgress } from "@/components/phase-progress";
import { ScanProgressBar } from "@/components/scan-progress-bar";
import { LiveFeed } from "@/components/live-feed";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState, ErrorState } from "@/components/states";
import { ArrowLeft, Play, Square, RotateCcw, ExternalLink, Globe } from "lucide-react";
import { timeAgo, severityColor, cn, formatDurationFromDates, severityBarClass } from "@/lib/utils";

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: scan, isLoading, error, refetch } = useScan(id);
  const { data: findings } = useScanFindings(id);
  const stopScan = useStopScan();
  const subscribe = useWSStore((s) => s.subscribe);
  const [activeTab, setActiveTab] = useState("findings");

  useEffect(() => {
    if (id) subscribe(id);
  }, [id, subscribe]);

  if (!id) return null;

  subscribe(id);

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-2 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="p-6">
        <ErrorState
          title="Scan not found"
          description="Could not load scan data."
          action={{ label: "Retry", onClick: () => refetch() }}
        />
      </div>
    );
  }

  const phases = scan.phases?.map((name, i) => ({ id: i + 1, name })) || [];
  const currentPhaseNum = scan.phase ? phases.findIndex((p) => p.name === scan.phase) + 1 : 0;

  const modeLabel =
    scan.scan_mode === "single"
      ? "Single Target"
      : scan.scan_mode === "dast"
        ? "DAST"
        : scan.scan_mode === "wildcard"
          ? "Wildcard"
          : scan.scan_mode || "N/A";

  const modeBadgeColor =
    scan.scan_mode === "wildcard"
      ? "bg-purple-500/10 text-purple-500 border-purple-500/20"
      : scan.scan_mode === "dast"
        ? "bg-blue-500/10 text-blue-500 border-blue-500/20"
        : scan.scan_mode === "single"
          ? "bg-emerald-500/10 text-emerald-500 border-emerald-500/20"
          : "";

  const hasSubScans = scan.sub_scans && scan.sub_scans.length > 0;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="icon" asChild>
              <Link to="/scans">
                <ArrowLeft className="h-4 w-4" />
              </Link>
            </Button>
            <div>
              <h1 className="text-2xl font-bold">{scan.target}</h1>
              <p className="text-sm text-muted-foreground font-mono">{scan.id}</p>
            </div>
            <Badge variant="outline" className={cn("ml-2 px-3 py-1 text-xs font-semibold", modeBadgeColor)}>
              {modeLabel}
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            Started {timeAgo(scan.start_time)} &middot; Duration:{" "}
            {formatDurationFromDates(scan.start_time, scan.end_time)}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <ScanStatusPill status={scan.status} />
          {scan.status === "running" && (
            <>
              <Button variant="outline" size="sm" onClick={() => stopScan.mutate(id)}>
                <Square className="h-3.5 w-3.5" />
                Stop
              </Button>
              <Button variant="outline" size="sm">
                <RotateCcw className="h-3.5 w-3.5" />
                Restart
              </Button>
            </>
          )}
          {scan.status === "paused" && (
            <Button variant="outline" size="sm">
              <Play className="h-3.5 w-3.5" />
              Resume
            </Button>
          )}
        </div>
      </div>

      {/* Progress Bar */}
      <ScanProgressBar
        progress={scan.progress}
        phase={scan.phase}
        status={scan.status}
        startTime={scan.start_time}
        phases={scan.phases}
      />

      {/* Phase Progress */}
      {phases.length > 0 && (
        <div>
          <PhaseProgress
            phases={phases}
            currentPhase={currentPhaseNum}
            completedPhases={Array.from({ length: currentPhaseNum - 1 }, (_, i) => i + 1)}
          />
          <div className="flex justify-between mt-1 text-xs text-muted-foreground">
            <span>Phase {currentPhaseNum} of {phases.length}</span>
            <span>{scan.phase}</span>
          </div>
        </div>
      )}

      {/* Risk Overview */}
      {findings && findings.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Risk Overview</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-4">
              {(["critical", "high", "medium", "low"] as const).map((sev) => {
                const count = findings.filter((f) => f.severity === sev).length;
                const maxCount = Math.max(
                  ...(["critical", "high", "medium", "low"] as const).map(
                    (s) => findings.filter((f) => f.severity === s).length
                  ),
                  1
                );
                return (
                  <div key={sev} className="flex-1">
                    <div className={cn("text-2xl font-bold", severityColor(sev))}>
                      {count}
                    </div>
                    <div className="text-xs text-muted-foreground capitalize">{sev}</div>
                    <div className="mt-1 h-1.5 w-full rounded-full bg-muted">
                      <div
                        className={cn("h-full rounded-full", severityBarClass(sev))}
                        style={{ width: `${(count / maxCount) * 100}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Wildcard Coverage */}
      {(scan.scan_mode === "wildcard" || hasSubScans) && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Globe className="h-4 w-4" />
              Wildcard Coverage
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span>Subdomain Discovery</span>
                <span className="text-muted-foreground">
                  {scan.sub_scan_completed || 0} / {scan.sub_scan_total || 0} completed
                </span>
              </div>
              <div className="h-2 w-full rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-primary transition-all"
                  style={{
                    width: `${((scan.sub_scan_completed || 0) / (scan.sub_scan_total || 1)) * 100}%`,
                  }}
                />
              </div>
              <div className="flex gap-4 text-xs text-muted-foreground">
                <span>{scan.sub_scan_completed || 0} completed</span>
                <span>{scan.sub_scan_running || 0} running</span>
                <span>{scan.sub_scan_remaining || 0} remaining</span>
                <span>{scan.sub_scan_total || 0} total</span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="events">Events</TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
          {hasSubScans && <TabsTrigger value="subdomains">Subdomains</TabsTrigger>}
        </TabsList>

        <TabsContent value="findings" className="mt-4">
          {!findings || findings.length === 0 ? (
            <EmptyState title="No findings yet" description="Findings will appear as the scan progresses." />
          ) : (
            <div className="space-y-2">
              {findings
                .sort((a, b) => {
                  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                  return (order[a.severity] || 5) - (order[b.severity] || 5);
                })
                .map((f) => (
                  <Link
                    key={f.id}
                    to={`/findings/${f.id}`}
                    className="flex items-center justify-between rounded-lg border p-4 hover:bg-muted/50 transition-colors"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="font-medium truncate">{f.title}</p>
                      <p className="text-xs text-muted-foreground font-mono truncate">{f.endpoint}</p>
                    </div>
                    <div className="flex items-center gap-3 ml-4">
                      <SeverityBadge severity={f.severity} />
                      <ExternalLink className="h-4 w-4 text-muted-foreground" />
                    </div>
                  </Link>
                ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="events" className="mt-4">
          <Card>
            <CardContent className="p-0">
              <div className="h-96">
                <LiveFeed />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="config" className="mt-4">
          <Card>
            <CardContent className="pt-6">
              <div className="grid gap-4 md:grid-cols-2">
                <InfoRow label="Scan Mode" value={modeLabel} />
                <InfoRow label="Preset" value={scan.preset || "Custom"} />
                <InfoRow label="Workers" value={scan.workers?.toString() || "4"} />
                <InfoRow label="Phases" value={scan.phases?.length?.toString() || "0"} />
                <InfoRow label="Target" value={scan.target} />
                <InfoRow label="Status" value={scan.status} />
                <InfoRow
                  label="Severity Filter"
                  value={
                    findings && findings.length > 0
                      ? [...new Set(findings.map((f) => f.severity))].join(", ")
                      : "All"
                  }
                />
              </div>
              {scan.phases && scan.phases.length > 0 && (
                <>
                  <h3 className="mt-6 mb-2 text-sm font-medium">Selected Phases</h3>
                  <div className="flex flex-wrap gap-2">
                    {scan.phases.map((p) => (
                      <Badge key={p} variant="outline">
                        {p}
                      </Badge>
                    ))}
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {hasSubScans && (
          <TabsContent value="subdomains" className="mt-4">
            <Card>
              <CardContent className="pt-6">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b text-left text-xs text-muted-foreground uppercase">
                        <th className="pb-2 pr-4 font-medium">Target</th>
                        <th className="pb-2 pr-4 font-medium">Status</th>
                        <th className="pb-2 pr-4 font-medium">Findings</th>
                        <th className="pb-2 pr-4 font-medium">Tokens</th>
                        <th className="pb-2 font-medium">Started</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scan.sub_scans!.map((sub) => (
                        <tr key={sub.id} className="border-b last:border-0">
                          <td className="py-2 pr-4 font-mono text-xs">{sub.target}</td>
                          <td className="py-2 pr-4">
                            <ScanStatusPill status={sub.status} />
                          </td>
                          <td className="py-2 pr-4">{sub.vuln_count}</td>
                          <td className="py-2 pr-4">{sub.total_tokens}</td>
                          <td className="py-2 text-muted-foreground">
                            {sub.started_at ? timeAgo(sub.started_at) : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground uppercase tracking-wide">{label}</p>
      <p className="text-sm font-mono mt-0.5">{value}</p>
    </div>
  );
}
