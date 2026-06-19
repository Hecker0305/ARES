import { Link } from "react-router-dom";
import { useInstances, usePauseInstance, useResumeInstance, useRestartInstance } from "@/api/queries";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/states";
import { Server, Play, Square, RotateCcw, ExternalLink, Cpu, HardDrive, MemoryStick } from "lucide-react";

export function InstancesPage() {
  const { data, isLoading } = useInstances();
  const pauseInstance = usePauseInstance();
  const resumeInstance = useResumeInstance();
  const restartInstance = useRestartInstance();

  const instances = data?.instances || [];
  const resource = data?.resource;

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <Skeleton className="h-8 w-48" />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-48 rounded-lg" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Instances</h1>

      {/* Resource Bar */}
      {resource && (
        <Card>
          <CardContent className="pt-6">
            <div className="grid gap-4 md:grid-cols-4">
              <div className="flex items-center gap-3">
                <Cpu className="h-5 w-5 text-muted-foreground" />
                <div>
                  <p className="text-xs text-muted-foreground">CPU Load</p>
                  <p className="text-lg font-bold">{resource.cpu}%</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <MemoryStick className="h-5 w-5 text-muted-foreground" />
                <div>
                  <p className="text-xs text-muted-foreground">Memory</p>
                  <p className="text-lg font-bold">{resource.memory}%</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <HardDrive className="h-5 w-5 text-muted-foreground" />
                <div>
                  <p className="text-xs text-muted-foreground">Disk Free</p>
                  <p className="text-lg font-bold">{resource.disk}%</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Server className="h-5 w-5 text-muted-foreground" />
                <div>
                  <p className="text-xs text-muted-foreground">Resource Level</p>
                  <p className="text-lg font-bold capitalize">{resource.level}</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Instance Cards */}
      {instances.length === 0 ? (
        <EmptyState title="No active instances" description="Start a scan to see running instances here." />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {instances.map((inst) => (
            <Card key={inst.id} className="card-hover">
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <div className="min-w-0">
                    <CardTitle className="text-base truncate">{inst.target}</CardTitle>
                    <p className="text-xs text-muted-foreground font-mono truncate">{inst.id}</p>
                  </div>
                  <ScanStatusPill status={inst.status} />
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-4 text-sm">
                  <div>
                    <p className="text-muted-foreground text-xs">Findings</p>
                    <p className="font-bold">{inst.findings_count}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground text-xs">Iterations</p>
                    <p className="font-bold">{inst.iterations}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground text-xs">Tokens</p>
                    <p className="font-bold">{inst.tokens?.toLocaleString()}</p>
                  </div>
                </div>

                {inst.phase && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">{inst.phase}</p>
                    <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                      <div
                        className="h-full rounded-full bg-primary transition-all"
                        style={{ width: `${((inst.progress || 0) * 100)}%` }}
                      />
                    </div>
                  </div>
                )}

                <div className="flex gap-2">
                  <Button variant="outline" size="sm" asChild className="flex-1">
                    <Link to={`/scans/${inst.id}`}>
                      <ExternalLink className="h-3.5 w-3.5" />
                      Details
                    </Link>
                  </Button>
                  {inst.status === "running" && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => pauseInstance.mutate(inst.id)}
                    >
                      <Square className="h-3.5 w-3.5" />
                    </Button>
                  )}
                  {inst.status === "paused" && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => resumeInstance.mutate(inst.id)}
                    >
                      <Play className="h-3.5 w-3.5" />
                    </Button>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => restartInstance.mutate(inst.id)}
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
