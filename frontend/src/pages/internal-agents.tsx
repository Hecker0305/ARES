import { useQuery } from "@tanstack/react-query";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Server, Monitor, Wifi, Activity } from "lucide-react";

export function InternalAgentsPage() {
  const { data: agents, isLoading } = useQuery({
    queryKey: ["agents"],
    queryFn: () => fetchAPI("/api/agents"),
    refetchInterval: 10000,
  });

  const { data: stats } = useQuery({
    queryKey: ["agentStats"],
    queryFn: () => fetchAPI("/api/agents/stats"),
    refetchInterval: 15000,
  });

  if (isLoading) return <Skeleton className="h-96" />;

  const statusColors: Record<string, string> = {
    online: "text-green-500",
    offline: "text-red-500",
    scanning: "text-yellow-500",
    error: "text-red-500",
  };

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Internal Agent Deployment</h1>
        <p className="text-muted-foreground">
          Lightweight scanners for internal network assessments and branch-office visibility
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card className="p-4">
          <Server className="h-5 w-5 text-blue-500" />
          {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
          <p className="mt-1 text-2xl font-bold">{(stats as any)?.total_agents ?? 0}</p>
          <p className="text-xs text-muted-foreground">Total Agents</p>
        </Card>
        <Card className="p-4">
          <Monitor className="h-5 w-5 text-green-500" />
          {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
          <p className="mt-1 text-2xl font-bold">{(stats as any)?.online_agents ?? 0}</p>
          <p className="text-xs text-muted-foreground">Online</p>
        </Card>
        <Card className="p-4">
          <Activity className="h-5 w-5 text-yellow-500" />
          {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
          <p className="mt-1 text-2xl font-bold">{(stats as any)?.scanning_agents ?? 0}</p>
          <p className="text-xs text-muted-foreground">Scanning</p>
        </Card>
        <Card className="p-4">
          <Wifi className="h-5 w-5 text-muted-foreground" />
          {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
          <p className="mt-1 text-2xl font-bold">{(stats as any)?.total_tasks ?? 0}</p>
          <p className="text-xs text-muted-foreground">Total Tasks</p>
        </Card>
      </div>

      <Card className="p-4">
        <h2 className="mb-3 font-medium">Deployed Agents</h2>
        {(!agents || agents.length === 0) && (
          <p className="text-sm text-muted-foreground">No agents deployed</p>
        )}
        <div className="space-y-2">
          {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
          {(agents as any[])?.map((agent: any) => (
            <div
              key={agent.id}
              className="flex items-center justify-between rounded bg-muted/50 p-3"
            >
              <div className="flex items-center gap-3">
                <span className={`h-2 w-2 rounded-full ${statusColors[agent.status] || ""}`} />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{agent.name}</span>
                    <Badge variant="outline" className="text-xs">
                      {agent.type}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {agent.hostname} &middot; {agent.ip_address} &middot; {agent.os}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {agent.network_segment && (
                  <Badge variant="secondary" className="text-xs">
                    {agent.network_segment}
                  </Badge>
                )}
                <Badge
                  variant={
                    agent.status === "online"
                      ? "default"
                      : agent.status === "scanning"
                        ? "secondary"
                        : "destructive"
                  }
                  className="text-xs"
                >
                  {agent.status}
                </Badge>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

async function fetchAPI(path: string) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
