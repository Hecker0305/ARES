import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { GitBranch, Share2, Route, AlertTriangle } from "lucide-react";

export function KnowledgeGraphPage() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ["kgStats"],
    queryFn: api.getKGStats,
    refetchInterval: 30000,
  });

  const { data: entities } = useQuery({
    queryKey: ["kgEntities"],
    queryFn: api.getKGEntities,
  });

  if (isLoading) return <Skeleton className="h-96" />;

  const entityTypeColors: Record<string, string> = {
    asset: "text-blue-500",
    vulnerability: "text-red-500",
    credential: "text-yellow-500",
    service: "text-green-500",
    identity: "text-purple-500",
    secret: "text-orange-500",
  };

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Security Knowledge Graph</h1>
        <p className="text-muted-foreground">
          Connected graph of assets, vulnerabilities, credentials, services, and identities
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card className="p-4">
          <div className="flex items-center gap-2">
            <GitBranch className="h-5 w-5 text-blue-500" />
            <span className="text-sm text-muted-foreground">Entities</span>
          </div>
          <p className="mt-1 text-2xl font-bold">
            {stats?.total_entities ?? 0}
          </p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2">
            <Share2 className="h-5 w-5 text-green-500" />
            <span className="text-sm text-muted-foreground">Relationships</span>
          </div>
          <p className="mt-1 text-2xl font-bold">
            {stats?.total_relationships ?? 0}
          </p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2">
            <Route className="h-5 w-5 text-yellow-500" />
            <span className="text-sm text-muted-foreground">Avg Risk</span>
          </div>
          <p className="mt-1 text-2xl font-bold">
            {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
            {(stats as any)?.average_risk_score?.toFixed(2) ?? "-"}
          </p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-red-500" />
            <span className="text-sm text-muted-foreground">Attack Paths</span>
          </div>
          <p className="mt-1 text-2xl font-bold">-</p>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="p-4">
          <h2 className="mb-3 font-medium">Entities by Type</h2>
          {stats?.entities_by_type && (
            <div className="space-y-2">
              {Object.entries(stats.entities_by_type).map(([type, count]) => (
                <div
                  key={type}
                  className="flex items-center justify-between rounded bg-muted/50 p-2"
                >
                  <span className={`text-sm font-medium capitalize ${entityTypeColors[type] || ""}`}>
                    {type}
                  </span>
                  <Badge variant="outline">{count as number}</Badge>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card className="p-4">
          <h2 className="mb-3 font-medium">Recent Entities</h2>
          {(!entities || entities.length === 0) && (
            <p className="text-sm text-muted-foreground">No entities yet</p>
          )}
          <div className="space-y-2">
            {entities?.slice(0, 10).map((entity) => (
              <div
                key={entity.id}
                className="flex items-center justify-between rounded bg-muted/50 p-2 text-sm"
              >
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${entityTypeColors[entity.type] || ""}`} />
                  <span className="font-medium">{entity.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-xs">
                    {entity.type}
                  </Badge>
                  {(entity.risk_score ?? 0) > 0 && (
                    <span className="text-xs text-muted-foreground">
                      {entity.risk_score?.toFixed(1)}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
