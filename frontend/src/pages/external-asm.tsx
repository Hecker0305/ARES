import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Globe, Server } from "lucide-react";

export function ExternalASMPage() {
  const { data: assets, isLoading } = useQuery({
    queryKey: ["asmAssets"],
    queryFn: api.listASMAssets,
    refetchInterval: 60000,
  });

  const { data: stats } = useQuery({
    queryKey: ["asmStats"],
    queryFn: api.getASMStats,
    refetchInterval: 60000,
  });

  if (isLoading) return <Skeleton className="h-96" />;

  const exposureColors: Record<string, string> = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-yellow-500",
    low: "text-blue-500",
  };

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">External Attack Surface Management</h1>
        <p className="text-muted-foreground">
          Continuous discovery, asset inventory, and internet exposure tracking
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card className="p-4">
          <Globe className="h-5 w-5 text-blue-500" />
          <p className="mt-1 text-2xl font-bold">{stats?.total_assets ?? 0}</p>
          <p className="text-xs text-muted-foreground">Total Assets</p>
        </Card>
        {stats?.by_type &&
          Object.entries(stats.by_type).map(([type, count]) => (
            <Card key={type} className="p-4">
              <Server className="h-5 w-5 text-muted-foreground" />
              <p className="mt-1 text-2xl font-bold">{count as number}</p>
              <p className="text-xs capitalize text-muted-foreground">{type}</p>
            </Card>
          ))}
      </div>

      <Card className="p-4">
        <h2 className="mb-3 font-medium">Discovered Assets</h2>
        {(!assets || assets.length === 0) && (
          <p className="text-sm text-muted-foreground">No assets discovered</p>
        )}
        <div className="space-y-2">
          {assets?.map((asset) => (
            <div
              key={asset.id}
              className="flex items-center justify-between rounded bg-muted/50 p-3"
            >
              <div className="flex items-center gap-3">
                <span className={`h-2 w-2 rounded-full ${exposureColors[asset.exposure] || ""}`} />
                <div>
                  <span className="text-sm font-medium">{asset.name}</span>
                  <span className="ml-2 text-xs text-muted-foreground">
                    {asset.type}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {asset.cloud_provider && (
                  <Badge variant="outline" className="text-xs">
                    {asset.cloud_provider}
                  </Badge>
                )}
                <Badge
                  variant={
                    asset.exposure === "critical"
                      ? "destructive"
                      : asset.exposure === "high"
                        ? "default"
                        : "secondary"
                  }
                  className="text-xs"
                >
                  {asset.exposure}
                </Badge>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
