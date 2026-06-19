import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { TrendingUp, AlertTriangle, Target, Clock } from "lucide-react";

export function ExecutiveRiskPage() {
  const { data: profile, isLoading: profileLoading } = useQuery({
    queryKey: ["riskProfile"],
    queryFn: api.getRiskProfile,
    refetchInterval: 30000,
  });

  const { data: assets } = useQuery({
    queryKey: ["riskAssets"],
    queryFn: api.listRiskAssets,
  });

  const { data: sla } = useQuery({
    queryKey: ["slaCompliance"],
    queryFn: api.getSLACompliance,
    refetchInterval: 60000,
  });

  const { data: trends } = useQuery({
    queryKey: ["riskTrends", 14],
    queryFn: () => api.getRiskTrends(14),
  });

  if (profileLoading) return <Skeleton className="h-96" />;

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Executive Risk Layer</h1>
        <p className="text-muted-foreground">
          Business impact scoring, risk trends, and SLA tracking
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card className="p-4">
          <div className="flex items-center gap-2 text-yellow-500">
            <AlertTriangle className="h-5 w-5" />
            <span className="text-sm text-muted-foreground">Avg Impact</span>
          </div>
          <p className="mt-1 text-2xl font-bold">
            {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
            {(profile as any)?.avg_impact_score?.toFixed(1) ?? "-"}
          </p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-red-500">
            <Target className="h-5 w-5" />
            <span className="text-sm text-muted-foreground">Max Impact</span>
          </div>
          <p className="mt-1 text-2xl font-bold">
            {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
            {(profile as any)?.max_impact_score?.toFixed(1) ?? "-"}
          </p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-blue-500">
            <TrendingUp className="h-5 w-5" />
            <span className="text-sm text-muted-foreground">Critical Assets</span>
          </div>
          <p className="mt-1 text-2xl font-bold">
            {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
            {(profile as any)?.critical_assets ?? 0}
          </p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-green-500">
            <Clock className="h-5 w-5" />
            <span className="text-sm text-muted-foreground">SLA Compliance</span>
          </div>
          <p className="mt-1 text-2xl font-bold">
            {sla?.compliance_rate?.toFixed(0) ?? "-"}%
          </p>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="p-4">
          <h2 className="mb-3 font-medium">Registered Assets</h2>
          {(!assets || assets.length === 0) && (
            <p className="text-sm text-muted-foreground">No assets registered</p>
          )}
          <div className="space-y-2">
            {assets?.map((a) => (
              <div
                key={a.id}
                className="flex items-center justify-between rounded bg-muted/50 p-2"
              >
                <div>
                  <span className="text-sm font-medium">{a.name}</span>
                  <span className="ml-2 text-xs text-muted-foreground">
                    {a.type}
                  </span>
                </div>
                <Badge
                  variant={
                    a.criticality === "critical"
                      ? "destructive"
                      : a.criticality === "high"
                        ? "default"
                        : "secondary"
                  }
                >
                  {a.criticality}
                </Badge>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-4">
          <h2 className="mb-3 font-medium">Risk Trends (Last 14 Days)</h2>
          {(!trends || trends.length === 0) && (
            <p className="text-sm text-muted-foreground">No trend data available</p>
          )}
          <div className="space-y-2">
            {trends?.slice(-7).map((t) => (
              <div key={t.date} className="flex items-center gap-3 text-sm">
                <span className="w-24 text-muted-foreground">
                  {new Date(t.date).toLocaleDateString()}
                </span>
                <div className="flex-1">
                  <div className="h-2 rounded-full bg-muted">
                    <div
                      className="h-2 rounded-full bg-yellow-500"
                      style={{ width: `${(t.avg_score / 10) * 100}%` }}
                    />
                  </div>
                </div>
                <span className="w-16 text-right font-medium">
                  {t.avg_score.toFixed(1)}
                </span>
                <span className="w-12 text-right text-muted-foreground">
                  {t.total_open}
                </span>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
