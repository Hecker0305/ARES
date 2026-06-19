import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertTriangle, Globe, Lock, Shield, Cloud } from "lucide-react";
import { useMemo } from "react";

const typeIcons: Record<string, typeof AlertTriangle> = {
  credential_leak: Lock,
  github_secret: Shield,
  certificate: Globe,
  domain_takeover: AlertTriangle,
  cloud_exposure: Cloud,
};

const typeLabels: Record<string, string> = {
  credential_leak: "Credential Leaks",
  github_secret: "GitHub Secrets",
  certificate: "Certificate Issues",
  domain_takeover: "Domain Takeover",
  cloud_exposure: "Cloud Exposure",
};

export function ExposureMonitoringPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["exposure"],
    queryFn: api.listExposureFindings,
    refetchInterval: 60000,
  });

  const grouped = useMemo(() => {
    if (!data?.findings) return {};
    const groups: Record<string, typeof data.findings> = {};
    for (const f of data.findings) {
      if (!groups[f.type]) groups[f.type] = [];
      groups[f.type].push(f);
    }
    return groups;
  }, [data]);

  if (isLoading) return <Skeleton className="h-96" />;
  if (error) return <div className="text-red-500">Failed to load exposure data</div>;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Exposure Monitoring</h1>
          <p className="text-muted-foreground">
            Continuous monitoring of external exposure signals
          </p>
        </div>
        <Badge variant="outline" className="text-sm">
          {data?.total ?? 0} total findings
        </Badge>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {Object.entries(grouped).map(([type, findings]) => {
          const Icon = typeIcons[type] || AlertTriangle;
          return (
            <Card key={type} className="p-4">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2">
                  <Icon className="h-5 w-5 text-yellow-500" />
                  <h3 className="font-medium">{typeLabels[type] || type}</h3>
                </div>
                <Badge>{findings.length}</Badge>
              </div>
              <div className="mt-3 space-y-2">
                {findings.slice(0, 5).map((f) => (
                  <div
                    key={f.id}
                    className="rounded bg-muted/50 p-2 text-sm"
                  >
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={
                          f.severity === "critical"
                            ? "destructive"
                            : f.severity === "high"
                              ? "default"
                              : "secondary"
                        }
                        className="text-xs"
                      >
                        {f.severity}
                      </Badge>
                      <span className="truncate font-medium">{f.title}</span>
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {f.target} &middot; {new Date(f.discovered).toLocaleDateString()}
                    </p>
                  </div>
                ))}
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
