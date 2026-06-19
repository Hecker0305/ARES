import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Shield, CheckCircle } from "lucide-react";
import { useState } from "react";

export function ComplianceFrameworksPage() {
  const { data: frameworks, isLoading } = useQuery({
    queryKey: ["complianceFrameworks"],
    queryFn: api.listComplianceFrameworks,
  });

  const [selected, setSelected] = useState<string | null>(null);

  const { data: detail } = useQuery({
    queryKey: ["complianceFramework", selected],
    queryFn: () => api.getComplianceFramework(selected!),
    enabled: !!selected,
  });

  if (isLoading) return <Skeleton className="h-96" />;

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Compliance Framework Builder</h1>
        <p className="text-muted-foreground">
          Create and manage custom compliance frameworks with control mappings
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        {frameworks?.map((fw) => (
          <Card
            key={fw.id}
            className={`cursor-pointer p-4 transition-colors hover:bg-muted/50 ${
              selected === fw.id ? "ring-2 ring-primary" : ""
            }`}
            onClick={() => setSelected(fw.id)}
          >
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" />
              <h3 className="font-medium">{fw.name}</h3>
              <Badge variant="outline" className="ml-auto text-xs">
                v{fw.version}
              </Badge>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              {fw.description}
            </p>
            <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
              <CheckCircle className="h-3 w-3" />
              {fw.controls?.length ?? 0} controls
            </div>
          </Card>
        ))}
      </div>

      {selected && detail && (
        <Card className="p-4">
          <h2 className="mb-3 font-medium">
            {detail.name} - Controls
          </h2>
          <div className="space-y-2">
            {detail.controls?.map((control) => (
              <div
                key={control.id}
                className="rounded bg-muted/50 p-3"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs font-mono">
                      {control.control_id}
                    </Badge>
                    <span className="text-sm font-medium">{control.title}</span>
                  </div>
                  <Badge
                    variant={
                      control.severity === "critical"
                        ? "destructive"
                        : control.severity === "high"
                          ? "default"
                          : "secondary"
                    }
                    className="text-xs"
                  >
                    {control.severity}
                  </Badge>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  {control.category}
                </p>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
