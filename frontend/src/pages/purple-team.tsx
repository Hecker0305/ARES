import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Swords, Play, ShieldCheck, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";

export function PurpleTeamPage() {
  const qc = useQueryClient();
  const { data: sims, isLoading } = useQuery({
    queryKey: ["purpleTeamSims"],
    queryFn: api.listPurpleTeamSimulations,
    refetchInterval: 10000,
  });

  const { data: coverage } = useQuery({
    queryKey: ["ptCoverage"],
    queryFn: api.getPurpleTeamCoverage,
    refetchInterval: 30000,
  });

  const [name, setName] = useState("");
  const [target, setTarget] = useState("");

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const createMut = useMutation({
    mutationFn: () =>
      api.createPurpleTeamSimulation({
        name,
        target,
        type: "attack_simulation",
        status: "pending",
        created_at: new Date().toISOString(),
      /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
      } as any),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["purpleTeamSims"] });
      toast.success("Simulation created");
      setName("");
      setTarget("");
    },
  });

  if (isLoading) return <Skeleton className="h-96" />;

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Purple Team Mode</h1>
        <p className="text-muted-foreground">
          Attack simulation, detection validation, and SIEM verification
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card className="p-4">
          <div className="flex items-center gap-2 text-blue-500">
            <Swords className="h-5 w-5" />
          </div>
          <p className="mt-1 text-2xl font-bold">
            {coverage?.total_simulations ?? 0}
          </p>
          <p className="text-xs text-muted-foreground">Simulations</p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-green-500">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <p className="mt-1 text-2xl font-bold">
            {coverage?.detection_coverage
              ? Object.values(coverage.detection_coverage).reduce(
                  (a: number, b: number) => a + b,
                  0,
                ) / Object.keys(coverage.detection_coverage).length
              : 0}
            %
          </p>
          <p className="text-xs text-muted-foreground">Avg Coverage</p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-red-500">
            <AlertTriangle className="h-5 w-5" />
          </div>
          <p className="mt-1 text-2xl font-bold">
            {coverage?.total_by_source
              ? Object.values(coverage.total_by_source).reduce(
                  (a: number, b: number) => a + b,
                  0,
                )
              : 0}
          </p>
          <p className="text-xs text-muted-foreground">Tests Run</p>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="p-4">
          <h2 className="mb-3 font-medium">Simulations</h2>
          {(!sims || sims.length === 0) && (
            <p className="text-sm text-muted-foreground">
              No simulations yet. Create one below.
            </p>
          )}
          <div className="space-y-2">
            {sims?.map((sim) => (
              <div
                key={sim.id}
                className="rounded bg-muted/50 p-3"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{sim.name}</span>
                    <Badge
                      variant={
                        sim.status === "completed"
                          ? "default"
                          : sim.status === "running"
                            ? "secondary"
                            : "outline"
                      }
                      className="text-xs"
                    >
                      {sim.status}
                    </Badge>
                  </div>
                  {sim.status === "pending" && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={async () => {
                        await api.startPurpleTeamSimulation(sim.id);
                        qc.invalidateQueries({ queryKey: ["purpleTeamSims"] });
                        toast.success("Simulation started");
                      }}
                    >
                      <Play className="mr-1 h-3 w-3" /> Start
                    </Button>
                  )}
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  {sim.target} &middot; {sim.type}
                </p>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-4">
          <h2 className="mb-3 font-medium">Detection Coverage by Source</h2>
          {coverage?.detection_coverage && (
            <div className="space-y-2">
              {Object.entries(coverage.detection_coverage).map(
                ([source, rate]) => (
                  <div key={source} className="flex items-center gap-3 text-sm">
                    <span className="w-24">{source}</span>
                    <div className="flex-1">
                      <div className="h-2 rounded-full bg-muted">
                        <div
                          className={`h-2 rounded-full ${
                            rate > 80
                              ? "bg-green-500"
                              : rate > 50
                                ? "bg-yellow-500"
                                : "bg-red-500"
                          }`}
                          style={{ width: `${rate}%` }}
                        />
                      </div>
                    </div>
                    <span className="w-12 text-right font-medium">
                      {rate.toFixed(0)}%
                    </span>
                  </div>
                ),
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
