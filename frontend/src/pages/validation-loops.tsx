import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { RotateCw, CheckCircle, XCircle, RefreshCw } from "lucide-react";

export function ValidationLoopsPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["validationTasks"],
    queryFn: api.listValidationTasks,
    refetchInterval: 15000,
  });

  const { data: stats } = useQuery({
    queryKey: ["validationStats"],
    queryFn: api.getValidationStats,
    refetchInterval: 15000,
  });

  if (isLoading) return <Skeleton className="h-96" />;

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Autonomous Validation Loops</h1>
        <p className="text-muted-foreground">
          Automatic retesting after remediation to confirm fixes
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card className="p-4">
          <div className="flex items-center gap-2 text-blue-500">
            <RotateCw className="h-5 w-5" />
          </div>
          <p className="mt-1 text-2xl font-bold">{stats?.total ?? 0}</p>
          <p className="text-xs text-muted-foreground">Total Tasks</p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-yellow-500">
            <RefreshCw className="h-5 w-5" />
          </div>
          <p className="mt-1 text-2xl font-bold">{stats?.pending ?? 0}</p>
          <p className="text-xs text-muted-foreground">Pending</p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-green-500">
            <CheckCircle className="h-5 w-5" />
          </div>
          <p className="mt-1 text-2xl font-bold">{stats?.passed ?? 0}</p>
          <p className="text-xs text-muted-foreground">Passed</p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-red-500">
            <XCircle className="h-5 w-5" />
          </div>
          <p className="mt-1 text-2xl font-bold">{stats?.failed ?? 0}</p>
          <p className="text-xs text-muted-foreground">Failed</p>
        </Card>
      </div>

      <Card className="p-4">
        <h2 className="mb-3 font-medium">Validation Tasks</h2>
        {(!data?.tasks || data.tasks.length === 0) && (
          <p className="text-sm text-muted-foreground">No validation tasks</p>
        )}
        <div className="space-y-2">
          {data?.tasks?.map((task) => (
            <div
              key={task.id}
              className="flex items-center justify-between rounded bg-muted/50 p-3"
            >
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">
                    {task.vulnerability_type}
                  </span>
                  <Badge
                    variant={
                      task.status === "passed"
                        ? "default"
                        : task.status === "failed"
                          ? "destructive"
                          : "secondary"
                    }
                    className="text-xs"
                  >
                    {task.status}
                  </Badge>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  {task.target} &middot; Attempt {task.attempts}/{task.max_attempts}
                </p>
              </div>
              {task.last_result && (
                <p className="text-xs text-muted-foreground">
                  {task.last_result}
                </p>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
