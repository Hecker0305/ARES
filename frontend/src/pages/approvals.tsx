import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { CheckCircle, XCircle, AlertTriangle, Clock } from "lucide-react";
import { toast } from "sonner";

export function ApprovalsPage() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["approvals"],
    queryFn: api.listApprovals,
    refetchInterval: 10000,
  });

  const approveMut = useMutation({
    mutationFn: ({ id }: { id: string }) => api.approveRequest(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["approvals"] });
      toast.success("Request approved");
    },
  });

  const denyMut = useMutation({
    mutationFn: ({ id }: { id: string }) => api.denyRequest(id, "Denied by user"),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["approvals"] });
      toast.success("Request denied");
    },
  });

  if (isLoading) return <Skeleton className="h-96" />;

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Approval Workflows</h1>
        <p className="text-muted-foreground">
          Human approval gates for exploitation, remediation, and integrations
        </p>
      </div>

      <div className="grid gap-4">
        {data?.approvals?.length === 0 && (
          <Card className="p-12 text-center text-muted-foreground">
            No pending approval requests
          </Card>
        )}
        {data?.approvals?.map((req) => (
          <Card key={req.id} className="p-4">
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-3">
                {req.status === "pending" && (
                  <Clock className="mt-1 h-5 w-5 text-yellow-500" />
                )}
                {req.status === "approved" && (
                  <CheckCircle className="mt-1 h-5 w-5 text-green-500" />
                )}
                {req.status === "denied" && (
                  <XCircle className="mt-1 h-5 w-5 text-red-500" />
                )}
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{req.type}</span>
                    <Badge
                      variant={
                        req.status === "pending"
                          ? "default"
                          : req.status === "approved"
                            ? "secondary"
                            : "destructive"
                      }
                    >
                      {req.status}
                    </Badge>
                  </div>
                  <p className="mt-1 text-sm">{req.reason}</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Target: {req.target} &middot; Requester: {req.requester}
                  </p>
                </div>
              </div>
              {req.status === "pending" && (
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="default"
                    onClick={() => approveMut.mutate({ id: req.id })}
                  >
                    <CheckCircle className="mr-1 h-4 w-4" /> Approve
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => denyMut.mutate({ id: req.id })}
                  >
                    <XCircle className="mr-1 h-4 w-4" /> Deny
                  </Button>
                </div>
              )}
            </div>
          </Card>
        ))}
      </div>

      <Card className="p-4">
        <h2 className="mb-2 font-medium">Emergency Stop</h2>
        <p className="text-sm text-muted-foreground">
          Emergency stop is available to halt all active operations immediately.
        </p>
        <EmergencyStopControls />
      </Card>
    </div>
  );
}

function EmergencyStopControls() {
  const { data } = useQuery({
    queryKey: ["eStop"],
    queryFn: api.getEStopStatus,
    refetchInterval: 5000,
  });
  const qc = useQueryClient();

  const triggerMut = useMutation({
    mutationFn: () => api.triggerEStop("Emergency stop triggered by user"),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["eStop"] });
      toast.error("Emergency stop activated");
    },
  });

  const clearMut = useMutation({
    mutationFn: () => api.clearEStop(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["eStop"] });
      toast.success("Emergency stop cleared");
    },
  });

  return (
    <div className="mt-3 flex items-center gap-3">
      {data?.active ? (
        <>
          <Badge variant="destructive" className="animate-pulse">
            <AlertTriangle className="mr-1 h-4 w-4" /> ACTIVE
          </Badge>
          <span className="text-sm text-red-500">{data.reason}</span>
          <Button size="sm" variant="outline" onClick={() => clearMut.mutate()}>
            Clear
          </Button>
        </>
      ) : (
        <Button
          size="sm"
          variant="destructive"
          onClick={() => triggerMut.mutate()}
        >
          <AlertTriangle className="mr-1 h-4 w-4" /> Trigger Emergency Stop
        </Button>
      )}
    </div>
  );
}
