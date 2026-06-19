import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Fingerprint, Link2, FileText } from "lucide-react";

export function EvidenceIntegrityPage() {
  const { data: chain, isLoading: chainLoading } = useQuery({
    queryKey: ["evidenceChain"],
    queryFn: api.getEvidenceChain,
  });

  const { data: log } = useQuery({
    queryKey: ["evidenceLog"],
    queryFn: api.getImmutableLog,
  });

  const { data: tamperCheck } = useQuery({
    queryKey: ["tamperCheck"],
    queryFn: api.checkTampering,
  });

  if (chainLoading) return <Skeleton className="h-96" />;

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Evidence Integrity</h1>
        <p className="text-muted-foreground">
          Cryptographic signing, chain-of-custody, and tamper detection
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card className="p-4">
          <div className="flex items-center gap-2 text-green-500">
            <Fingerprint className="h-5 w-5" />
            <span className="text-sm text-muted-foreground">
              Chain Integrity
            </span>
          </div>
          <p className="mt-1 text-lg font-bold">
            {tamperCheck?.tampered ? "Tampered" : "Valid"}
          </p>
          {tamperCheck?.issues?.map((issue, i) => (
            <p key={i} className="text-xs text-red-500">
              {issue}
            </p>
          ))}
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-blue-500">
            <Link2 className="h-5 w-5" />
            <span className="text-sm text-muted-foreground">
              Chain Entries
            </span>
          </div>
          <p className="mt-1 text-lg font-bold">{chain?.length ?? 0}</p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-yellow-500">
            <FileText className="h-5 w-5" />
            <span className="text-sm text-muted-foreground">Log Entries</span>
          </div>
          <p className="mt-1 text-lg font-bold">{log?.length ?? 0}</p>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="p-4">
          <h2 className="mb-3 font-medium">Chain of Custody</h2>
          {(!chain || chain.length === 0) && (
            <p className="text-sm text-muted-foreground">
              No chain of custody entries
            </p>
          )}
          <div className="space-y-2">
            {chain?.map((entry) => (
              <div
                key={entry.id}
                className="rounded bg-muted/50 p-2 text-sm"
              >
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-xs">
                    {entry.action}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    by {entry.performed_by}
                  </span>
                </div>
                <p className="mt-1 text-xs font-mono text-muted-foreground">
                  Hash: {entry.hash.slice(0, 16)}...
                </p>
                {entry.notes && (
                  <p className="mt-1 text-xs">{entry.notes}</p>
                )}
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-4">
          <h2 className="mb-3 font-medium">Immutable Audit Log</h2>
          {(!log || log.length === 0) && (
            <p className="text-sm text-muted-foreground">
              No audit log entries
            </p>
          )}
          <div className="space-y-2">
            {log?.slice(-20).map((entry) => (
              <div
                key={entry.id}
                className="rounded bg-muted/50 p-2 text-sm"
              >
                <div className="flex items-center gap-2">
                  <Badge
                    variant={
                      entry.level === "error"
                        ? "destructive"
                        : entry.level === "warn"
                          ? "default"
                          : "secondary"
                    }
                    className="text-xs"
                  >
                    {entry.level}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    {new Date(entry.timestamp).toLocaleString()}
                  </span>
                </div>
                <p className="mt-1">{entry.message}</p>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
