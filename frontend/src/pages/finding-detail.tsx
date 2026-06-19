import { useParams, Link } from "react-router-dom";
import { useFinding, useVerifyFinding, useUpdateFindingStatus } from "@/api/queries";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/states";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ArrowLeft, CheckCircle, RefreshCw, Shield } from "lucide-react";

export function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: finding, isLoading, error, refetch } = useFinding(id);
  const verifyFinding = useVerifyFinding();
  const updateStatus = useUpdateFindingStatus();

  if (!id) return null;

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-48 rounded-lg" />
        <Skeleton className="h-32 rounded-lg" />
      </div>
    );
  }

  if (error || !finding) {
    return (
      <div className="p-6">
        <ErrorState
          title="Finding not found"
          description="Could not load finding data."
          action={{ label: "Retry", onClick: () => refetch() }}
        />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start gap-3">
        <Button variant="ghost" size="icon" asChild>
          <Link to="/findings">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold">{finding.title}</h1>
            <SeverityBadge severity={finding.severity} />
          </div>
          <p className="text-sm text-muted-foreground font-mono mt-1">{finding.endpoint}</p>
        </div>
      </div>

      {/* CVSS Score */}
      {finding.cvssScore && (
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-6">
              <CVSSRing score={finding.cvssScore} />
              <div>
                <p className="text-sm text-muted-foreground">CVSS Score</p>
                <p className="text-3xl font-bold">{finding.cvssScore}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Description, Impact, Remediation */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Description</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{finding.description || "No description available."}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Impact</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{finding.impact || "No impact assessment available."}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Remediation</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{finding.remediation || "No remediation guidance available."}</p>
          </CardContent>
        </Card>
      </div>

      {/* Proof of Concept */}
      {finding.poc && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Proof of Concept</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="rounded bg-muted/50 p-4 text-sm font-mono overflow-x-auto whitespace-pre-wrap">
              {finding.poc}
            </pre>
          </CardContent>
        </Card>
      )}

      {/* MITRE ATT&CK */}
      {finding.mitreMapping && finding.mitreMapping.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="h-4 w-4" />
              MITRE ATT&CK Mapping
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {finding.mitreMapping.map((m, i) => (
                <div key={i} className="flex items-center gap-3 rounded-md border p-3">
                  <Badge variant="outline">{m.id}</Badge>
                  <div>
                    <p className="text-sm font-medium">{m.technique}</p>
                    <p className="text-xs text-muted-foreground">{m.tactic}</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Verification Chain */}
      {finding.verificationChain && finding.verificationChain.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Verification Chain</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {finding.verificationChain.map((round) => (
                <div key={round.round} className="flex items-center gap-3">
                  <CheckCircle className="h-4 w-4 text-success" />
                  <span className="text-sm font-medium">Round {round.round}</span>
                  <Badge variant="success">{round.result}</Badge>
                  <span className="text-xs text-muted-foreground ml-auto">{round.timestamp}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Actions */}
      <div className="flex gap-3">
        <Button variant="outline" onClick={() => verifyFinding.mutate(id)} disabled={verifyFinding.isPending}>
          <RefreshCw className={`h-4 w-4 ${verifyFinding.isPending ? "animate-spin" : ""}`} />
          Re-Verify
        </Button>
        {["Open", "Fixed", "Accept Risk", "Won't Fix"].map((status) => (
          <Button
            key={status}
            variant={finding.status === status.toLowerCase() ? "default" : "outline"}
            onClick={() => updateStatus.mutate({ id, status: status.toLowerCase() })}
          >
            {status}
          </Button>
        ))}
      </div>
    </div>
  );
}

function CVSSRing({ score }: { score: number }) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 10) * circumference;
  const color = score >= 9 ? "#dc2626" : score >= 7 ? "#ea580c" : score >= 4 ? "#ca8a04" : "#2563eb";

  return (
    <svg width="80" height="80" viewBox="0 0 80 80">
      <circle cx="40" cy="40" r={radius} fill="none" stroke="#262626" strokeWidth="6" />
      <circle
        cx="40"
        cy="40"
        r={radius}
        fill="none"
        stroke={color}
        strokeWidth="6"
        strokeDasharray={circumference}
        strokeDashoffset={circumference - progress}
        strokeLinecap="round"
        transform="rotate(-90 40 40)"
      />
      <text x="40" y="44" textAnchor="middle" fill="#fafafa" fontSize="16" fontWeight="bold">
        {score}
      </text>
    </svg>
  );
}
