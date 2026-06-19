import { useState } from "react";
import { useComplianceReports, useComplianceFindings } from "@/api/queries";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/states";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Shield, AlertTriangle } from "lucide-react";

const frameworks = [
  { id: "all", name: "All Frameworks" },
  { id: "NIST CSF 2.0", name: "NIST CSF 2.0" },
  { id: "ISO 27001:2022", name: "ISO 27001:2022" },
  { id: "PCI DSS v4.0", name: "PCI DSS v4.0" },
  { id: "SOC 2 Type II", name: "SOC 2 Type II" },
  { id: "HIPAA", name: "HIPAA" },
  { id: "GDPR", name: "GDPR" },
];

export function CompliancePage() {
  const { data: reports, isLoading } = useComplianceReports();
  const [selectedFramework, setSelectedFramework] = useState("all");
  const { data: findings } = useComplianceFindings(selectedFramework === "all" ? undefined : selectedFramework);
  if (isLoading) return <div className="p-6"><Skeleton className="h-64 rounded-lg" /></div>;
  const avgScore = reports ? Math.round(reports.reduce((sum, r) => sum + r.score, 0) / reports.length) : 0;
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between"><div><h1 className="text-2xl font-bold">Compliance</h1><p className="text-muted-foreground mt-1">Multi-framework compliance dashboard.</p></div><Select value={selectedFramework} onValueChange={setSelectedFramework}><SelectTrigger className="w-48"><SelectValue /></SelectTrigger><SelectContent>{frameworks.map((fw) => (<SelectItem key={fw.id} value={fw.id}>{fw.name}</SelectItem>))}</SelectContent></Select></div>
      <div className="grid gap-4 md:grid-cols-4">
        <Card><CardContent className="pt-6"><p className="text-sm text-muted-foreground">Average Score</p><p className="text-3xl font-bold mt-1">{avgScore}%</p></CardContent></Card>
        <Card><CardContent className="pt-6"><p className="text-sm text-muted-foreground">Frameworks</p><p className="text-3xl font-bold mt-1">{reports?.length || 0}</p></CardContent></Card>
        <Card><CardContent className="pt-6"><p className="text-sm text-muted-foreground">Critical Gaps</p><p className="text-3xl font-bold mt-1 text-severity-critical">{reports?.reduce((sum, r) => sum + r.gapsCritical, 0) || 0}</p></CardContent></Card>
        <Card><CardContent className="pt-6"><p className="text-sm text-muted-foreground">High Gaps</p><p className="text-3xl font-bold mt-1 text-severity-high">{reports?.reduce((sum, r) => sum + r.gapsHigh, 0) || 0}</p></CardContent></Card>
      </div>
      {!reports || reports.length === 0 ? (<EmptyState title="No compliance data" description="Run scans to generate compliance mappings." />) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {reports.filter((r) => selectedFramework === "all" || r.framework === selectedFramework).map((report) => (
            <Card key={report.framework}><CardHeader className="pb-3"><div className="flex items-center gap-2"><Shield className="h-5 w-5" /><CardTitle className="text-base">{report.framework}</CardTitle></div></CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between"><span className="text-sm text-muted-foreground">Score</span><span className="text-2xl font-bold">{report.score}%</span></div>
                <div className="h-2 rounded-full bg-muted overflow-hidden"><div className="h-full rounded-full bg-success transition-all" style={{ width: `${report.score}%` }} /></div>
                <div className="grid grid-cols-2 gap-2 text-xs"><div><span className="text-muted-foreground">Passed:</span> <span className="font-medium">{report.controlsPassed}</span></div><div><span className="text-muted-foreground">Failed:</span> <span className="font-medium">{report.controlsFailed}</span></div><div><span className="text-muted-foreground">Critical:</span> <span className="font-medium text-severity-critical">{report.gapsCritical}</span></div><div><span className="text-muted-foreground">High:</span> <span className="font-medium text-severity-high">{report.gapsHigh}</span></div></div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
      {findings && findings.length > 0 && (<Card><CardHeader><CardTitle className="text-base flex items-center gap-2"><AlertTriangle className="h-4 w-4" />Control Findings</CardTitle></CardHeader><CardContent><div className="space-y-2">{findings.slice(0, 20).map((f, i) => (<div key={i} className="flex items-start justify-between rounded-md border p-3"><div><p className="font-medium text-sm">{f.controlId}</p><p className="text-xs text-muted-foreground mt-0.5">{f.description}</p></div><Badge variant={f.status === "pass" ? "success" : f.status === "fail" ? "destructive" : "muted"}>{f.status}</Badge></div>))}</div></CardContent></Card>)}
    </div>
  );
}
