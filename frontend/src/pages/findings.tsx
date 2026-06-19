import { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { useFindings, useDeleteFinding } from "@/api/queries";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState, ErrorState } from "@/components/states";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Trash2, ExternalLink, Search } from "lucide-react";
import { timeAgo, cn } from "@/lib/utils";

const cvssColor = (score: number) => {
  if (score >= 9.0) return "bg-red-500/10 text-red-500 border-red-500/20";
  if (score >= 7.0) return "bg-orange-500/10 text-orange-500 border-orange-500/20";
  if (score >= 4.0) return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
  return "bg-blue-500/10 text-blue-500 border-blue-500/20";
};

export function FindingsPage() {
  const { data: findings, isLoading, error, refetch } = useFindings();
  const deleteFinding = useDeleteFinding();
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const severityCounts = useMemo(() => {
    if (!Array.isArray(findings)) return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    return counts;
  }, [findings]);

  const filtered = useMemo(() => {
    if (!Array.isArray(findings)) return [];
    return findings.filter((f) => {
      const matchesSearch = !search || f.title.toLowerCase().includes(search.toLowerCase()) || f.endpoint.toLowerCase().includes(search.toLowerCase());
      const matchesSeverity = severityFilter === "all" || f.severity === severityFilter;
      return matchesSearch && matchesSeverity;
    });
  }, [findings, search, severityFilter]);

  const handleSelectAll = () => { setSelected(selected.size === filtered.length && filtered.length > 0 ? new Set() : new Set(filtered.map((f) => f.id))); };
  const handleSelect = (id: string) => { const next = new Set(selected); if (next.has(id)) next.delete(id); else next.add(id); setSelected(next); };
  const handleBulkDelete = async () => { for (const id of selected) { await deleteFinding.mutateAsync(id); } setSelected(new Set()); };

  if (error) return <div className="p-6"><ErrorState title="Failed to load findings" description="Could not fetch findings from the backend." action={{ label: "Retry", onClick: () => refetch() }} /></div>;

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Findings</h1>
      <div className="flex gap-3">
        {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
          <button key={sev} onClick={() => setSeverityFilter(severityFilter === sev ? "all" : sev)} className={`flex items-center gap-2 rounded-lg border px-4 py-2 transition-colors ${severityFilter === sev ? "border-primary bg-primary/5" : "border-border hover:bg-muted/50"}`}>
            <SeverityBadge severity={sev} /><span className="text-lg font-bold">{severityCounts[sev]}</span>
          </button>
        ))}
      </div>
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input placeholder="Search findings..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-8" />
        </div>
        {selected.size > 0 && (<div className="flex items-center gap-2 ml-auto"><span className="text-sm text-muted-foreground">{selected.size} selected</span><Button variant="destructive" size="sm" onClick={handleBulkDelete}><Trash2 className="h-3.5 w-3.5" />Delete</Button></div>)}
      </div>
      {isLoading ? (<div className="space-y-2">{[1, 2, 3, 4, 5].map((i) => <Skeleton key={i} className="h-12 w-full" />)}</div>) : !findings || findings.length === 0 ? (<EmptyState title="No findings" description="Findings will appear here once scans discover vulnerabilities." />) : filtered.length === 0 ? (<EmptyState title="No matching findings" description="Try adjusting your search or filters." />) : (
        <div className="rounded-lg border">
          <table className="w-full text-sm">
            <thead><tr className="border-b bg-muted/30">
              <th className="w-10 px-4 py-2.5 text-left"><input type="checkbox" checked={selected.size === filtered.length && filtered.length > 0} onChange={handleSelectAll} className="rounded border-input" /></th>
              <th className="px-4 py-2.5 text-left font-medium">Title</th><th className="px-4 py-2.5 text-left font-medium">Severity</th><th className="px-4 py-2.5 text-left font-medium">Endpoint</th><th className="px-4 py-2.5 text-left font-medium">Status</th><th className="px-4 py-2.5 text-left font-medium">CVE</th><th className="px-4 py-2.5 text-left font-medium">Discovered</th><th className="w-20 px-4 py-2.5 text-right font-medium">Actions</th>
            </tr></thead>
            <tbody>{filtered.map((f) => (
              <tr key={f.id} className="border-b last:border-0 hover:bg-muted/20">
                <td className="px-4 py-2.5"><input type="checkbox" checked={selected.has(f.id)} onChange={() => handleSelect(f.id)} className="rounded border-input" /></td>
                <td className="px-4 py-2.5"><Link to={`/findings/${f.id}`} className="font-medium hover:underline">{f.title}</Link></td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    {f.cvssScore != null && (
                      <Badge variant="outline" className={cn("rounded-full text-xs font-semibold px-2 py-0", cvssColor(f.cvssScore))}>
                        {f.cvssScore.toFixed(1)}
                      </Badge>
                    )}
                  </div>
                </td>
                <td className="px-4 py-2.5 font-mono text-xs truncate max-w-48">{f.endpoint}</td>
                <td className="px-4 py-2.5"><Badge variant={f.status === "open" ? "destructive" : "muted"}>{f.status}</Badge></td>
                <td className="px-4 py-2.5">
                  {f.cve ? (
                    <Badge variant="outline" className="font-mono text-xs">
                      {f.cve}
                    </Badge>
                  ) : null}
                </td>
                <td className="px-4 py-2.5 text-muted-foreground">{timeAgo(f.discoveredAt)}</td>
                <td className="px-4 py-2.5 text-right"><Button variant="ghost" size="icon" asChild><Link to={`/findings/${f.id}`}><ExternalLink className="h-4 w-4" /></Link></Button></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}
