import { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { useScansList, useDeleteScan, useGenerateReport } from "@/api/queries";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState, ErrorState } from "@/components/states";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Trash2, ExternalLink, PlusCircle, Search, FileText } from "lucide-react";
import { timeAgo } from "@/lib/utils";
import { toast } from "sonner";

export function ScansPage() {
  const { data: scans, isLoading, error, refetch } = useScansList();
  const deleteScan = useDeleteScan();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [generatingId, setGeneratingId] = useState<string | null>(null);
  const generateReport = useGenerateReport();

  const filtered = useMemo(() => {
    if (!Array.isArray(scans)) return [];
    return scans.filter((s) => {
      const matchesSearch =
        !search ||
        s.target.toLowerCase().includes(search.toLowerCase()) ||
        s.id.toLowerCase().includes(search.toLowerCase());
      const matchesStatus = statusFilter === "all" || s.status === statusFilter;
      return matchesSearch && matchesStatus;
    });
  }, [scans, search, statusFilter]);

  const handleSelectAll = () => {
    if (selected.size === filtered.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filtered.map((s) => s.id)));
    }
  };

  const handleSelect = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  };

  const handleBulkDelete = async () => {
    for (const id of selected) {
      await deleteScan.mutateAsync(id);
    }
    setSelected(new Set());
  };

  const handleGeneratePdf = async (scanId: string) => {
    setGeneratingId(scanId);
    try {
      await generateReport.mutateAsync({ scanId, format: "pdf" });
      toast.success("PDF report generated");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to generate report");
    } finally {
      setGeneratingId(null);
    }
  };

  if (error) {
    return (
      <div className="p-6">
        <ErrorState
          title="Failed to load scans"
          description="Could not fetch scan data from the backend."
          action={{ label: "Retry", onClick: () => refetch() }}
        />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Scans</h1>
        <Button asChild>
          <Link to="/scans/new">
            <PlusCircle className="h-4 w-4" />
            New Scan
          </Link>
        </Button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search by target or ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8"
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="running">Running</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
            <SelectItem value="stopped">Stopped</SelectItem>
            <SelectItem value="failed">Failed</SelectItem>
            <SelectItem value="paused">Paused</SelectItem>
            <SelectItem value="saved">Saved</SelectItem>
          </SelectContent>
        </Select>
        {selected.size > 0 && (
          <div className="flex items-center gap-2 ml-auto">
            <span className="text-sm text-muted-foreground">{selected.size} selected</span>
            <Button variant="destructive" size="sm" onClick={handleBulkDelete}>
              <Trash2 className="h-3.5 w-3.5" />
              Delete
            </Button>
          </div>
        )}
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="space-y-2">
          {[1, 2, 3, 4, 5].map((i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : !scans || scans.length === 0 ? (
        <EmptyState
          title="No scans yet"
          description="Start your first scan to begin security testing."
          action={{ label: "New Scan", onClick: () => (window.location.href = "/scans/new") }}
        />
      ) : filtered.length === 0 ? (
        <EmptyState title="No matching scans" description="Try adjusting your search or filters." />
      ) : (
        <div className="rounded-lg border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/30">
                <th className="w-10 px-4 py-2.5 text-left">
                  <input
                    type="checkbox"
                    checked={selected.size === filtered.length && filtered.length > 0}
                    onChange={handleSelectAll}
                    className="rounded border-input"
                  />
                </th>
                <th className="px-4 py-2.5 text-left font-medium">Target</th>
                <th className="px-4 py-2.5 text-left font-medium">Status</th>
                <th className="px-4 py-2.5 text-left font-medium">Progress</th>
                <th className="px-4 py-2.5 text-left font-medium">Findings</th>
                <th className="px-4 py-2.5 text-left font-medium">Started</th>
                <th className="w-20 px-4 py-2.5 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((scan) => (
                <tr key={scan.id} className="border-b last:border-0 hover:bg-muted/20">
                  <td className="px-4 py-2.5">
                    <input
                      type="checkbox"
                      checked={selected.has(scan.id)}
                      onChange={() => handleSelect(scan.id)}
                      className="rounded border-input"
                    />
                  </td>
                  <td className="px-4 py-2.5">
                    <div>
                      <Link to={`/scans/${scan.id}`} className="font-medium hover:underline">
                        {scan.target}
                      </Link>
                      <p className="text-xs text-muted-foreground font-mono">{scan.id.substring(0, 12)}</p>
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <ScanStatusPill status={scan.status} />
                  </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden max-w-24">
                          <div
                            className="h-full rounded-full bg-primary"
                            style={{ width: `${scan.status === "completed" || scan.status === "finished" ? 100 : Math.min(((scan.progress || 0) * 100), 100)}%` }}
                          />
                        </div>
                        <span className="text-xs text-muted-foreground">{scan.status === "completed" || scan.status === "finished" ? "100" : Math.min(Math.round((scan.progress || 0) * 100), 100)}%</span>
                      </div>
                    </td>
                  <td className="px-4 py-2.5">
                    {scan.findings_count > 0 ? (
                      <Badge variant="outline">{scan.findings_count}</Badge>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-muted-foreground">{timeAgo(scan.start_time)}</td>
                  <td className="px-4 py-2.5 text-right">
                    <div className="flex justify-end gap-1">
                      {scan.findings_count > 0 && (
                        <Button variant="ghost" size="icon" onClick={() => handleGeneratePdf(scan.id)} disabled={generatingId !== null} title="Generate PDF report">
                          {generatingId === scan.id ? (
                            <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                          ) : (
                            <FileText className="h-4 w-4" />
                          )}
                        </Button>
                      )}
                      <Button variant="ghost" size="icon" asChild>
                        <Link to={`/scans/${scan.id}`}>
                          <ExternalLink className="h-4 w-4" />
                        </Link>
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
