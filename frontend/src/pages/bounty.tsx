import { useState } from "react";
import { useBountyReports, useBountyPlatforms, useSyncAllBounty } from "@/api/queries";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/states";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { RefreshCw } from "lucide-react";
import { timeAgo } from "@/lib/utils";

export function BountyPage() {
  const { data: reportsData, isLoading: reportsLoading } = useBountyReports();
  const { data: platformsData, isLoading: platformsLoading } = useBountyPlatforms();
  const syncAll = useSyncAllBounty();
  const [activeTab, setActiveTab] = useState("reports");
  const reports = reportsData?.reports || [];
  const platforms = platformsData?.platforms || [];
  const totalBounty = reports.reduce((sum, r) => sum + (r.bounty || 0), 0);
  const criticalReports = reports.filter((r) => r.severity === "critical").length;
  if (reportsLoading || platformsLoading) return <div className="p-6"><Skeleton className="h-64 rounded-lg" /></div>;
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between"><div><h1 className="text-2xl font-bold">Bug Bounty</h1><p className="text-muted-foreground mt-1">HackerOne and Bugcrowd integration.</p></div><Button onClick={() => syncAll.mutate()} disabled={syncAll.isPending}><RefreshCw className={`h-4 w-4 ${syncAll.isPending ? "animate-spin" : ""}`} />Sync All</Button></div>
      <div className="grid gap-4 md:grid-cols-4">
        <Card><CardContent className="pt-6"><p className="text-sm text-muted-foreground">Total Reports</p><p className="text-3xl font-bold mt-1">{reportsData?.total || 0}</p></CardContent></Card>
        <Card><CardContent className="pt-6"><p className="text-sm text-muted-foreground">Total Bounty</p><p className="text-3xl font-bold mt-1">${totalBounty.toLocaleString()}</p></CardContent></Card>
        <Card><CardContent className="pt-6"><p className="text-sm text-muted-foreground">Critical Reports</p><p className="text-3xl font-bold mt-1 text-severity-critical">{criticalReports}</p></CardContent></Card>
        <Card><CardContent className="pt-6"><p className="text-sm text-muted-foreground">Platforms</p><p className="text-3xl font-bold mt-1">{platforms.length}</p></CardContent></Card>
      </div>
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList><TabsTrigger value="reports">Reports</TabsTrigger><TabsTrigger value="platforms">Platforms</TabsTrigger><TabsTrigger value="submit">Submit</TabsTrigger></TabsList>
        <TabsContent value="reports" className="mt-4">
          {!reports || reports.length === 0 ? (<EmptyState title="No bounty reports" description="Sync platforms to import reports." />) : (
            <div className="rounded-lg border"><table className="w-full text-sm"><thead><tr className="border-b bg-muted/30"><th className="px-4 py-2.5 text-left font-medium">Title</th><th className="px-4 py-2.5 text-left font-medium">Platform</th><th className="px-4 py-2.5 text-left font-medium">Severity</th><th className="px-4 py-2.5 text-left font-medium">Target</th><th className="px-4 py-2.5 text-left font-medium">Bounty</th><th className="px-4 py-2.5 text-left font-medium">Date</th></tr></thead>
              <tbody>{reports.map((r) => (<tr key={r.id} className="border-b last:border-0 hover:bg-muted/20">
                <td className="px-4 py-2.5 font-medium">{r.title}</td><td className="px-4 py-2.5"><Badge variant="outline">{r.platform}</Badge></td><td className="px-4 py-2.5"><Badge variant={r.severity === "critical" ? "destructive" : r.severity === "high" ? "warning" : "muted"}>{r.severity}</Badge></td><td className="px-4 py-2.5 font-mono text-xs">{r.target}</td><td className="px-4 py-2.5">{r.bounty ? `$${r.bounty.toLocaleString()}` : "—"}</td><td className="px-4 py-2.5 text-muted-foreground">{timeAgo(r.created_at)}</td>
              </tr>))}</tbody>
            </table></div>
          )}
        </TabsContent>
        <TabsContent value="platforms" className="mt-4">
          {!platforms || platforms.length === 0 ? (<EmptyState title="No platforms configured" description="Add HackerOne or Bugcrowd to get started." />) : (
            <div className="grid gap-4 md:grid-cols-2">{platforms.map((p) => (
              <Card key={p.platform}><CardHeader className="pb-3"><div className="flex items-center justify-between"><CardTitle className="text-base">{p.platform}</CardTitle><Badge variant={p.enabled ? "success" : "muted"}>{p.enabled ? "Connected" : "Disconnected"}</Badge></div></CardHeader>
                <CardContent className="space-y-3"><div className="grid grid-cols-3 gap-2 text-xs"><div><p className="text-muted-foreground">Reports</p><p className="font-bold">{p.reports || 0}</p></div><div><p className="text-muted-foreground">Bounty</p><p className="font-bold">${p.bounty_earned?.toLocaleString() || 0}</p></div><div><p className="text-muted-foreground">Auto Sync</p><p className="font-bold">{p.auto_sync ? "Yes" : "No"}</p></div></div></CardContent>
              </Card>
            ))}</div>
          )}
        </TabsContent>
        <TabsContent value="submit" className="mt-4">
          <Card><CardHeader><CardTitle>Submit Report</CardTitle><CardDescription>Manually submit a bounty report.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2"><Label>Platform</Label><Select><SelectTrigger><SelectValue placeholder="Select" /></SelectTrigger><SelectContent><SelectItem value="hackerone">HackerOne</SelectItem><SelectItem value="bugcrowd">Bugcrowd</SelectItem></SelectContent></Select></div>
                <div className="space-y-2"><Label>Severity</Label><Select><SelectTrigger><SelectValue placeholder="Select" /></SelectTrigger><SelectContent><SelectItem value="critical">Critical</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="low">Low</SelectItem></SelectContent></Select></div>
                <div className="space-y-2 md:col-span-2"><Label>Title</Label><Input placeholder="SQL Injection in login endpoint" /></div>
                <div className="space-y-2"><Label>Target</Label><Input placeholder="https://example.com" /></div>
                <div className="space-y-2"><Label>CWE</Label><Input placeholder="CWE-89" /></div>
                <div className="space-y-2 md:col-span-2"><Label>Description</Label><Textarea placeholder="Detailed description of the vulnerability..." className="min-h-24" /></div>
              </div>
              <Button>Submit Report</Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
