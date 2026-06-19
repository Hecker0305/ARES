import { useState } from "react";
import { useSchedules, useCreateSchedule, useDeleteSchedule, useToggleSchedule } from "@/api/queries";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/states";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Plus, Trash2, Play, Pause } from "lucide-react";
import { parseCronDescription } from "@/lib/utils";
import { useSettings } from "@/store/settings";


export function SchedulesPage() {
  const { adminUsername } = useSettings();
  const { data: schedules, isLoading } = useSchedules();
  const createSchedule = useCreateSchedule();
  const deleteSchedule = useDeleteSchedule();
  const toggleSchedule = useToggleSchedule();
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({ name: "", target: "", cron_expr: "", enabled: true, created_by: adminUsername });
  const handleCreate = async () => { 
    if (!formData.name || !formData.target || !formData.cron_expr) return; 
    await createSchedule.mutateAsync(formData); 
    setFormData({ name: "", target: "", cron_expr: "", enabled: true, created_by: adminUsername }); 
    setShowForm(false); 
  };
  if (isLoading) return <div className="p-6"><Skeleton className="h-64 rounded-lg" /></div>;
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between"><div><h1 className="text-2xl font-bold">Schedules</h1><p className="text-muted-foreground mt-1">Automated recurring scans with cron expressions.</p></div><Button onClick={() => setShowForm(!showForm)}><Plus className="h-4 w-4" />New Schedule</Button></div>
      {showForm && (<Card><CardHeader><CardTitle>Create Schedule</CardTitle><CardDescription>Configure a recurring scan.</CardDescription></CardHeader><CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2"><Label>Name</Label><Input value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} placeholder="Daily scan" /></div>
          <div className="space-y-2"><Label>Target</Label><Input value={formData.target} onChange={(e) => setFormData({ ...formData, target: e.target.value })} placeholder="https://example.com" /></div>
          <div className="space-y-2 md:col-span-2"><Label>Cron Expression</Label><Input value={formData.cron_expr} onChange={(e) => setFormData({ ...formData, cron_expr: e.target.value })} placeholder="0 2 * * *" />{formData.cron_expr && (<p className="text-xs text-muted-foreground">{parseCronDescription(formData.cron_expr)}</p>)}</div>
        </div>
        <div className="flex items-center gap-2"><Switch checked={formData.enabled} onCheckedChange={(v) => setFormData({ ...formData, enabled: v })} id="schedule-enabled" /><Label htmlFor="schedule-enabled">Enabled</Label></div>
        <div className="flex gap-2"><Button onClick={handleCreate} disabled={createSchedule.isPending}>{createSchedule.isPending ? "Creating..." : "Create"}</Button><Button variant="outline" onClick={() => setShowForm(false)}>Cancel</Button></div>
      </CardContent></Card>)}
      {!schedules || schedules.length === 0 ? (<EmptyState title="No schedules" description="Create a schedule to automate recurring scans." />) : (
        <div className="rounded-lg border">
          <table className="w-full text-sm"><thead><tr className="border-b bg-muted/30"><th className="px-4 py-2.5 text-left font-medium">Name</th><th className="px-4 py-2.5 text-left font-medium">Target</th><th className="px-4 py-2.5 text-left font-medium">Cron</th><th className="px-4 py-2.5 text-left font-medium">Schedule</th><th className="px-4 py-2.5 text-left font-medium">Status</th><th className="w-24 px-4 py-2.5 text-right font-medium">Actions</th></tr></thead>
          <tbody>{schedules.map((s) => (<tr key={s.id} className="border-b last:border-0 hover:bg-muted/20">
            <td className="px-4 py-2.5 font-medium">{s.name}</td><td className="px-4 py-2.5 font-mono text-xs">{s.target}</td><td className="px-4 py-2.5 font-mono text-xs">{s.cron_expr}</td><td className="px-4 py-2.5 text-muted-foreground text-xs">{parseCronDescription(s.cron_expr)}</td>
            <td className="px-4 py-2.5"><Badge variant={s.enabled ? "success" : "muted"}>{s.enabled ? "Active" : "Paused"}</Badge></td>
            <td className="px-4 py-2.5 text-right"><div className="flex justify-end gap-1"><Button variant="ghost" size="icon" onClick={() => toggleSchedule.mutate({ id: s.id, action: s.enabled ? "pause" : "resume" })}>{s.enabled ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}</Button><Button variant="ghost" size="icon" onClick={() => deleteSchedule.mutate(s.id)}><Trash2 className="h-4 w-4" /></Button></div></td>
          </tr>))}</tbody>
        </table>
      </div>)}
    </div>
  );
}
