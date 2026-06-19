import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface C2Agent {
  id: string;
  name: string;
  implant_type: string;
  beacon_mode: string;
  address: string;
  external_ip: string;
  hostname: string;
  os: string;
  username: string;
  elevated: boolean;
  arch: string;
  last_seen: string;
  status: string;
}

interface C2Task {
  id: string;
  agent_id: string;
  type: string;
  command: string;
  args: string[];
  status: string;
  result: string;
  created_at: string;
}

interface ExfilFile {
  id: string;
  agent_id: string;
  file_path: string;
  file_name: string;
  file_size: number;
  status: string;
  created_at: string;
}

export function C2AdvPage() {
  const [agents, setAgents] = useState<C2Agent[]>([]);
  const [tasks, setTasks] = useState<C2Task[]>([]);
  const [exfils, setExfils] = useState<ExfilFile[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [command, setCommand] = useState("");
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch("/api/c2/agents").then(r => r.ok ? r.json() : []),
      fetch("/api/c2/tasks").then(r => r.ok ? r.json() : []),
      fetch("/api/c2/exfil").then(r => r.ok ? r.json() : []),
    ]).then(([a, t, e]) => { setAgents(a || []); setTasks(t || []); setExfils(e || []); }).finally(() => setLoading(false));
  }, []);

  async function sendTask() {
    if (!selectedAgent || !command) return;
    const r = await fetch("/api/c2/tasks", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: selectedAgent, type: "exec", command }),
    });
    if (r.ok) {
      const t = await r.json();
      setTasks(prev => [...prev, { id: t.id, agent_id: selectedAgent, type: "exec", command, args: [], status: "pending", result: "", created_at: new Date().toISOString() }]);
      setCommand("");
    }
  }

  async function killAgent(id: string) {
    await fetch(`/api/c2/agents/${id}/kill`, { method: "POST" });
    setAgents(prev => prev.map(a => a.id === id ? { ...a, status: "killed" } : a));
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div><h1 className="text-2xl font-bold">Advanced C2</h1>
        <p className="text-muted-foreground">Agent management, beaconing, tasking, and exfiltration</p></div>
      </div>

      <Tabs defaultValue="agents">
        <TabsList>
          <TabsTrigger value="agents">Agents ({agents.length})</TabsTrigger>
          <TabsTrigger value="tasking">Tasking</TabsTrigger>
          <TabsTrigger value="exfil">Exfiltration</TabsTrigger>
        </TabsList>

        <TabsContent value="agents">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {agents.map(a => (
              <Card key={a.id} className={`cursor-pointer ${selectedAgent === a.id ? 'ring-2 ring-primary' : ''}`} onClick={() => setSelectedAgent(a.id)}>
                <CardContent className="pt-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{a.name || a.id?.slice(0, 12)}</span>
                      <Badge variant={a.status === "online" ? "default" : a.status === "killed" ? "destructive" : "secondary"}>{a.status}</Badge>
                      {a.elevated && <Badge variant="outline">SYSTEM</Badge>}
                    </div>
                    <Badge variant="secondary">{a.beacon_mode}</Badge>
                  </div>
                  <div className="grid grid-cols-2 gap-1 text-xs text-muted-foreground">
                    <div>OS: {a.os} ({a.arch})</div>
                    <div>User: {a.username}</div>
                    <div>Host: {a.hostname}</div>
                    <div>IP: {a.external_ip || a.address}</div>
                  </div>
                  <div className="mt-2 text-xs text-muted-foreground">
                    Last seen: {a.last_seen ? new Date(a.last_seen).toLocaleString() : "N/A"}
                  </div>
                  <Button size="sm" variant="destructive" className="mt-2 w-full" onClick={() => killAgent(a.id)}>Kill Agent</Button>
                </CardContent>
              </Card>
            ))}
            {agents.length === 0 && <p className="col-span-2 text-muted-foreground">No agents registered.</p>}
          </div>
        </TabsContent>

        <TabsContent value="tasking">
          <Card>
            <CardHeader><CardTitle>Send Task</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-4">
                <select className="flex h-9 w-48 rounded-md border border-input bg-transparent px-3 py-1 text-sm" value={selectedAgent} onChange={e => setSelectedAgent(e.target.value)}>
                  <option value="">Select agent...</option>
                  {agents.filter(a => a.status === "online").map(a => <option key={a.id} value={a.id}>{a.name || a.id?.slice(0,12)}</option>)}
                </select>
                <Input placeholder="Command (e.g., whoami)" value={command} onChange={e => setCommand(e.target.value)} className="flex-1" />
                <Button onClick={sendTask} disabled={!selectedAgent || !command}>Send</Button>
              </div>
            </CardContent>
          </Card>
          <div className="mt-4 space-y-2">
            {tasks.filter(t => !selectedAgent || t.agent_id === selectedAgent).map(t => (
              <Card key={t.id}>
                <CardContent className="pt-3 text-sm">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Badge variant={t.status === "completed" ? "default" : t.status === "sent" ? "secondary" : "outline"}>{t.status}</Badge>
                      <span className="font-mono">{t.command}</span>
                    </div>
                    <span className="text-xs text-muted-foreground">{t.created_at ? new Date(t.created_at).toLocaleString() : ""}</span>
                  </div>
                  {t.result && <pre className="mt-2 rounded bg-muted p-2 text-xs overflow-x-auto">{t.result}</pre>}
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="exfil">
          <div className="space-y-4">
            <div className="flex gap-4">
              <select className="flex h-9 w-48 rounded-md border border-input bg-transparent px-3 py-1 text-sm" value={selectedAgent} onChange={e => setSelectedAgent(e.target.value)}>
                <option value="">All agents</option>
                {agents.map(a => <option key={a.id} value={a.id}>{a.name || a.id?.slice(0,12)}</option>)}
              </select>
            </div>
            {exfils.filter(f => !selectedAgent || f.agent_id === selectedAgent).map(f => (
              <Card key={f.id}>
                <CardContent className="pt-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">{f.file_name}</div>
                      <div className="text-sm text-muted-foreground">{(f.file_size / 1024).toFixed(1)} KB</div>
                    </div>
                    <Badge>{f.status}</Badge>
                  </div>
                </CardContent>
              </Card>
            ))}
            {exfils.length === 0 && <p className="text-muted-foreground">No exfiltrated files.</p>}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
