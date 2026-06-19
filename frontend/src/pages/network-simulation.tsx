import { useState, useEffect, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface SimTemplate {
  id: string;
  name: string;
  scenario: string;
  description: string;
  target_count: number;
  duration: string;
}

interface SimPhase {
  name: string;
  status: string;
  duration: string;
  started_at: string;
}

interface SimMetrics {
  total_packets: number;
  total_bytes: number;
  active_connections: number;
  peak_connections: number;
  duration: string;
  avg_latency: string;
  packet_loss: number;
}

interface Simulation {
  id: string;
  name: string;
  scenario: string;
  targets: { id: string; hostname: string; ip: string; os: string; role: string }[];
  phases: SimPhase[];
  status: string;
  metrics: SimMetrics;
  created_at: string;
}

export function NetworkSimPage() {
  const [templates, setTemplates] = useState<SimTemplate[]>([]);
  const [sims, setSims] = useState<Simulation[]>([]);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [loading, setLoading] = useState(true);
  const pollRefs = useRef<Map<string, ReturnType<typeof setInterval>>>(new Map());

  useEffect(() => {
    const refs = pollRefs.current;
    return () => {
      refs.forEach((id) => clearInterval(id));
      refs.clear();
    };
  }, []);

  useEffect(() => {
    Promise.all([
      fetch("/api/netsim/templates").then(r => r.ok ? r.json() : []),
      fetch("/api/netsim/simulations").then(r => r.ok ? r.json() : []),
    ]).then(([t, s]) => { setTemplates(t || []); setSims(s || []); }).finally(() => setLoading(false));
  }, []);

  async function createFromTemplate(t: SimTemplate) {
    const r = await fetch("/api/netsim/simulations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: `${t.name} - ${new Date().toLocaleString()}`,
        scenario: t.scenario,
        targets: Array.from({ length: t.target_count }, (_, i) => ({
          id: `target-${i}`,
          hostname: `target-${i}.local`,
          ip: `10.0.0.${100 + i}`,
          os: "linux",
          role: i === 0 ? "primary" : "secondary",
        })),
      }),
    });
    if (r.ok) {
      const sim = await r.json();
      setSims(prev => [...prev, sim]);
      startSimulation(sim.id);
    }
  }

  async function startSimulation(id: string) {
    await fetch(`/api/netsim/simulations/${id}/start`, { method: "POST" });

    const poll = setInterval(async () => {
      const r = await fetch(`/api/netsim/simulations/${id}`);
      if (r.ok) {
        const updated = await r.json();
        setSims(prev => prev.map(s => s.id === id ? updated : s));
        if (updated.status === "completed" || updated.status === "stopped") {
          clearInterval(poll);
          pollRefs.current.delete(id);
        }
      }
    }, 2000);
    pollRefs.current.set(id, poll);
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div><h1 className="text-2xl font-bold">Network Simulation</h1>
        <p className="text-muted-foreground">Large-scale distributed attack simulation and traffic generation</p></div>
      </div>

      <Tabs defaultValue="templates">
        <TabsList>
          <TabsTrigger value="templates">Templates</TabsTrigger>
          <TabsTrigger value="simulations">Simulations ({sims.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="templates">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {templates.map(t => (
              <Card key={t.id}>
                <CardHeader>
                  <CardTitle className="text-sm">{t.name}</CardTitle>
                  <Badge variant="secondary" className="w-fit">{t.scenario}</Badge>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <p className="text-muted-foreground text-xs">{t.description}</p>
                  <div className="flex justify-between text-xs text-muted-foreground">
                    <span>{t.target_count} targets</span>
                    <span>{t.duration}</span>
                  </div>
                  <Button size="sm" className="w-full" onClick={() => createFromTemplate(t)}>Deploy Simulation</Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="simulations">
          {sims.length === 0 ? <p className="text-muted-foreground">No simulations deployed.</p> :
           sims.map(s => (
            <Card key={s.id}>
              <CardContent className="pt-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{s.name}</span>
                    <Badge variant={s.status === "running" ? "default" : s.status === "completed" ? "secondary" : "outline"}>{s.status}</Badge>
                    <Badge variant="outline">{s.scenario}</Badge>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-3">
                  <div className="text-center p-2 rounded bg-muted">
                    <div className="text-lg font-bold">{s.metrics?.total_packets?.toLocaleString() || 0}</div>
                    <div className="text-xs text-muted-foreground">Packets</div>
                  </div>
                  <div className="text-center p-2 rounded bg-muted">
                    <div className="text-lg font-bold">{((s.metrics?.total_bytes || 0) / 1024 / 1024).toFixed(1)}MB</div>
                    <div className="text-xs text-muted-foreground">Data Transferred</div>
                  </div>
                  <div className="text-center p-2 rounded bg-muted">
                    <div className="text-lg font-bold">{s.metrics?.peak_connections || 0}</div>
                    <div className="text-xs text-muted-foreground">Peak Connections</div>
                  </div>
                  <div className="text-center p-2 rounded bg-muted">
                    <div className="text-lg font-bold">{s.metrics?.packet_loss?.toFixed(1)}%</div>
                    <div className="text-xs text-muted-foreground">Packet Loss</div>
                  </div>
                </div>

                <div className="space-y-1">
                  {s.phases?.map((p, i) => (
                    <div key={i} className="flex items-center gap-2 text-sm">
                      <Badge variant={p.status === "completed" ? "default" : p.status === "running" ? "secondary" : "outline"} className="w-20 justify-center">
                        {p.status === "completed" ? "Done" : p.status === "running" ? "..." : "Pending"}
                      </Badge>
                      <span>{p.name.replace(/_/g, ' ')}</span>
                      {p.duration && <span className="text-xs text-muted-foreground ml-auto">{p.duration}</span>}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
           ))}
        </TabsContent>
      </Tabs>
    </div>
  );
}
