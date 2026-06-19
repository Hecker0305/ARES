import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface PacketTemplate {
  id: string;
  name: string;
  protocol: string;
  description: string;
  raw_hex: string;
  options: Record<string, string>;
}

interface InjectionResult {
  id: string;
  template_id: string;
  template_name: string;
  target: string;
  packets_sent: number;
  bytes_sent: number;
  duration: string;
  status: string;
  started_at: string;
  completed_at: string;
  error: string;
}

interface MITMRelay {
  id: string;
  listen_addr: string;
  target_addr: string;
  protocol: string;
  status: string;
}

export function PacketInjectionPage() {
  const [templates, setTemplates] = useState<PacketTemplate[]>([]);
  const [results, setResults] = useState<InjectionResult[]>([]);
  const [relays, setRelays] = useState<MITMRelay[]>([]);
  const [target, setTarget] = useState("");
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch("/api/packet/templates").then(r => r.ok ? r.json() : []),
      fetch("/api/packet/results").then(r => r.ok ? r.json() : []),
      fetch("/api/packet/mitm").then(r => r.ok ? r.json() : []),
    ]).then(([t, r, m]) => { setTemplates(t || []); setResults(r || []); setRelays(m || []); }).finally(() => setLoading(false));
  }, []);

  async function inject(templateId: string) {
    if (!target) return;
    const r = await fetch("/api/packet/inject", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ template_id: templateId, target }),
    });
    if (r.ok) {
      const result = await r.json();
      setResults(prev => [result, ...prev]);
    }
  }

  async function startMITM() {
    const r = await fetch("/api/packet/mitm/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ listen_addr: "0.0.0.0:8080", target_addr: target }),
    });
    if (r.ok) {
      const relay = await r.json();
      setRelays(prev => [...prev, relay]);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div><h1 className="text-2xl font-bold">Packet Injection</h1>
        <p className="text-muted-foreground">Scapy-based packet injection and MITM relay framework</p></div>
      </div>

      <div className="flex items-center gap-4">
        <Input placeholder="Target IP:Port" value={target} onChange={e => setTarget(e.target.value)} className="w-64" />
      </div>

      <Tabs defaultValue="templates">
        <TabsList>
          <TabsTrigger value="templates">Templates</TabsTrigger>
          <TabsTrigger value="results">Results</TabsTrigger>
          <TabsTrigger value="mitm">MITM Relays</TabsTrigger>
        </TabsList>

        <TabsContent value="templates">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {templates.map(t => (
              <Card key={t.id}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm">{t.name}</CardTitle>
                    <Badge>{t.protocol}</Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <p className="text-muted-foreground text-xs">{t.description}</p>
                  <Button size="sm" className="w-full" disabled={!target} onClick={() => inject(t.id)}>
                    Inject
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="results">
          {results.length === 0 ? <p className="text-muted-foreground">No injection results yet.</p> :
           results.map(r => (
            <Card key={r.id}>
              <CardContent className="pt-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{r.template_name}</span>
                      <Badge variant={r.status === "completed" ? "default" : "destructive"}>{r.status}</Badge>
                    </div>
                    <div className="text-sm text-muted-foreground">Target: {r.target}</div>
                  </div>
                  <div className="text-right text-sm">
                    <div>{r.packets_sent} packets</div>
                    <div className="text-muted-foreground">{(r.bytes_sent / 1024).toFixed(1)} KB</div>
                    <div className="text-muted-foreground">{r.duration}</div>
                  </div>
                </div>
              </CardContent>
            </Card>
           ))}
        </TabsContent>

        <TabsContent value="mitm">
          <div className="space-y-4">
            <Button onClick={startMITM} disabled={!target}>Start MITM Relay</Button>
            {relays.map(r => (
              <Card key={r.id}>
                <CardContent className="pt-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="font-medium">{r.listen_addr}</span>
                      <Badge className="ml-2" variant={r.status === "running" ? "default" : "secondary"}>{r.status}</Badge>
                    </div>
                    <div className="text-sm text-muted-foreground">→ {r.target_addr} ({r.protocol})</div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
