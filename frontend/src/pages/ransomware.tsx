import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface RansomwareFamily {
  name: string;
  aliases: string[];
  first_seen: string;
  last_seen: string;
  type: string;
  platform: string;
  extensions: string[];
  ransom_note: string;
  ransom_amount: string;
  wallet_addresses: string[];
  decryptor_available: boolean;
  decryptor_url: string;
  cve: string[];
  iocs: { type: string; value: string; context: string }[];
}

interface Report {
  id: string;
  sample_hash: string;
  family: string;
  confidence: number;
  detected_extensions: string[];
  matched_patterns: string[];
  ransom_note_text: string;
}

export function RansomwarePage() {
  const [families, setFamilies] = useState<RansomwareFamily[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch("/api/ransomware/families").then(r => r.ok ? r.json() : []),
      fetch("/api/ransomware/reports").then(r => r.ok ? r.json() : []),
    ]).then(([f, r]) => { setFamilies(f || []); setReports(r || []); }).finally(() => setLoading(false));
  }, []);

  async function runAnalysis() {
    const r = await fetch("/api/ransomware/analyze", { method: "POST" });
    if (r.ok) {
      const data = await r.json();
      setReports(prev => [...prev, data]);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div><h1 className="text-2xl font-bold">Ransomware Analysis</h1>
        <p className="text-muted-foreground">Family identification, IOCs, and decryptor lookup</p></div>
        <Button onClick={runAnalysis}>Run Analysis</Button>
      </div>

      <Tabs defaultValue="families">
        <TabsList>
          <TabsTrigger value="families">Families</TabsTrigger>
          <TabsTrigger value="reports">Analysis Reports</TabsTrigger>
          <TabsTrigger value="decryptors">Decryptors</TabsTrigger>
        </TabsList>

        <TabsContent value="families">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {loading ? <p>Loading...</p> :
             families.map(f => (
              <Card key={f.name}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg">{f.name}</CardTitle>
                    <Badge variant={f.decryptor_available ? "default" : "destructive"}>
                      {f.decryptor_available ? "Decryptor Available" : "No Decryptor"}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  <div className="grid grid-cols-2 gap-2">
                    <div><span className="text-muted-foreground">Type:</span> {f.type}</div>
                    <div><span className="text-muted-foreground">Platform:</span> {f.platform}</div>
                    <div><span className="text-muted-foreground">First Seen:</span> {f.first_seen}</div>
                    <div><span className="text-muted-foreground">Last Seen:</span> {f.last_seen}</div>
                    <div><span className="text-muted-foreground">Ransom:</span> {f.ransom_amount || "Unknown"}</div>
                  </div>
                  {f.extensions?.length > 0 && (
                    <div>
                      <span className="text-muted-foreground">Extensions:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {f.extensions.map(ext => <Badge key={ext} variant="outline">{ext}</Badge>)}
                      </div>
                    </div>
                  )}
                  {f.aliases?.length > 0 && (
                    <div><span className="text-muted-foreground">Aliases:</span> {f.aliases.join(", ")}</div>
                  )}
                  {f.wallet_addresses?.length > 0 && (
                    <div>
                      <span className="text-muted-foreground">Wallets:</span>
                      <div className="font-mono text-xs mt-1 space-y-0.5">
                        {f.wallet_addresses.map(w => <div key={w} className="truncate">{w}</div>)}
                      </div>
                    </div>
                  )}
                  {f.iocs?.length > 0 && (
                    <div>
                      <span className="text-muted-foreground">IOCs:</span>
                      <div className="mt-1 space-y-0.5">
                        {f.iocs.slice(0, 5).map((ioc, i) => (
                          <div key={i} className="flex items-center gap-2 font-mono text-xs">
                            <Badge variant="outline" className="text-[10px]">{ioc.type}</Badge>
                            <span className="truncate">{ioc.value}</span>
                          </div>
                        ))}
                        {f.iocs.length > 5 && <div className="text-xs text-muted-foreground">...and {f.iocs.length - 5} more</div>}
                      </div>
                    </div>
                  )}
                  {f.decryptor_available && (
                    <Button variant="outline" size="sm" className="w-full" onClick={() => window.open(f.decryptor_url, "_blank")}>
                      Download Decryptor
                    </Button>
                  )}
                </CardContent>
              </Card>
             ))}
          </div>
        </TabsContent>

        <TabsContent value="reports">
          {reports.length === 0 ? <p className="text-muted-foreground">No analysis reports yet. Run an analysis to begin.</p> :
           reports.map(r => (
            <Card key={r.id}>
              <CardContent className="pt-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-medium">{r.family}</span>
                    <Badge>{(r.confidence * 100).toFixed(0)}% confidence</Badge>
                  </div>
                </div>
                <div className="text-sm text-muted-foreground">
                  Sample: {r.sample_hash?.slice(0, 16)}... | {r.detected_extensions?.join(", ")}
                </div>
              </CardContent>
            </Card>
           ))}
        </TabsContent>

        <TabsContent value="decryptors">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {families.filter(f => f.decryptor_available).map(f => (
              <Card key={f.name}>
                <CardHeader><CardTitle className="text-lg">{f.name}</CardTitle></CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <p>Decryptor available via NoMoreRansom.</p>
                  <Button variant="default" className="w-full" onClick={() => window.open(f.decryptor_url, "_blank")}>
                    Get Decryptor
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
