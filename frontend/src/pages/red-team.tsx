import { useState } from "react";
import { useRedTeamPayloads, useStartRedTeamAssessment, useTestRedTeamPayload } from "@/api/queries";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { EmptyState } from "@/components/states";
import { Skeleton } from "@/components/ui/skeleton";
import { Command } from "lucide-react";

export function RedTeamPage() {
  const { data: payloads, isLoading } = useRedTeamPayloads();
  const startAssessment = useStartRedTeamAssessment();
  const testPayload = useTestRedTeamPayload();
  const [targetUrl, setTargetUrl] = useState("");
  const [testPayloadUrl, setTestPayloadUrl] = useState("");
  const [testPayloadContent, setTestPayloadContent] = useState("");
  const [testType, setTestType] = useState("prompt_injection");
  const [testResult, setTestResult] = useState<string | null>(null);

  const handleTest = async () => {
    if (!testPayloadUrl || !testPayloadContent) return;
    const result = await testPayload.mutateAsync({ targetUrl: testPayloadUrl, payload: testPayloadContent, testType });
    setTestResult(JSON.stringify(result, null, 2));
  };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Red Team</h1>
        <p className="text-muted-foreground mt-1">LLM red-teaming with 50+ injection prompts.</p>
      </div>

      <Tabs defaultValue="assess">
        <TabsList>
          <TabsTrigger value="assess">Assessment</TabsTrigger>
          <TabsTrigger value="test">Test Payload</TabsTrigger>
          <TabsTrigger value="library">Payload Library</TabsTrigger>
        </TabsList>

        <TabsContent value="assess" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Command className="h-5 w-5" />
                Start Red Team Assessment
              </CardTitle>
              <CardDescription>Launch an automated LLM red-teaming assessment.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Target URL</Label>
                <Input
                  placeholder="https://llm-app.example.com"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                />
              </div>
              <Button
                onClick={() => startAssessment.mutate({ targetUrl })}
                disabled={startAssessment.isPending || !targetUrl}
              >
                {startAssessment.isPending ? "Starting..." : "Start Assessment"}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="test" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Test Custom Payload</CardTitle>
              <CardDescription>Test a specific payload against a target.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Target URL</Label>
                  <Input
                    value={testPayloadUrl}
                    onChange={(e) => setTestPayloadUrl(e.target.value)}
                    placeholder="https://llm-app.example.com/chat"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Test Type</Label>
                  <select
                    value={testType}
                    onChange={(e) => setTestType(e.target.value)}
                    className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm"
                  >
                    <option value="prompt_injection">Prompt Injection</option>
                    <option value="data_extraction">Data Extraction</option>
                    <option value="jailbreak">Jailbreak</option>
                  </select>
                </div>
              </div>
              <div className="space-y-2">
                <Label>Payload</Label>
                <Textarea
                  value={testPayloadContent}
                  onChange={(e) => setTestPayloadContent(e.target.value)}
                  placeholder="Ignore previous instructions and..."
                  className="min-h-20 font-mono text-sm"
                />
              </div>
              <Button onClick={handleTest} disabled={testPayload.isPending}>
                {testPayload.isPending ? "Testing..." : "Test Payload"}
              </Button>

              {testResult && (
                <div className="mt-4 rounded-lg border p-4">
                  <pre className="text-xs font-mono bg-muted/50 p-3 rounded overflow-x-auto">{testResult}</pre>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="library" className="mt-4">
          {isLoading ? (
            <Skeleton className="h-64 rounded-lg" />
          ) : payloads ? (
            <div className="grid gap-4 md:grid-cols-3">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Prompt Injections</CardTitle>
                  <CardDescription>{payloads.prompt_injections.length} payloads</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {payloads.prompt_injections.slice(0, 10).map((p, i) => (
                      <div key={i} className="rounded border p-2 text-xs font-mono truncate">
                        {p}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Data Extractions</CardTitle>
                  <CardDescription>{payloads.data_extractions.length} payloads</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {payloads.data_extractions.slice(0, 10).map((p, i) => (
                      <div key={i} className="rounded border p-2 text-xs font-mono truncate">
                        {p}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Jailbreaks</CardTitle>
                  <CardDescription>{payloads.jailbreaks.length} payloads</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {payloads.jailbreaks.slice(0, 10).map((p, i) => (
                      <div key={i} className="rounded border p-2 text-xs font-mono truncate">
                        {p}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          ) : (
            <EmptyState title="No payload data" description="Payload library not available." />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
