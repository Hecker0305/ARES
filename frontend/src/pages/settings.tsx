import { useState, useEffect } from "react";
import {
  useSettings, useSaveSettings, useLLMSettings, useSaveLLMSettings,
  useWebhookSettings, useSaveWebhookSettings, useTestWebhook,
  useEnvironmentSettings, useSaveEnvironmentSettings,
  useTeam, useInviteTeamMember, useScope, useAddScope, useDeleteScope,
  useRateLimitSettings, useSaveRateLimitSettings,
  useDiscordSettings, useSaveDiscordSettings,
  useAgentMailSettings, useSaveAgentMailSettings,
} from "@/api/queries";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Plus, Trash2, Send, Eye, EyeOff, Search, Shield, Wrench } from "lucide-react";

/* eslint-disable react-hooks/set-state-in-effect */

export function SettingsPage() {
  const [tab, setTab] = useState("general");
  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="llm">LLM</TabsTrigger>
          <TabsTrigger value="webhooks">Webhooks</TabsTrigger>
          <TabsTrigger value="discord">Discord</TabsTrigger>
          <TabsTrigger value="ratelimit">Rate Limits</TabsTrigger>
          <TabsTrigger value="agentmail">AgentMail</TabsTrigger>
          <TabsTrigger value="scope">Scope</TabsTrigger>
          <TabsTrigger value="team">Team</TabsTrigger>
          <TabsTrigger value="env">Env Vars</TabsTrigger>
          <TabsTrigger value="account">Account</TabsTrigger>
        </TabsList>
        <TabsContent value="general" className="mt-4"><GeneralSettingsTab /></TabsContent>
        <TabsContent value="llm" className="mt-4"><LLMSettingsTab /></TabsContent>
        <TabsContent value="webhooks" className="mt-4"><WebhookSettingsTab /></TabsContent>
        <TabsContent value="discord" className="mt-4"><DiscordSettingsTab /></TabsContent>
        <TabsContent value="ratelimit" className="mt-4"><RateLimitSettingsTab /></TabsContent>
        <TabsContent value="agentmail" className="mt-4"><AgentMailSettingsTab /></TabsContent>
        <TabsContent value="scope" className="mt-4"><ScopeTab /></TabsContent>
        <TabsContent value="team" className="mt-4"><TeamTab /></TabsContent>
        <TabsContent value="env" className="mt-4"><EnvVarsTab /></TabsContent>
        <TabsContent value="account" className="mt-4"><AccountTab /></TabsContent>
      </Tabs>
    </div>
  );
}

function GeneralSettingsTab() {
  const { data: settings, isLoading } = useSettings();
  const saveSettings = useSaveSettings();
  const [formData, setFormData] = useState({ instanceName: "", maxWorkers: 4, evidenceRetention: "30d", confidenceGate: 0.7 });
  useEffect(() => {
    if (settings) {
      setFormData({
        instanceName: settings.instanceName || "",
        maxWorkers: settings.maxWorkers || 4,
        evidenceRetention: settings.evidenceRetention || "30d",
        confidenceGate: settings.confidenceGate || 0.7,
      });
    }
  }, [settings]);
  if (isLoading) return <Skeleton className="h-64 rounded-lg" />;
  return (
    <Card><CardHeader><CardTitle>General Settings</CardTitle><CardDescription>Configure instance name, workers, and retention.</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2"><Label>Instance Name</Label><Input value={formData.instanceName} onChange={(e) => setFormData({ ...formData, instanceName: e.target.value })} /></div>
          <div className="space-y-2"><Label>Max Workers</Label><Input type="number" min={1} max={16} value={formData.maxWorkers} onChange={(e) => setFormData({ ...formData, maxWorkers: parseInt(e.target.value) || 1 })} /></div>
          <div className="space-y-2"><Label>Evidence Retention</Label><Input value={formData.evidenceRetention} onChange={(e) => setFormData({ ...formData, evidenceRetention: e.target.value })} placeholder="30d" /></div>
          <div className="space-y-2"><Label>Confidence Gate (0-1)</Label><Input type="number" min={0} max={1} step={0.1} value={formData.confidenceGate} onChange={(e) => setFormData({ ...formData, confidenceGate: parseFloat(e.target.value) || 0 })} /></div>
        </div>
        <Button onClick={() => saveSettings.mutate(formData)} disabled={saveSettings.isPending}>{saveSettings.isPending ? "Saving..." : "Save"}</Button>
      </CardContent>
    </Card>
  );
}

function LLMSettingsTab() {
  const { data: settings, isLoading } = useLLMSettings();
  const saveLLM = useSaveLLMSettings();
  const { data: env } = useEnvironmentSettings();
  const saveEnv = useSaveEnvironmentSettings();
  const [formData, setFormData] = useState({ provider: "", model: "", baseURL: "" });
  const [extended, setExtended] = useState({ apiKey: "", reasoningEffort: "medium", llmMaxRetries: 3, memoryCompressorTimeout: 60, maxIterations: 50, geminiSearchKey: "" });
  const [showApiKey, setShowApiKey] = useState(false);
  const [showGeminiKey, setShowGeminiKey] = useState(false);
  useEffect(() => {
    if (settings) {
      setFormData({ provider: settings.provider || "", model: settings.model || "", baseURL: settings.baseURL || "" });
    }
    if (env) setExtended({
      apiKey: env["LLM_API_KEY"] || "",
      reasoningEffort: env["REASONING_EFFORT"] || "medium",
      llmMaxRetries: parseInt(env["LLM_MAX_RETRIES"]) || 3,
      memoryCompressorTimeout: parseInt(env["MEMORY_COMPRESSOR_TIMEOUT"]) || 60,
      maxIterations: parseInt(env["MAX_ITERATIONS"]) || 50,
      geminiSearchKey: env["GEMINI_SEARCH_KEY"] || "",
    });
  }, [settings, env]);
  const handleSave = async () => {
    await saveLLM.mutateAsync(formData);
    const envPatch: Record<string, string> = { ...env };
    envPatch["LLM_API_KEY"] = extended.apiKey;
    envPatch["REASONING_EFFORT"] = extended.reasoningEffort;
    envPatch["LLM_MAX_RETRIES"] = String(extended.llmMaxRetries);
    envPatch["MEMORY_COMPRESSOR_TIMEOUT"] = String(extended.memoryCompressorTimeout);
    envPatch["MAX_ITERATIONS"] = String(extended.maxIterations);
    envPatch["GEMINI_SEARCH_KEY"] = extended.geminiSearchKey;
    await saveEnv.mutateAsync(envPatch);
  };
  if (isLoading) return <Skeleton className="h-64 rounded-lg" />;
  return (
    <Card><CardHeader><CardTitle>LLM Configuration</CardTitle><CardDescription>Configure the AI model provider and extended settings.</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2"><Label>Provider</Label><Select value={formData.provider} onValueChange={(v) => setFormData({ ...formData, provider: v })}><SelectTrigger><SelectValue placeholder="Select provider" /></SelectTrigger><SelectContent><SelectItem value="ollama">Ollama (Local)</SelectItem><SelectItem value="openai">OpenAI</SelectItem><SelectItem value="anthropic">Anthropic</SelectItem><SelectItem value="google">Google Gemini</SelectItem><SelectItem value="deepseek">DeepSeek</SelectItem><SelectItem value="groq">Groq</SelectItem><SelectItem value="custom">Custom</SelectItem></SelectContent></Select></div>
          <div className="space-y-2"><Label>Model</Label><Input value={formData.model} onChange={(e) => setFormData({ ...formData, model: e.target.value })} placeholder="llama3.1" /></div>
          <div className="space-y-2"><Label>Base URL</Label><Input value={formData.baseURL} onChange={(e) => setFormData({ ...formData, baseURL: e.target.value })} placeholder="http://localhost:11434" /></div>
          <div className="space-y-2"><Label>API Key</Label><div className="relative"><Input type={showApiKey ? "text" : "password"} value={extended.apiKey} onChange={(e) => setExtended({ ...extended, apiKey: e.target.value })} placeholder="sk-..." /><button type="button" onClick={() => setShowApiKey(!showApiKey)} className="absolute right-2 top-2 text-muted-foreground">{showApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button></div></div>
          <div className="space-y-2"><Label>Reasoning Effort</Label><Select value={extended.reasoningEffort} onValueChange={(v) => setExtended({ ...extended, reasoningEffort: v })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="low">Low</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="xhigh">Extra High</SelectItem></SelectContent></Select></div>
          <div className="space-y-2"><Label>LLM Max Retries</Label><Input type="number" min={0} max={20} value={extended.llmMaxRetries} onChange={(e) => setExtended({ ...extended, llmMaxRetries: parseInt(e.target.value) || 0 })} /></div>
          <div className="space-y-2"><Label>Memory Compressor Timeout (s)</Label><Input type="number" min={5} max={600} value={extended.memoryCompressorTimeout} onChange={(e) => setExtended({ ...extended, memoryCompressorTimeout: parseInt(e.target.value) || 5 })} /></div>
          <div className="space-y-2"><Label>Max Iterations</Label><Input type="number" min={0} max={1000} value={extended.maxIterations} onChange={(e) => setExtended({ ...extended, maxIterations: parseInt(e.target.value) || 0 })} /></div>
          <div className="space-y-2 md:col-span-2"><Label>Gemini Search Key</Label><div className="relative"><Input type={showGeminiKey ? "text" : "password"} value={extended.geminiSearchKey} onChange={(e) => setExtended({ ...extended, geminiSearchKey: e.target.value })} placeholder="AIza..." /><button type="button" onClick={() => setShowGeminiKey(!showGeminiKey)} className="absolute right-2 top-2 text-muted-foreground">{showGeminiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button></div></div>
        </div>
        <Button onClick={handleSave} disabled={saveLLM.isPending || saveEnv.isPending}>{saveLLM.isPending || saveEnv.isPending ? "Saving..." : "Save"}</Button>
      </CardContent>
    </Card>
  );
}

function WebhookSettingsTab() {
  const { data: settings, isLoading } = useWebhookSettings();
  const saveWebhook = useSaveWebhookSettings();
  const testWebhook = useTestWebhook();
  const [formData, setFormData] = useState({ url: "", secret: "", events: [] as string[] });
  const [showSecret, setShowSecret] = useState(false);
  useEffect(() => {
    if (settings) {
      setFormData({ url: settings.url || "", secret: settings.secret || "", events: settings.events || [] });
    }
  }, [settings]);
  const webhookEvents = ["scan_complete", "vuln_found", "scan_failed", "report_ready"];
  const toggleEvent = (event: string) => { setFormData((prev) => ({ ...prev, events: prev.events.includes(event) ? prev.events.filter((e) => e !== event) : [...prev.events, event] })); };
  if (isLoading) return <Skeleton className="h-64 rounded-lg" />;
  return (
    <Card><CardHeader><CardTitle>Webhook Notifications</CardTitle><CardDescription>Configure webhook alerts for scan events.</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2"><Label>Webhook URL</Label><Input value={formData.url} onChange={(e) => setFormData({ ...formData, url: e.target.value })} placeholder="https://hooks.slack.com/services/..." /></div>
        <div className="space-y-2"><Label>Secret (HMAC-SHA256)</Label><div className="relative"><Input type={showSecret ? "text" : "password"} value={formData.secret} onChange={(e) => setFormData({ ...formData, secret: e.target.value })} placeholder="whsec_..." /><button type="button" onClick={() => setShowSecret(!showSecret)} className="absolute right-2 top-2 text-muted-foreground">{showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button></div></div>
        <div className="space-y-2"><Label>Events</Label><div className="flex flex-wrap gap-2">{webhookEvents.map((event) => (<button key={event} onClick={() => toggleEvent(event)} className={`rounded-md px-3 py-1.5 text-sm transition-colors ${formData.events.includes(event) ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground hover:bg-muted/80"}`}>{event}</button>))}</div></div>
        <div className="flex gap-2"><Button onClick={() => saveWebhook.mutate(formData)} disabled={saveWebhook.isPending}>{saveWebhook.isPending ? "Saving..." : "Save"}</Button><Button variant="outline" onClick={() => testWebhook.mutate()} disabled={testWebhook.isPending || !formData.url}><Send className="h-3.5 w-3.5" />Test</Button></div>
      </CardContent>
    </Card>
  );
}

function DiscordSettingsTab() {
  const { data: settings, isLoading } = useDiscordSettings();
  const saveDiscord = useSaveDiscordSettings();
  const testWebhook = useTestWebhook();
  const [formData, setFormData] = useState({ webhookUrl: "", minimumSeverity: "medium" });
  const [showUrl, setShowUrl] = useState(false);
  useEffect(() => {
    if (settings) {
      setFormData({ webhookUrl: settings.webhookUrl || "", minimumSeverity: settings.minimumSeverity || "medium" });
    }
  }, [settings]);
  if (isLoading) return <Skeleton className="h-64 rounded-lg" />;
  return (
    <Card><CardHeader><CardTitle>Discord Notifications</CardTitle><CardDescription>Configure Discord webhook for scan notifications.</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2"><Label>Webhook URL</Label><div className="relative"><Input type={showUrl ? "text" : "password"} value={formData.webhookUrl} onChange={(e) => setFormData({ ...formData, webhookUrl: e.target.value })} placeholder="https://discord.com/api/webhooks/..." /><button type="button" onClick={() => setShowUrl(!showUrl)} className="absolute right-2 top-2 text-muted-foreground">{showUrl ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button></div></div>
        <div className="space-y-2"><Label>Minimum Severity</Label><Select value={formData.minimumSeverity} onValueChange={(v) => setFormData({ ...formData, minimumSeverity: v })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="info">Info</SelectItem><SelectItem value="low">Low</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="critical">Critical</SelectItem></SelectContent></Select></div>
        <div className="flex gap-2"><Button onClick={() => saveDiscord.mutate(formData)} disabled={saveDiscord.isPending}>{saveDiscord.isPending ? "Saving..." : "Save"}</Button><Button variant="outline" onClick={() => testWebhook.mutate()} disabled={testWebhook.isPending || !formData.webhookUrl}><Send className="h-3.5 w-3.5" />Test</Button></div>
      </CardContent>
    </Card>
  );
}

function RateLimitSettingsTab() {
  const { data: settings, isLoading } = useRateLimitSettings();
  const saveRateLimit = useSaveRateLimitSettings();
  const [formData, setFormData] = useState({ requestsPerWindow: 100, windowSeconds: 60 });
  useEffect(() => {
    if (settings) {
      setFormData({ requestsPerWindow: settings.requestsPerWindow || 100, windowSeconds: settings.windowSeconds || 60 });
    }
  }, [settings]);
  if (isLoading) return <Skeleton className="h-64 rounded-lg" />;
  return (
    <Card><CardHeader><CardTitle>Rate Limits</CardTitle><CardDescription>Configure API rate limiting settings.</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2"><Label>Requests Per Window</Label><Input type="number" min={1} max={1000} value={formData.requestsPerWindow} onChange={(e) => setFormData({ ...formData, requestsPerWindow: parseInt(e.target.value) || 1 })} /></div>
          <div className="space-y-2"><Label>Window (Seconds)</Label><Input type="number" min={1} max={600} value={formData.windowSeconds} onChange={(e) => setFormData({ ...formData, windowSeconds: parseInt(e.target.value) || 1 })} /></div>
        </div>
        <Button onClick={() => saveRateLimit.mutate(formData)} disabled={saveRateLimit.isPending}>{saveRateLimit.isPending ? "Saving..." : "Save"}</Button>
      </CardContent>
    </Card>
  );
}

function AgentMailSettingsTab() {
  const { data: settings, isLoading } = useAgentMailSettings();
  const saveAgentMail = useSaveAgentMailSettings();
  const [formData, setFormData] = useState({ pod: "", apiKey: "" });
  const [showKey, setShowKey] = useState(false);
  useEffect(() => {
    if (settings) {
      setFormData({ pod: settings.pod || "", apiKey: settings.hasApiKey ? "" : (settings.apiKey || "") });
    }
  }, [settings]);
  if (isLoading) return <Skeleton className="h-64 rounded-lg" />;
  return (
    <Card><CardHeader><CardTitle>AgentMail</CardTitle><CardDescription>Email-based reporting channel configuration.</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2"><Label>Pod Name</Label><Input value={formData.pod} onChange={(e) => setFormData({ ...formData, pod: e.target.value })} placeholder="my-pod" /></div>
          <div className="space-y-2"><Label>API Key</Label><div className="relative"><Input type={showKey ? "text" : "password"} value={formData.apiKey} onChange={(e) => setFormData({ ...formData, apiKey: e.target.value })} placeholder="amk_..." /><button type="button" onClick={() => setShowKey(!showKey)} className="absolute right-2 top-2 text-muted-foreground">{showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button></div></div>
        </div>
        <Button onClick={() => saveAgentMail.mutate(formData)} disabled={saveAgentMail.isPending}>{saveAgentMail.isPending ? "Saving..." : "Save"}</Button>
      </CardContent>
    </Card>
  );
}

function ScopeTab() {
  const { data: scope, isLoading } = useScope();
  const addScope = useAddScope();
  const deleteScope = useDeleteScope();
  const [target, setTarget] = useState("");
  const [tags, setTags] = useState("");
  const handleAdd = async () => { if (!target.trim()) return; await addScope.mutateAsync({ target: target.trim(), tags: tags.split(",").map((t) => t.trim()).filter(Boolean) }); setTarget(""); setTags(""); };
  if (isLoading) return <Skeleton className="h-64 rounded-lg" />;
  return (
    <Card><CardHeader><CardTitle>Authorized Scope</CardTitle><CardDescription>Define targets authorized for testing.</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-3"><Input placeholder="Target (e.g., *.example.com)" value={target} onChange={(e) => setTarget(e.target.value)} /><Input placeholder="Tags (comma-separated)" value={tags} onChange={(e) => setTags(e.target.value)} /><Button onClick={handleAdd} disabled={addScope.isPending}><Plus className="h-4 w-4" />Add</Button></div>
        <Separator />
        <div className="space-y-2">{scope?.map((entry) => (<div key={entry.id} className="flex items-center justify-between rounded-md border p-3"><div><p className="font-mono text-sm">{entry.target}</p><div className="flex gap-1 mt-1">{entry.tags.map((tag) => (<Badge key={tag} variant="outline" className="text-xs">{tag}</Badge>))}</div></div><Button variant="ghost" size="icon" onClick={() => deleteScope.mutate(entry.id)}><Trash2 className="h-4 w-4" /></Button></div>))}{(!scope || scope.length === 0) && (<p className="text-sm text-muted-foreground py-4">No scope entries defined.</p>)}</div>
      </CardContent>
    </Card>
  );
}

function TeamTab() {
  const { data: team, isLoading } = useTeam();
  const inviteMember = useInviteTeamMember();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("viewer");
  const handleInvite = async () => { if (!email.trim()) return; await inviteMember.mutateAsync({ email: email.trim(), role }); setEmail(""); };
  if (isLoading) return <Skeleton className="h-64 rounded-lg" />;
  return (
    <Card><CardHeader><CardTitle>Team Members</CardTitle><CardDescription>Manage team access.</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-3"><Input type="email" placeholder="Email address" value={email} onChange={(e) => setEmail(e.target.value)} /><Select value={role} onValueChange={setRole}><SelectTrigger className="w-32"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="admin">Admin</SelectItem><SelectItem value="operator">Operator</SelectItem><SelectItem value="viewer">Viewer</SelectItem></SelectContent></Select><Button onClick={handleInvite} disabled={inviteMember.isPending}>Invite</Button></div>
        <Separator />
        <div className="space-y-2">{team?.map((member) => (<div key={member.name} className="flex items-center justify-between rounded-md border p-3"><div><p className="font-medium">{member.name}</p><p className="text-xs text-muted-foreground">Last active: {member.lastActive}</p></div><Badge>{member.role}</Badge></div>))}{(!team || team.length === 0) && (<p className="text-sm text-muted-foreground py-4">No team members.</p>)}</div>
      </CardContent>
    </Card>
  );
}

function getInputType(key: string): "text" | "password" | "url" | "boolean" {
  const upper = key.toUpperCase();
  if (upper.endsWith("_KEY") || upper.endsWith("_SECRET") || upper.endsWith("_PASSWORD") || upper.endsWith("_TOKEN")) return "password";
  if (upper.endsWith("_URL") || upper.endsWith("_URI") || upper.endsWith("_ENDPOINT") || upper.endsWith("_HOST")) return "url";
  if (upper.startsWith("ENABLE_") || upper.startsWith("DISABLE_") || upper.startsWith("FEATURE_") || upper.endsWith("_ENABLED") || upper.endsWith("_DISABLED") || upper === "DEBUG" || upper === "VERBOSE") return "boolean";
  return "text";
}

function inferCategory(key: string): string {
  const prefix = key.split("_")[0]?.toUpperCase() || "OTHER";
  const known: Record<string, string> = {
    LLM: "LLM",
    OPENAI: "LLM",
    ANTHROPIC: "LLM",
    GEMINI: "LLM",
    OLLAMA: "LLM",
    DISCORD: "Notifications",
    WEBHOOK: "Notifications",
    SLACK: "Notifications",
    SMTP: "Mail",
    AGENTMAIL: "Mail",
    MAIL: "Mail",
    DB: "Database",
    DATABASE: "Database",
    POSTGRES: "Database",
    REDIS: "Database",
    MONGO: "Database",
    S3: "Storage",
    STORAGE: "Storage",
    AWS: "Cloud",
    GCP: "Cloud",
    AZURE: "Cloud",
    CLOUD: "Cloud",
    AUTH: "Auth",
    OAUTH: "Auth",
    JWT: "Auth",
    LOG: "Logging",
    LOGGING: "Logging",
    METRICS: "Monitoring",
    MONITOR: "Monitoring",
    PROMETHEUS: "Monitoring",
    GRAFANA: "Monitoring",
    RATE: "Rate Limits",
    RATE_LIMIT: "Rate Limits",
    MEMORY: "Performance",
    CACHE: "Performance",
    PERFORMANCE: "Performance",
    TIMEOUT: "Performance",
    WORKER: "Workers",
    WORKERS: "Workers",
    THREAD: "Workers",
    PROXY: "Network",
    NETWORK: "Network",
    SSL: "Network",
    TLS: "Network",
    CORS: "Network",
  };
  return known[prefix] || "Other";
}

function AccountTab() {
  return (
    <Card><CardHeader><CardTitle>Account</CardTitle><CardDescription>Your authentication status and session details.</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-lg border p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            <span className="font-medium">Authentication Status</span>
            <Badge variant="success">authenticated</Badge>
          </div>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div><span className="text-muted-foreground">Session:</span> <span className="font-medium">Active</span></div>
            <div><span className="text-muted-foreground">Username:</span> <span className="font-medium">admin</span></div>
            <div><span className="text-muted-foreground">Role:</span> <span className="font-medium capitalize">admin</span></div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function EnvVarsTab() {
  const { data: env, isLoading } = useEnvironmentSettings();
  const saveEnv = useSaveEnvironmentSettings();
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [originalData, setOriginalData] = useState<Record<string, string>>({});
  const [searchQuery, setSearchQuery] = useState("");
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});
  useEffect(() => {
    if (env) {
      setFormData({ ...env });
      setOriginalData({ ...env });
    }
  }, [env]);
  const handleChange = (key: string, value: string) => {
    setFormData((prev) => ({ ...prev, [key]: value }));
  };
  const getChangedKeys = () => {
    const changed: string[] = [];
    for (const key of Object.keys(formData)) {
      if (formData[key] !== originalData[key]) changed.push(key);
    }
    return changed;
  };
  const changedKeys = getChangedKeys();
  const filteredEntries = Object.entries(formData).filter(([key]) =>
    key.toLowerCase().includes(searchQuery.toLowerCase())
  );
  const grouped = filteredEntries.reduce<Record<string, [string, string][]>>((acc, [key, value]) => {
    const cat = inferCategory(key);
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push([key, value]);
    return acc;
  }, {});
  const sortedCategories = Object.keys(grouped).sort();
  /* eslint-disable-next-line @typescript-eslint/no-unused-vars */
  const isSecretKey = (key: string) => getInputType(key) === "password";
  const toggleSecret = (key: string) => setShowSecrets((prev) => ({ ...prev, [key]: !prev[key] }));
  if (isLoading) return <Skeleton className="h-64 rounded-lg" />;
  return (
    <Card><CardHeader><CardTitle>Environment Variables</CardTitle><CardDescription>Override configuration via environment variables.</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search environment variables..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 font-mono text-sm"
          />
        </div>
        {changedKeys.length > 0 && (
          <div className="flex items-center gap-2 text-sm text-amber-500">
            <Wrench className="h-4 w-4" />
            <span>{changedKeys.length} unsaved change{changedKeys.length !== 1 ? "s" : ""}</span>
          </div>
        )}
        <div className="space-y-6">
          {sortedCategories.map((category) => (
            <div key={category}>
              <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-2">{category}</h3>
              <div className="space-y-2">
                {grouped[category].map(([key, value]) => {
                  const inputType = getInputType(key);
                  const isSecret = inputType === "password";
                  const isBool = inputType === "boolean";
                  const isChanged = changedKeys.includes(key);
                  return (
                    <div key={key} className="flex items-center gap-3">
                      <div className="min-w-0 flex-1 max-w-56">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-xs truncate block">{key}</span>
                          {isChanged && <Badge variant="outline" className="text-[10px] h-4 px-1 border-amber-500 text-amber-500">edited</Badge>}
                        </div>
                      </div>
                      <div className="flex-1">
                        {isBool ? (
                          <div className="flex items-center gap-2">
                            <Switch
                              checked={value === "true" || value === "1"}
                              onCheckedChange={(checked) => handleChange(key, checked ? "true" : "false")}
                            />
                            <span className="text-xs text-muted-foreground">{value === "true" || value === "1" ? "Enabled" : "Disabled"}</span>
                          </div>
                        ) : (
                          <div className="relative">
                            <Input
                              type={isSecret && !showSecrets[key] ? "password" : "text"}
                              value={value}
                              onChange={(e) => handleChange(key, e.target.value)}
                              className="font-mono text-sm pr-8"
                            />
                            {isSecret && (
                              <button type="button" onClick={() => toggleSecret(key)} className="absolute right-2 top-2 text-muted-foreground">
                                {showSecrets[key] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
        {filteredEntries.length === 0 && (
          <p className="text-sm text-muted-foreground py-4">No environment variables match your search.</p>
        )}
        <div className="flex items-center gap-3 pt-2">
          <Button onClick={() => saveEnv.mutate(formData)} disabled={saveEnv.isPending || changedKeys.length === 0}>
            {saveEnv.isPending ? "Saving..." : "Save All"}
          </Button>
          {changedKeys.length > 0 && (
            <Button variant="outline" onClick={() => setFormData({ ...originalData })}>Reset</Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
