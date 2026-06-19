import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useScanPresets, useStartScan } from "@/api/queries";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, severityDot, severityBg } from "@/lib/utils";
import { useScanCount } from "@/lib/scan-counter";
import { Target, Globe, Search, Check, Upload, Image, KeyRound } from "lucide-react";

export function NewScanPage() {
  const navigate = useNavigate();
  const { data: presets, isLoading } = useScanPresets();
  const startScan = useStartScan();
  const scanCount = useScanCount();
  const logoInputRef = useRef<HTMLInputElement>(null);

  const [targets, setTargets] = useState("");
  const [scanMode, setScanMode] = useState("single");
  const [selectedPhases, setSelectedPhases] = useState<number[]>([]);
  const [preset, setPreset] = useState("none");
  const [instruction, setInstruction] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [workers, setWorkers] = useState(4);
  const [authorized, setAuthorized] = useState(false);
  const [logoFile, setLogoFile] = useState<File | null>(null);
  const [displayName, setDisplayName] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string[]>([
    "info",
    "low",
    "medium",
    "high",
    "critical",
  ]);
  const [model, setModel] = useState("server-default");
  const [modelCustom, setModelCustom] = useState("");

  const phases = presets?.phases || [];
  const severityLevels = ["info", "low", "medium", "high", "critical"];

  const togglePhase = (id: number) => {
    setSelectedPhases((prev) =>
      prev.includes(id) ? prev.filter((p) => p !== id) : [...prev, id],
    );
  };

  const selectAllPhases = () => {
    setSelectedPhases(phases.map((p) => p.id));
  };

  const clearPhases = () => {
    setSelectedPhases([]);
  };

  const handlePresetChange = (value: string) => {
    setPreset(value);
    const found = presets?.presets.find((p) => p.name === value);
    if (found) {
      setSelectedPhases(found.phases.map((_, i) => i + 1));
      setScanMode(found.scan_mode);
    }
  };

  const toggleSeverity = (sev: string) => {
    setSeverityFilter((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev],
    );
  };

  const handleSubmit = async () => {
    if (!targets.trim() || !authorized) return;
    if (scanCount.exhausted) return;

    const targetList = targets
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter(Boolean);

    let logoPath: string | undefined;
    if (logoFile) {
      const result = await api.uploadLogo(logoFile);
      logoPath = result.path;
    }

    const resolvedModel =
      model === "server-default"
        ? undefined
        : model === "custom"
          ? modelCustom || undefined
          : model;

    await startScan.mutateAsync({
      target: targetList[0],
      targets: targetList,
      preset,
      scanMode,
      phases: selectedPhases.map((p) => phases.find((ph) => ph.id === p)?.name || ""),
      workers,
      severityFilter,
      model: resolvedModel,
      displayName: displayName || undefined,
      companyName: companyName || undefined,
      logoPath,
    });

    scanCount.decrement();
    navigate("/scans");
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <Skeleton className="h-8 w-48" />
        <div className="grid gap-4 md:grid-cols-2">
          <Skeleton className="h-48 rounded-lg" />
          <Skeleton className="h-48 rounded-lg" />
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold">New Scan</h1>
        <p className="text-muted-foreground mt-1">Configure and launch a new security scan.</p>
      </div>

      {scanCount.exhausted && (
        <div className="flex items-center gap-3 rounded-lg border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          <KeyRound className="h-4 w-4 shrink-0" />
          <span>Scan limit reached ({scanCount.max} / {scanCount.max}). Contact admin to reset.</span>
        </div>
      )}

      {!scanCount.exhausted && scanCount.remaining <= 3 && (
        <div className="flex items-center gap-3 rounded-lg border border-amber-500/40 bg-amber-500/5 px-4 py-3 text-sm text-amber-600">
          <KeyRound className="h-4 w-4 shrink-0" />
          <span>{scanCount.remaining} scan{scanCount.remaining !== 1 ? "s" : ""} remaining</span>
        </div>
      )}

      {/* Targets */}
      <Card>
        <CardHeader>
          <CardTitle>Targets</CardTitle>
          <CardDescription>Enter one target per line or comma-separated.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            placeholder="https://example.com&#10;https://api.example.com&#10;192.168.1.1"
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            className="min-h-24 font-mono text-sm"
          />
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm">
              <Upload className="h-3.5 w-3.5" />
              Upload targets
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Scan Mode */}
      <Card>
        <CardHeader>
          <CardTitle>Scan Mode</CardTitle>
          <CardDescription>Choose the testing approach.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-3">
            {[
              { id: "single", icon: Target, name: "Single Target", desc: "Test one URL or host" },
              { id: "dast", icon: Globe, name: "DAST", desc: "Browser-assisted dynamic testing" },
              { id: "wildcard", icon: Search, name: "Wildcard / Multi", desc: "Subdomain enumeration + testing" },
            ].map((mode) => (
              <button
                key={mode.id}
                onClick={() => setScanMode(mode.id)}
                className={cn(
                  "flex flex-col items-start gap-3 rounded-lg border p-4 text-left transition-colors",
                  scanMode === mode.id
                    ? "border-primary bg-primary/5"
                    : "border-border hover:bg-muted/50",
                )}
              >
                <mode.icon className="h-5 w-5" />
                <div>
                  <p className="font-medium">{mode.name}</p>
                  <p className="text-xs text-muted-foreground">{mode.desc}</p>
                </div>
                {scanMode === mode.id && <Check className="ml-auto h-4 w-4 text-primary" />}
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Presets & Phases */}
      <Card>
        <CardHeader>
          <CardTitle>Methodology</CardTitle>
          <CardDescription>Select phases or use a preset.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-3">
            <Label>Preset</Label>
            <Select value={preset} onValueChange={handlePresetChange}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="None" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">None (custom)</SelectItem>
                {presets?.presets.map((p) => (
                  <SelectItem key={p.name} value={p.name}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <div className="flex gap-2 ml-auto">
              <Button variant="outline" size="sm" onClick={selectAllPhases}>
                Select all
              </Button>
              <Button variant="outline" size="sm" onClick={clearPhases}>
                Clear
              </Button>
            </div>
          </div>
          <Separator />
          <div className="grid gap-2 md:grid-cols-2">
            {phases.map((phase) => (
              <label
                key={phase.id}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 cursor-pointer transition-colors",
                  selectedPhases.includes(phase.id) ? "bg-primary/5" : "hover:bg-muted/50",
                )}
              >
                <input
                  type="checkbox"
                  checked={selectedPhases.includes(phase.id)}
                  onChange={() => togglePhase(phase.id)}
                  className="rounded border-input"
                />
                <span className="text-sm">
                  <span className="text-muted-foreground mr-1">{phase.id}.</span>
                  {phase.name}
                </span>
              </label>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Severity Filter */}
      <Card>
        <CardHeader>
          <CardTitle>Severity Filter</CardTitle>
          <CardDescription>Only include findings matching selected severities. Toggle chips to filter.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {severityLevels.map((sev) => (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors",
                  severityFilter.includes(sev)
                    ? severityBg(sev)
                    : "bg-muted text-muted-foreground hover:bg-muted/80",
                )}
              >
                <span className={cn("h-2 w-2 rounded-full", severityDot(sev))} />
                {sev.charAt(0).toUpperCase() + sev.slice(1)}
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Configuration */}
      <Card>
        <CardHeader>
          <CardTitle>Configuration</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>Display Name</Label>
              <Input
                placeholder="e.g. Q3 Production Scan / auto-generated"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Workers</Label>
              <Input
                type="number"
                min={1}
                max={16}
                value={workers}
                onChange={(e) => setWorkers(parseInt(e.target.value) || 1)}
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label>Custom Instructions</Label>
            <Textarea
              placeholder="Focus on SQL injection, IDOR, and auth bypass. Avoid destructive tests."
              value={instruction}
              onChange={(e) => setInstruction(e.target.value)}
              className="min-h-20"
            />
          </div>
        </CardContent>
      </Card>

      {/* Report Branding */}
      <Card>
        <CardHeader>
          <CardTitle>Report Branding</CardTitle>
          <CardDescription>Customise scan report appearance.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>Company Name</Label>
              <Input
                placeholder="Acme Corp"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Company Logo</Label>
              <div className="flex items-center gap-3">
                <Button
                  variant="outline"
                  size="sm"
                  type="button"
                  onClick={() => logoInputRef.current?.click()}
                >
                  <Upload className="h-3.5 w-3.5 mr-1" />
                  {logoFile ? "Change logo" : "Upload logo"}
                </Button>
                {logoFile && (
                  <span className="text-xs text-muted-foreground truncate max-w-32">
                    {logoFile.name}
                  </span>
                )}
                <input
                  ref={logoInputRef}
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) setLogoFile(file);
                    if (e.target) e.target.value = "";
                  }}
                />
              </div>
              {logoFile ? (
                <div className="mt-2 rounded-md border p-2 inline-flex items-center gap-2">
                  <img
                    src={URL.createObjectURL(logoFile)}
                    alt="Logo preview"
                    className="h-10 w-auto object-contain"
                  />
                  <span className="text-xs text-muted-foreground">Preview</span>
                </div>
              ) : (
                <div className="mt-2 rounded-md border border-dashed p-3 inline-flex items-center gap-2 text-muted-foreground">
                  <Image className="h-5 w-5" />
                  <span className="text-xs">No logo selected</span>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Model Override */}
      <Card>
        <CardHeader>
          <CardTitle>Model Override</CardTitle>
          <CardDescription>Override the default LLM model used for this scan.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Select value={model} onValueChange={setModel}>
            <SelectTrigger className="w-full">
              <SelectValue placeholder="Server default" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="server-default">Server default</SelectItem>
              <SelectItem value="openai/gpt-5">OpenAI GPT-5</SelectItem>
              <SelectItem value="openai/gpt-5-mini">OpenAI GPT-5 Mini</SelectItem>
              <SelectItem value="anthropic/claude-opus-4.6">Anthropic Claude Opus 4.6</SelectItem>
              <SelectItem value="google/gemini-3-flash">Google Gemini 3 Flash</SelectItem>
              <SelectItem value="custom">Custom model...</SelectItem>
            </SelectContent>
          </Select>
          {model === "custom" && (
            <Input
              placeholder="Enter model identifier"
              value={modelCustom}
              onChange={(e) => setModelCustom(e.target.value)}
            />
          )}
        </CardContent>
      </Card>

      {/* Authorization */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center gap-3">
            <Switch checked={authorized} onCheckedChange={setAuthorized} id="auth" />
            <Label htmlFor="auth" className="cursor-pointer">
              I have explicit authorization to test these targets.
            </Label>
          </div>
        </CardContent>
      </Card>

      {/* Actions */}
      <div className="flex justify-end gap-3">
        <Button variant="outline" onClick={() => navigate("/scans")}>
          Cancel
        </Button>
        <Button
          onClick={handleSubmit}
          disabled={!targets.trim() || !authorized || startScan.isPending}
        >
          {startScan.isPending ? "Starting..." : "Start Scan"}
        </Button>
      </div>
    </div>
  );
}
