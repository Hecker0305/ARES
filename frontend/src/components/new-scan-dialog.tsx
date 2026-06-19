import { useState } from "react";
import {
  Dialog,
  DialogTrigger,
  DialogPortal,
  DialogOverlay,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogClose,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useStartScan } from "@/api/queries";
import { toast } from "sonner";
import { cn, severityBg, severityDot } from "@/lib/utils";
import { useScanCount } from "@/lib/scan-counter";
import { Scan, Globe, Asterisk } from "lucide-react";

type ScanMode = "single" | "dast" | "wildcard";
type Severity = "info" | "low" | "medium" | "high" | "critical";

const SCAN_MODES: { value: ScanMode; label: string; icon: typeof Scan }[] = [
  { value: "single", label: "Single", icon: Scan },
  { value: "dast", label: "DAST", icon: Globe },
  { value: "wildcard", label: "Wildcard", icon: Asterisk },
];

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

interface NewScanDialogProps {
  children: React.ReactNode;
  onScanCreated?: () => void;
}

export function NewScanDialog({ children, onScanCreated }: NewScanDialogProps) {
  const [open, setOpen] = useState(false);
  const [targets, setTargets] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [scanMode, setScanMode] = useState<ScanMode>("single");
  const [severityFilter, setSeverityFilter] = useState<Severity[]>(["critical", "high", "medium"]);

  const startScan = useStartScan();
  const scanCount = useScanCount();

  const toggleSeverity = (sev: Severity) => {
    setSeverityFilter((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev],
    );
  };

  const handleSubmit = async () => {
    const trimmed = targets.trim();
    if (!trimmed) {
      toast.error("At least one target is required");
      return;
    }

    if (scanCount.exhausted) {
      toast.error("Scan limit reached. Contact admin to reset.");
      return;
    }

    const targetList = trimmed
      .split("\n")
      .map((t) => t.trim())
      .filter(Boolean);

    try {
      await startScan.mutateAsync({
        target: targetList[0],
        targets: targetList.length > 1 ? targetList : undefined,
        displayName: displayName.trim() || undefined,
        scanMode,
        severityFilter,
      });
      scanCount.decrement();
      toast.success("Scan created successfully");
      onScanCreated?.();
      setOpen(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to create scan");
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{children}</DialogTrigger>
      <DialogPortal>
        <DialogOverlay />
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>New Scan</DialogTitle>
            <DialogDescription>
              Configure and launch a new security scan against your targets.
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-5 py-2">
          <div className="grid gap-2">
            <Label htmlFor="targets">
              Targets
            </Label>
              <Textarea
                id="targets"
                placeholder="example.com&#10;api.example.com&#10;*.example.org"
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                rows={4}
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="displayName">Display name (optional)</Label>
              <Input
                id="displayName"
                placeholder="My Scan"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
            </div>

            <div className="grid gap-2">
              <Label>Scan mode</Label>
              <div className="flex gap-2">
                {SCAN_MODES.map(({ value, label, icon: Icon }) => (
                  <Button
                    key={value}
                    type="button"
                    variant={scanMode === value ? "default" : "outline"}
                    size="sm"
                    className="flex-1"
                    onClick={() => setScanMode(value)}
                  >
                    <Icon className="h-4 w-4" />
                    {label}
                  </Button>
                ))}
              </div>
            </div>

            <div className="grid gap-2">
              <Label>Severity filter</Label>
              <div className="flex flex-wrap gap-2">
                {SEVERITIES.map((sev) => {
                  const active = severityFilter.includes(sev);
                  return (
                    <button
                      key={sev}
                      type="button"
                      onClick={() => toggleSeverity(sev)}
                      className={cn(
                        "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
                        active
                          ? severityBg(sev)
                          : "border border-input bg-background text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                      )}
                    >
                      <span className={cn("h-1.5 w-1.5 rounded-full", active ? severityDot(sev) : "bg-muted-foreground")} />
                      {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="flex items-center justify-end gap-2">
            <DialogClose asChild>
              <Button variant="outline" disabled={startScan.isPending}>
                Cancel
              </Button>
            </DialogClose>
            <Button onClick={handleSubmit} disabled={startScan.isPending}>
              {startScan.isPending ? "Starting..." : "Start Scan"}
            </Button>
          </div>
        </DialogContent>
      </DialogPortal>
    </Dialog>
  );
}
