import { useState, useEffect, useMemo, useRef } from "react";
import { useWSStore } from "@/store/ws";
import { cn, formatDuration } from "@/lib/utils";
import { Loader2 } from "lucide-react";

interface ScanProgressBarProps {
  progress: number;
  phase: string;
  status: string;
  startTime: string;
  phases?: string[];
}

function getPhaseDescription(phase: string): string {
  const descs: Record<string, string> = {
    starting: "Initializing scan environment",
    initializing: "Initializing scan environment",
    subdomain: "Discovering subdomains and related targets",
    crawling: "Crawling target application for endpoints",
    discovery: "Running active reconnaissance & discovery",
    probing: "Probing endpoints for vulnerabilities",
    scanning: "Scanning with automated security tools",
    analysis: "Analyzing results and validating findings",
    reporting: "Generating comprehensive report",
    completed: "Scan completed",
    finished: "Scan finished",
  };
  return descs[phase.toLowerCase()] || `${phase} phase in progress`;
}

function getStatusMessage(events: { type: string; content?: string; tool_name?: string; output?: string }[], phase: string): string {
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i];
    if (e.type === "phase_change" && e.content) {
      return e.content.length > 80 ? e.content.substring(0, 80) + "..." : e.content;
    }
    if (e.type === "tool_run" && e.tool_name) return `Running ${e.tool_name}...`;
    if (e.type === "tool_complete" && e.content) return e.content;
    if (e.type === "status" && e.content) return e.content;
    if (e.type === "agent_thought" && e.content) return e.content.substring(0, 100);
    if (e.type === "finding_add" && e.content) return `Found: ${e.content.substring(0, 60)}`;
    if (e.content) return e.content.substring(0, 100);
  }
  return getPhaseDescription(phase);
}

export function ScanProgressBar({ progress, phase, status, startTime, phases }: ScanProgressBarProps) {
  const events = useWSStore((s) => s.events);
  const sendStatusRequest = useWSStore((s) => s.sendStatusRequest);
  const [now, setNow] = useState(() => Date.now());
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (status !== "running") return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [status]);

  useEffect(() => {
    if (status !== "running") return;
    pollRef.current = setInterval(() => sendStatusRequest(), 3000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [status, sendStatusRequest]);

  const elapsed = useMemo(() => {
    return now - new Date(startTime).getTime();
  }, [now, startTime]);

  const eta = useMemo(() => {
    if (progress < 0.01) return -1;
    const total = elapsed / progress;
    return total - elapsed;
  }, [progress, elapsed]);

  const isRunning = status === "running";
  const isFinished = status === "completed" || status === "finished";
  const pct = isFinished ? 100 : Math.min(Math.round(progress * 100), 100);

  const statusMsg = useMemo(() => getStatusMessage(events, phase), [events, phase]);

  const phaseNum = phases ? phases.indexOf(phase) + 1 : 0;
  const totalPhases = phases?.length || 0;

  const barColor = isRunning ? "bg-primary" : isFinished ? "bg-success" : status === "failed" ? "bg-destructive" : status === "stopped" ? "bg-warning" : "bg-muted";

  return (
    <div className={cn(
      "rounded-lg border p-4 transition-all",
      isRunning && "border-primary/30 bg-muted/20",
      isFinished && "border-muted",
      progress === 0 && isRunning && "border-primary/10",
    )}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-3">
          <span className="text-2xl font-bold tabular-nums">{pct}%</span>
          {isRunning && (
            <span className="flex items-center gap-1.5 text-sm text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              {elapsed > 0 && <span>Elapsed: {formatDuration(elapsed)}</span>}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 text-sm tabular-nums">
          {isRunning && eta > 0 && (
            <span className="text-muted-foreground">
              ETA: {formatDuration(eta)}
            </span>
          )}
          {isRunning && eta < 0 && (
            <span className="text-muted-foreground text-xs">Estimating...</span>
          )}
          {phaseNum > 0 && totalPhases > 0 && (
            <span className="text-xs text-muted-foreground">
              Phase {phaseNum}/{totalPhases}
            </span>
          )}
        </div>
      </div>

      <div className="h-2.5 w-full rounded-full bg-muted overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all duration-500 ease-out", barColor, isRunning && pct > 0 && pct < 100 && "animate-pulse")}
          style={{ width: `${Math.max(pct, 2)}%` }}
        />
      </div>

      <div className="flex items-center justify-between mt-2">
        <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          {phase ? getPhaseDescription(phase) : "Initializing"}
        </span>
        {isRunning && (
          <span className="text-xs text-muted-foreground truncate max-w-[300px] ml-4" title={statusMsg}>
            {statusMsg}
          </span>
        )}
        {isFinished && (
          <span className="text-xs text-success">Completed in {formatDuration(elapsed)}</span>
        )}
        {(status === "failed" || status === "stopped") && (
          <span className="text-xs text-destructive-foreground">
            {status === "failed" ? "Failed" : "Stopped"} after {formatDuration(elapsed)}
          </span>
        )}
      </div>
    </div>
  );
}
