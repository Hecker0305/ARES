import { cn } from "@/lib/utils";
import { useWSStore } from "@/store/ws";

const statusLabels: Record<string, string> = {
  idle: "Idle",
  connecting: "Connecting",
  connected: "Connected",
  disconnected: "Disconnected",
  reconnecting: "Reconnecting",
};

const statusBannerText: Record<string, string> = {
  connecting: "Connecting to live feed...",
  disconnected: "Disconnected from live feed",
  reconnecting: "Reconnecting to live feed...",
};

const statusColors: Record<string, string> = {
  idle: "bg-muted-foreground",
  connecting: "bg-warning pulse-dot",
  connected: "bg-success",
  disconnected: "bg-destructive-foreground",
  reconnecting: "bg-warning pulse-dot",
};

export function ConnectionStatus() {
  const status = useWSStore((s) => s.status);

  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-muted px-2.5 py-0.5 text-xs">
      <span className={cn("h-1.5 w-1.5 rounded-full", statusColors[status])} />
      {statusLabels[status]}
    </span>
  );
}

export function ConnectionBanner() {
  const status = useWSStore((s) => s.status);

  if (status === "connected" || status === "idle") return null;

  return (
    <div className="flex items-center justify-center gap-2 bg-warning/10 px-4 py-1.5 text-xs text-warning">
      <span className="h-1.5 w-1.5 rounded-full bg-warning pulse-dot" />
      {statusBannerText[status] || "Disconnected from live feed"}
    </div>
  );
}
