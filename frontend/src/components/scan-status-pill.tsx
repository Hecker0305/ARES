import { cn, statusColor, statusDot } from "@/lib/utils";

interface ScanStatusPillProps {
  status: string;
  className?: string;
}

export function ScanStatusPill({ status, className }: ScanStatusPillProps) {
  const isRunning = status.toLowerCase() === "running";
  return (
    <span className={cn("relative inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium", statusColor(status), className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", statusDot(status))} />
      {status.charAt(0).toUpperCase() + status.slice(1)}
      {isRunning && <span className="absolute inset-0 rounded-full bg-success/20 animate-ping" />}
    </span>
  );
}
