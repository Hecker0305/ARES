import { cn, severityBg, severityDot } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium", severityBg(severity), className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", severityDot(severity))} />
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}
