import { cn } from "@/lib/utils";
import { Link } from "react-router-dom";
import type { LucideIcon } from "lucide-react";

interface MetricCardProps {
  label: string;
  value: string | number;
  hint?: string;
  icon?: LucideIcon;
  accent?: "default" | "critical" | "warning" | "success";
  link?: string;
  className?: string;
}

const accentColors = {
  default: "border-border",
  critical: "border-severity-critical/50",
  warning: "border-warning/50",
  success: "border-success/50",
};

export function MetricCard({ label, value, hint, icon: Icon, accent = "default", link, className }: MetricCardProps) {
  const content = (
    <div className={cn("rounded-lg border bg-card p-4 card-hover", accentColors[accent], className)}>
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">{label}</p>
        {Icon && <Icon className="h-4 w-4 text-muted-foreground" />}
      </div>
      <p className="mt-2 text-2xl font-bold">{value}</p>
      {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );

  if (link) {
    return <Link to={link}>{content}</Link>;
  }

  return content;
}
