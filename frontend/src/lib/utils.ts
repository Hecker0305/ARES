import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);

  if (hours > 0) {
    return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  }
  return `${seconds}s`;
}

export function timeAgo(date: string): string {
  const now = Date.now();
  let then: number;
  try {
    then = new Date(date).getTime();
    if (isNaN(then)) return "invalid date";
  } catch {
    return "invalid date";
  }
  const diff = now - then;

  if (diff < 60000) return "just now";
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}

export function formatTime(date?: string): string {
  if (!date) return "--:--:--";
  try {
    const d = new Date(date);
    if (isNaN(d.getTime())) return "--:--:--";
    return d.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return "--:--:--";
  }
}

export function shortId(id: string): string {
  return id.length > 12 ? id.substring(0, 12) + "..." : id;
}

export function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "text-severity-critical";
    case "high":
      return "text-severity-high";
    case "medium":
      return "text-severity-medium";
    case "low":
      return "text-severity-low";
    case "info":
      return "text-severity-info";
    default:
      return "text-muted-foreground";
  }
}

export function severityBg(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-severity-critical/10 text-severity-critical";
    case "high":
      return "bg-severity-high/10 text-severity-high";
    case "medium":
      return "bg-severity-medium/10 text-severity-medium";
    case "low":
      return "bg-severity-low/10 text-severity-low";
    case "info":
      return "bg-severity-info/10 text-severity-info";
    default:
      return "bg-muted text-muted-foreground";
  }
}

export function severityDot(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-severity-critical";
    case "high":
      return "bg-severity-high";
    case "medium":
      return "bg-severity-medium";
    case "low":
      return "bg-severity-low";
    case "info":
      return "bg-severity-info";
    default:
      return "bg-muted-foreground";
  }
}

export function severityRank(severity: string): number {
  switch (severity.toLowerCase()) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "medium":
      return 2;
    case "low":
      return 3;
    case "info":
      return 4;
    default:
      return 5;
  }
}

export function normalizeSeverity(severity: string): string {
  const s = severity.toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(s)) return s;
  return "unknown";
}

export function formatDurationFromDates(start: string, end?: string): string {
  const startMs = new Date(start).getTime();
  const endMs = end ? new Date(end).getTime() : Date.now();
  const diffMs = endMs - startMs;
  if (diffMs < 0) return "0s";
  return formatDuration(diffMs);
}

export function severityBarClass(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-severity-critical";
    case "high":
      return "bg-severity-high";
    case "medium":
      return "bg-severity-medium";
    case "low":
      return "bg-severity-low";
    case "info":
      return "bg-severity-info";
    default:
      return "bg-muted";
  }
}

export function statusColor(status: string): string {
  switch (status.toLowerCase()) {
    case "running":
      return "text-success";
    case "finished":
    case "completed":
      return "text-muted-foreground";
    case "stopped":
    case "failed":
      return "text-destructive-foreground";
    case "paused":
    case "queued":
      return "text-warning";
    case "saved":
      return "text-blue-400";
    default:
      return "text-muted-foreground";
  }
}

export function statusDot(status: string): string {
  switch (status.toLowerCase()) {
    case "running":
      return "bg-success pulse-dot";
    case "finished":
    case "completed":
      return "bg-muted-foreground";
    case "stopped":
    case "failed":
      return "bg-destructive-foreground";
    case "paused":
    case "queued":
      return "bg-warning pulse-dot";
    case "saved":
      return "bg-blue-400";
    default:
      return "bg-muted-foreground";
  }
}

export function copyToClipboard(text: string): Promise<void> {
  return navigator.clipboard.writeText(text);
}

export function parseCronDescription(cron: string): string {
  const parts = cron.split(" ");
  if (parts.length < 5) return cron;

  const [minute, hour, dayOfMonth, month, dayOfWeek] = parts;

  if (minute === "0" && hour === "*" && dayOfMonth === "*" && month === "*" && dayOfWeek === "*") {
    return "Every hour";
  }
  if (minute === "0" && hour === "0" && dayOfMonth === "*" && month === "*" && dayOfWeek === "*") {
    return "Daily at 12:00 AM";
  }
  if (minute === "0" && hour === "2" && dayOfMonth === "*" && month === "*" && dayOfWeek === "*") {
    return "Daily at 2:00 AM";
  }
  if (dayOfWeek !== "*") {
    const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    return `Weekly on ${days[parseInt(dayOfWeek)]} at ${hour}:${minute.padStart(2, "0")}`;
  }
  if (dayOfMonth !== "*") {
    return `Monthly on day ${dayOfMonth} at ${hour}:${minute.padStart(2, "0")}`;
  }
  return `At ${hour}:${minute.padStart(2, "0")}`;
}
