import type { WSEvent } from "@/api/types";

export function exportFeedAsJSON(events: WSEvent[]): string {
  return JSON.stringify(events, null, 2);
}

export function exportFeedAsJSONL(events: WSEvent[]): string {
  return events.map((e) => JSON.stringify(e)).join("\n");
}

export function exportFeedAsTXT(events: WSEvent[]): string {
  return events
    .map((e) => {
      const time = e.timestamp || "--:--:--";
      const type = e.type.toUpperCase().padEnd(12);
      const tool = e.tool_name ? `[${e.tool_name}] ` : "";
      const content = e.content || e.output || e.error || "";
      return `${time} ${type} ${tool}${content}`;
    })
    .join("\n");
}

export function downloadFeed(content: string, format: "json" | "jsonl" | "txt"): void {
  const blob = new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ares-feed-${Date.now()}.${format}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
