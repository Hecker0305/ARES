import { useState, useRef, useEffect, useMemo } from "react";
import { useWSStore } from "@/store/ws";
import { cn, formatTime } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Pause, Play, Trash2, Download, ChevronDown, ChevronRight } from "lucide-react";
import { exportFeedAsJSON, exportFeedAsJSONL, exportFeedAsTXT, downloadFeed } from "@/lib/feed-export";

const FILTERS = ["all", "tool", "vuln", "error", "agent", "http", "llm"] as const;
type Filter = (typeof FILTERS)[number];

function matchFilter(type: string, filter: Filter): boolean {
  if (filter === "all") return true;
  const t = type.toLowerCase();
  switch (filter) {
    case "tool":
      return t.includes("tool") || t.includes("nuclei") || t.includes("sqlmap");
    case "vuln":
      return t.includes("vuln") || t.includes("finding");
    case "error":
      return t.includes("error");
    case "agent":
      return t.includes("agent") || t.includes("thought") || t.includes("decision") || t.includes("phase");
    case "http":
      return t.includes("http") || t.includes("request") || t.includes("response");
    case "llm":
      return t.includes("llm") || t.includes("token");
    default:
      return true;
  }
}

export function LiveFeed() {
  const events = useWSStore((s) => s.events);
  const paused = useWSStore((s) => s.paused);
  const pause = useWSStore((s) => s.pause);
  const resume = useWSStore((s) => s.resume);
  const clear = useWSStore((s) => s.clear);

  const [filter, setFilter] = useState<Filter>("all");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  const filteredEvents = useMemo(
    () => events.filter((e) => matchFilter(e.type, filter)),
    [events, filter],
  );

  useEffect(() => {
    if (!paused && feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [filteredEvents.length, paused]);

  const handleExport = (format: "json" | "jsonl" | "txt") => {
    const exporter =
      format === "json"
        ? exportFeedAsJSON
        : format === "jsonl"
          ? exportFeedAsJSONL
          : exportFeedAsTXT;
    downloadFeed(exporter(filteredEvents), format);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between border-b px-4 py-2">
        <Tabs value={filter} onValueChange={(v) => setFilter(v as Filter)}>
          <TabsList>
            {FILTERS.map((f) => (
              <TabsTrigger key={f} value={f} className="capitalize">
                {f}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" onClick={() => handleExport("json")}>
            <Download className="h-3.5 w-3.5" />
          </Button>
          <Button variant="ghost" size="sm" onClick={paused ? resume : pause}>
            {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
          </Button>
          <Button variant="ghost" size="sm" onClick={clear}>
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
      <div ref={feedRef} className="flex-1 overflow-y-auto font-mono text-xs">
        {filteredEvents.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            No events yet
          </div>
        ) : (
          filteredEvents.map((event, i) => (
            <LiveEventRow
              key={`${event.timestamp || ""}-${i}`}
              event={event}
              isExpanded={expandedId === i}
              onToggle={() => setExpandedId(expandedId === i ? null : i)}
            />
          ))
        )}
      </div>
    </div>
  );
}

interface LiveEventRowProps {
  event: { type: string; tool_name?: string; content?: string; output?: string; error?: string; timestamp?: string };
  isExpanded: boolean;
  onToggle: () => void;
}

function LiveEventRow({ event, isExpanded, onToggle }: LiveEventRowProps) {
  const eventType = event?.type || "unknown";
  const eventTool = event?.tool_name || "";
  const eventContent = event?.content || "";
  const eventOutput = event?.output || "";
  const eventError = event?.error || "";

  const typeColor = (() => {
    const t = eventType.toLowerCase();
    if (t.includes("vuln") || t.includes("finding")) return "text-severity-critical";
    if (t.includes("error")) return "text-destructive-foreground";
    if (t.includes("tool")) return "text-blue-400";
    if (t.includes("agent") || t.includes("thought")) return "text-purple-400";
    if (t.includes("http")) return "text-green-400";
    if (t.includes("llm")) return "text-yellow-400";
    return "text-muted-foreground";
  })();

  const hasDetail = eventOutput || eventError || eventContent;

  const displayText = (() => {
    if (eventContent) return eventContent;
    if (eventOutput) return eventOutput.length > 120 ? eventOutput.substring(0, 120) + "..." : eventOutput;
    if (eventError) return eventError.length > 120 ? eventError.substring(0, 120) + "..." : eventError;
    return "";
  })();

  return (
    <div className="border-b border-border/30">
      <button
        onClick={onToggle}
        className="flex w-full items-start gap-2 px-4 py-1.5 hover:bg-muted/50 text-left"
      >
        <span className="mt-0.5 text-muted-foreground">
          {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        </span>
        <span className="text-muted-foreground shrink-0">{formatTime(event?.timestamp)}</span>
        <span className={cn("shrink-0 font-semibold uppercase w-20 truncate", typeColor)}>
          {eventType.substring(0, 10)}
        </span>
        {eventTool && (
          <span className="text-blue-400 shrink-0">[{eventTool}]</span>
        )}
        <span className="truncate text-muted-foreground">{displayText}</span>
      </button>
      {isExpanded && hasDetail && (
        <div className="px-4 pb-3 pl-10 text-xs">
          {eventContent && (
            <pre className="mt-1 rounded bg-muted/50 p-2 overflow-x-auto whitespace-pre-wrap">
              {eventContent}
            </pre>
          )}
          {eventOutput && (
            <pre className="mt-1 rounded bg-muted/50 p-2 overflow-x-auto whitespace-pre-wrap">
              {eventOutput}
            </pre>
          )}
          {eventError && (
            <pre className="mt-1 rounded bg-destructive/10 p-2 text-destructive-foreground overflow-x-auto whitespace-pre-wrap">
              {eventError}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
