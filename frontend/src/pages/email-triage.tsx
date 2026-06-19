import { useMemo } from "react";
import { Link } from "react-router-dom";
import { useAgentMailSettings } from "@/api/queries";
import { useWSStore } from "@/store/ws";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/states";
import { cn, formatTime } from "@/lib/utils";
import { Mail, MessageSquare } from "lucide-react";

export function EmailTriagePage() {
  const { data: settings, isLoading } = useAgentMailSettings();
  const wsStatus = useWSStore((s) => s.status);
  const events = useWSStore((s) => s.events);

  const agentMailEvents = useMemo(
    () => events.filter((e) => {
      const t = e.type.toLowerCase();
      return t === "email" || t === "agentmail" || t.includes("agentmail");
    }),
    [events],
  );

  const hasApiKey = settings?.hasApiKey || !!settings?.apiKey;

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <h1 className="text-2xl font-bold">Email Triage</h1>
        <div className="grid gap-4 md:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-28 rounded-lg" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Email Triage</h1>
        {!hasApiKey && (
          <Link
            to="/settings"
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            <Mail className="h-4 w-4" />
            Configure AgentMail
          </Link>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">AgentMail Pod</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-lg font-bold font-mono">{settings?.pod || "—"}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">API Key</CardTitle>
          </CardHeader>
          <CardContent>
            {hasApiKey ? (
              <Badge variant="success">Connected</Badge>
            ) : (
              <Badge variant="warning">Not configured</Badge>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">Listening</CardTitle>
          </CardHeader>
          <CardContent className="flex items-center gap-2">
            <span
              className={cn(
                "h-2 w-2 rounded-full",
                wsStatus === "connected" ? "bg-success" : "bg-muted-foreground",
              )}
            />
            <span className="text-sm font-medium">
              {wsStatus === "connected" ? "Live" : "Disconnected"}
            </span>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <MessageSquare className="h-5 w-5 text-muted-foreground" />
            <CardTitle>Live AgentMail Events</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {agentMailEvents.length === 0 ? (
            <EmptyState
              icon="inbox"
              title="No AgentMail events"
              description={
                hasApiKey
                  ? "Waiting for incoming emails. Events will appear here in real time."
                  : "Configure AgentMail in settings to start receiving email events."
              }
            />
          ) : (
            <div className="space-y-1">
              {agentMailEvents.map((event, i) => (
                <div
                  key={`${event.timestamp || ""}-${i}`}
                  className="flex items-start gap-3 rounded-md border border-border/30 p-3 hover:bg-muted/30"
                >
                  <span className="shrink-0 text-xs text-muted-foreground font-mono mt-0.5">
                    {formatTime(event.timestamp)}
                  </span>
                  <div className="flex flex-wrap gap-1.5 shrink-0">
                    <Badge variant="outline" className="text-xs font-mono">
                      {event.type}
                    </Badge>
                    {event.tool_name && (
                      <Badge variant="muted" className="text-xs">
                        {event.tool_name}
                      </Badge>
                    )}
                  </div>
                  <span className="text-sm text-muted-foreground truncate min-w-0">
                    {event.content || event.output || event.error || ""}
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
