import { Brain, Mail, Bell, Gauge, ExternalLink, Settings } from "lucide-react";
import { useLLMSettings, useDiscordSettings, useAgentMailSettings, useRateLimitSettings } from "@/api/queries";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

function IntegrationCardSkeleton() {
  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardHeader className="flex flex-row items-start gap-4 space-y-0 pb-4">
        <Skeleton className="h-10 w-10 rounded-lg" />
        <div className="flex-1 space-y-2">
          <Skeleton className="h-5 w-32" />
          <Skeleton className="h-4 w-48" />
        </div>
        <Skeleton className="h-5 w-20 rounded-full" />
      </CardHeader>
      <CardContent className="space-y-3">
        <Skeleton className="h-4 w-36" />
        <div className="flex gap-2">
          <Skeleton className="h-9 w-24 rounded-md" />
          <Skeleton className="h-9 w-24 rounded-md" />
        </div>
      </CardContent>
    </Card>
  );
}

export function IntegrationsPage() {
  const llm = useLLMSettings();
  const discord = useDiscordSettings();
  const agentMail = useAgentMailSettings();
  const rateLimit = useRateLimitSettings();

  const isLoading = llm.isLoading || discord.isLoading || agentMail.isLoading || rateLimit.isLoading;

  const llmConnected = !!llm.data?.provider && !!llm.data?.model;
  const discordConnected = !!discord.data?.webhookUrl;
  const agentMailConnected = !!agentMail.data?.pod && !!agentMail.data?.hasApiKey;

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <h1 className="text-2xl font-bold">Integrations</h1>
        <p className="text-sm text-muted-foreground">Central hub of all connected services.</p>
        <div className="grid gap-6 md:grid-cols-2">
          <IntegrationCardSkeleton />
          <IntegrationCardSkeleton />
          <IntegrationCardSkeleton />
          <IntegrationCardSkeleton />
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Integrations</h1>
        <p className="text-sm text-muted-foreground mt-1">Central hub of all connected services.</p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader className="flex flex-row items-start gap-4 space-y-0 pb-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-violet-500/10">
              <Brain className="h-5 w-5 text-violet-400" />
            </div>
            <div className="flex-1">
              <CardTitle className="text-base">LLM Provider</CardTitle>
              <CardDescription>AI model provider for scan agents</CardDescription>
            </div>
            <Badge variant={llmConnected ? "success" : "outline"}>
              {llmConnected ? "Connected" : "Not connected"}
            </Badge>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              {llmConnected
                ? `${llm.data!.provider} / ${llm.data!.model}`
                : "No AI provider configured"}
            </p>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" asChild>
                <a href="/settings"><Settings className="h-3.5 w-3.5" />Configure</a>
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader className="flex flex-row items-start gap-4 space-y-0 pb-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/10">
              <Mail className="h-5 w-5 text-emerald-400" />
            </div>
            <div className="flex-1">
              <CardTitle className="text-base">AgentMail</CardTitle>
              <CardDescription>Email-based reporting channel</CardDescription>
            </div>
            <Badge variant={agentMailConnected ? "success" : "outline"}>
              {agentMailConnected ? "Connected" : "Not connected"}
            </Badge>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              {agentMailConnected
                ? `Pod: ${agentMail.data!.pod}`
                : "No email pod configured"}
            </p>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" asChild>
                <a href="/settings"><Settings className="h-3.5 w-3.5" />Configure</a>
              </Button>
              <Button size="sm" variant="ghost" asChild>
                <a href="https://agentmail.co" target="_blank" rel="noopener noreferrer">
                  <ExternalLink className="h-3.5 w-3.5" />Docs
                </a>
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader className="flex flex-row items-start gap-4 space-y-0 pb-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-500/10">
              <Bell className="h-5 w-5 text-amber-400" />
            </div>
            <div className="flex-1">
              <CardTitle className="text-base">Discord Webhook</CardTitle>
              <CardDescription>Real-time alert notifications</CardDescription>
            </div>
            <Badge variant={discordConnected ? "success" : "outline"}>
              {discordConnected ? "Connected" : "Not connected"}
            </Badge>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              {discordConnected
                ? `Min severity: ${discord.data!.minimumSeverity}`
                : "No webhook configured"}
            </p>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" asChild>
                <a href="/settings"><Settings className="h-3.5 w-3.5" />Configure</a>
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader className="flex flex-row items-start gap-4 space-y-0 pb-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-sky-500/10">
              <Gauge className="h-5 w-5 text-sky-400" />
            </div>
            <div className="flex-1">
              <CardTitle className="text-base">Outbound Rate Limiter</CardTitle>
              <CardDescription>Engagement request throttling</CardDescription>
            </div>
            <Badge variant="success">Active</Badge>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              {rateLimit.data
                ? `${rateLimit.data.requestsPerWindow} requests / ${rateLimit.data.windowSeconds}s window`
                : "Default limits active"}
            </p>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" asChild>
                <a href="/settings"><Settings className="h-3.5 w-3.5" />Adjust</a>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
