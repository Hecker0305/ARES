import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Send, Bot, Sparkles } from "lucide-react";
import { toast } from "sonner";

export function CopilotPage() {
  const [query, setQuery] = useState("");
  const [response, setResponse] = useState<string | null>(null);
  const qc = useQueryClient();

  const { data: suggestions } = useQuery({
    queryKey: ["copilotSuggestions"],
    queryFn: api.copilotSuggestions,
    staleTime: 600000,
  });

  const { data: history } = useQuery({
    queryKey: ["copilotHistory"],
    queryFn: api.copilotHistory,
  });

  const queryMut = useMutation({
    mutationFn: (q: string) => api.copilotQuery({ query: q }),
    onSuccess: (data) => {
      setResponse(data.answer);
      qc.invalidateQueries({ queryKey: ["copilotHistory"] });
    },
    onError: () => {
      toast.error("Failed to process query");
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;
    queryMut.mutate(query);
  };

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">AI Security Copilot</h1>
        <p className="text-muted-foreground">
          Ask questions about your security posture using natural language
        </p>
      </div>

      <Card className="p-4">
        <form onSubmit={handleSubmit} className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Ask a question... (e.g., 'Show all exploitable internet-facing assets')"
            className="flex-1 rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
          />
          <Button type="submit" disabled={queryMut.isPending}>
            <Send className="mr-1 h-4 w-4" />
            Ask
          </Button>
        </form>
      </Card>

      {queryMut.isPending && <Skeleton className="h-32" />}

      {response && (
        <Card className="p-4">
          <div className="flex items-start gap-3">
            <Bot className="mt-1 h-5 w-5 text-primary" />
            <div className="whitespace-pre-wrap text-sm leading-relaxed">
              {response}
            </div>
          </div>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="p-4">
          <div className="mb-3 flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-yellow-500" />
            <h2 className="font-medium">Suggested Questions</h2>
          </div>
          <div className="space-y-2">
            {suggestions?.suggestions?.map((s, i) => (
              <button
                key={i}
                onClick={() => {
                  setQuery(s);
                  queryMut.mutate(s);
                }}
                className="w-full rounded bg-muted/50 p-2 text-left text-sm hover:bg-muted transition-colors"
              >
                {s}
              </button>
            ))}
          </div>
        </Card>

        <Card className="p-4">
          <h2 className="mb-3 font-medium">Recent Queries</h2>
          {(!history || history.length === 0) && (
            <p className="text-sm text-muted-foreground">No query history</p>
          )}
          <div className="space-y-2">
            {history?.slice(-10).reverse().map((entry, i) => (
              <div key={i} className="rounded bg-muted/50 p-2 text-sm">
                <p className="font-medium">{entry.question}</p>
                <p className="mt-1 text-xs text-muted-foreground line-clamp-2">
                  {entry.answer}
                </p>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
