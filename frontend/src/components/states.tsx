import { cn } from "@/lib/utils";
import { AlertCircle, AlertTriangle, Inbox, Search } from "lucide-react";
import { Button } from "@/components/ui/button";

interface EmptyStateProps {
  icon?: "inbox" | "search";
  title: string;
  description: string;
  action?: { label: string; onClick: () => void };
  className?: string;
}

export function EmptyState({ icon = "inbox", title, description, action, className }: EmptyStateProps) {
  const Icon = icon === "search" ? Search : Inbox;
  return (
    <div className={cn("flex flex-col items-center justify-center rounded-lg border border-dashed p-12 text-center", className)}>
      <Icon className="h-10 w-10 text-muted-foreground/50" />
      <h3 className="mt-4 text-lg font-semibold">{title}</h3>
      <p className="mt-1 text-sm text-muted-foreground max-w-sm">{description}</p>
      {action && (
        <Button onClick={action.onClick} className="mt-4">
          {action.label}
        </Button>
      )}
    </div>
  );
}

interface ErrorStateProps {
  title: string;
  description: string;
  action?: { label: string; onClick: () => void };
  className?: string;
}

export function ErrorState({ title, description, action, className }: ErrorStateProps) {
  return (
    <div className={cn("flex flex-col items-center justify-center rounded-lg border border-destructive/30 bg-destructive/5 p-8 text-center", className)}>
      <AlertCircle className="h-10 w-10 text-destructive" />
      <h3 className="mt-4 text-lg font-semibold text-destructive">{title}</h3>
      <p className="mt-1 text-sm text-muted-foreground max-w-sm">{description}</p>
      {action && (
        <Button onClick={action.onClick} variant="outline" className="mt-4">
          {action.label}
        </Button>
      )}
    </div>
  );
}

interface BackendUnreachableProps {
  message?: string;
  onRetry?: () => void;
  className?: string;
}

export function BackendUnreachable({
  message = "Cannot connect to the API server. Make sure the backend is running.",
  onRetry,
  className,
}: BackendUnreachableProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center rounded-lg border border-destructive/30 bg-destructive/5 p-8 text-center",
        className,
      )}
    >
      <AlertTriangle className="h-10 w-10 text-destructive" />
      <h3 className="mt-4 text-lg font-semibold text-destructive">Backend Unreachable</h3>
      <p className="mt-1 text-sm text-muted-foreground max-w-sm">{message}</p>
      {onRetry && (
        <Button onClick={onRetry} variant="outline" className="mt-4">
          Retry
        </Button>
      )}
      <div className="mt-6 text-left text-xs text-muted-foreground space-y-1">
        <p className="font-medium">Common fixes:</p>
        <ul className="list-disc list-inside space-y-0.5">
          <li>Start the Go backend server</li>
          <li>Run the mock backend with <code className="text-foreground">node mock-backend.mjs</code></li>
          <li>Set VITE_API_TARGET environment variable</li>
        </ul>
      </div>
    </div>
  );
}
