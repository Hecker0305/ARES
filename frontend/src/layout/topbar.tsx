import { useNavigate } from "react-router-dom";
import { useActiveScans, useStopScan } from "@/api/queries";
import { ConnectionStatus } from "@/components/connection-status";
import { Button } from "@/components/ui/button";
import { Menu, PlusCircle, Square, Search } from "lucide-react";
import { useCommandPalette } from "@/components/command-palette";

interface TopbarProps {
  onMenuToggle: () => void;
}

export function Topbar({ onMenuToggle }: TopbarProps) {
  const navigate = useNavigate();
  const { data: activeScans } = useActiveScans();
  const stopScan = useStopScan();
  const [, setShowCommandPalette] = useCommandPalette();

  const hasActiveScans = activeScans && activeScans.length > 0;

  return (
    <>
      <header className="flex h-14 items-center justify-between border-b px-4">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" className="md:hidden" onClick={onMenuToggle}>
            <Menu className="h-5 w-5" />
          </Button>
          <button
            onClick={() => setShowCommandPalette(true)}
            className="hidden md:flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted"
          >
            <Search className="h-3.5 w-3.5" />
            <span>Search scans, pages...</span>
            <kbd className="ml-auto rounded bg-background px-1.5 py-0.5 text-xs font-mono">Ctrl+K</kbd>
          </button>
        </div>
        <div className="flex items-center gap-2">
          {hasActiveScans && (
            <div className="flex items-center gap-2 text-xs">
              <span className="h-2 w-2 rounded-full bg-success pulse-dot" />
              <span className="text-muted-foreground">{activeScans.length} active</span>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 text-destructive hover:text-destructive"
                onClick={() => {
                  if (Array.isArray(activeScans)) {
                    activeScans.forEach((s) => {
                      if (s.id) stopScan.mutate(s.id);
                    });
                  }
                }}
              >
                <Square className="h-3 w-3" />
                Stop all
              </Button>
            </div>
          )}
          <ConnectionStatus />
          <Button size="sm" onClick={() => navigate("/scans/new")}>
            <PlusCircle className="h-3.5 w-3.5" />
            New Scan
          </Button>
        </div>
      </header>
    </>
  );
}
