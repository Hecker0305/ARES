import { useState, useEffect } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "@/layout/sidebar";
import { Topbar } from "@/layout/topbar";
import { ConnectionBanner } from "@/components/connection-status";
import { useWSStore } from "@/store/ws";
import { CommandPaletteProvider } from "@/components/command-palette";

export function AppShell() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const connect = useWSStore((s) => s.connect);
  const disconnect = useWSStore((s) => s.disconnect);

  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  return (
    <CommandPaletteProvider>
      <div className="flex h-screen bg-background">
        {/* Desktop sidebar */}
        <aside className="hidden w-64 shrink-0 border-r md:block">
          <Sidebar />
        </aside>

        {/* Mobile sidebar overlay */}
        {mobileOpen && (
          <div className="fixed inset-0 z-40 md:hidden">
            <div className="fixed inset-0 bg-black/60" onClick={() => setMobileOpen(false)} />
            <aside className="fixed inset-y-0 left-0 w-64 bg-background border-r z-50">
              <Sidebar mobile onClose={() => setMobileOpen(false)} />
            </aside>
          </div>
        )}

        <div className="flex flex-1 flex-col overflow-hidden">
          <ConnectionBanner />
          <Topbar onMenuToggle={() => setMobileOpen(true)} />
          <main className="flex-1 overflow-y-auto">
            <Outlet />
          </main>
        </div>
      </div>
    </CommandPaletteProvider>
  );
}
