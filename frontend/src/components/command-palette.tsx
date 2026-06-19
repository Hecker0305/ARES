import { useState, useEffect, createContext, useContext } from "react";
import { useNavigate } from "react-router-dom";
import { Command } from "cmdk";
import { useScansList, useInstances } from "@/api/queries";
import {
  Dialog,
  DialogContent,
} from "@/components/ui/dialog";
import {
  LayoutDashboard,
  Radar,
  PlusCircle,
  ListTodo,
  Activity,
  FileText,
  Server,
  Settings,
  Clock,
  Shield,
  Target,
  Search,
  Network,
  Bug,
} from "lucide-react";

interface CommandPaletteContextValue {
  show: boolean;
  setShow: (v: boolean) => void;
}

const CommandPaletteContext = createContext<CommandPaletteContextValue>({
  show: false,
  setShow: () => {},
});

// eslint-disable-next-line react-refresh/only-export-components
export function useCommandPalette() {
  const ctx = useContext(CommandPaletteContext);
  return [ctx.show, ctx.setShow] as const;
}

const pages = [
  { to: "/", icon: LayoutDashboard, label: "Overview" },
  { to: "/scans", icon: Radar, label: "Scans" },
  { to: "/scans/new", icon: PlusCircle, label: "New Scan" },
  { to: "/findings", icon: ListTodo, label: "Findings" },
  { to: "/live", icon: Activity, label: "Live Feed" },
  { to: "/reports", icon: FileText, label: "Reports" },
  { to: "/instances", icon: Server, label: "Instances" },
  { to: "/projects", icon: Target, label: "Projects" },
  { to: "/schedules", icon: Clock, label: "Schedules" },
  { to: "/compliance", icon: Shield, label: "Compliance" },
  { to: "/bounty", icon: Bug, label: "Bounty" },
  { to: "/cloud-scanner", icon: Search, label: "Cloud Scanner" },
  { to: "/red-team", icon: Network, label: "Red Team" },
  { to: "/attack-graph", icon: Network, label: "Attack Graph" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

export function CommandPaletteProvider({ children }: { children: React.ReactNode }) {
  const [show, setShow] = useState(false);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setShow((v) => !v);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  return (
    <CommandPaletteContext.Provider value={{ show, setShow }}>
      {children}
      <CommandPalette open={show} onOpenChange={setShow} />
    </CommandPaletteContext.Provider>
  );
}

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}

function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const navigate = useNavigate();
  const { data: scans } = useScansList();
  const { data: instances } = useInstances();

  const handleSelect = (to: string) => {
    navigate(to);
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="overflow-hidden p-0 max-w-lg">
        <Command className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:text-muted-foreground [&_[cmdk-group]:not([hidden])_~[cmdk-group]]:pt-0 [&_[cmdk-group]]:px-2 [&_[cmdk-input-wrapper]_svg]:h-5 [&_[cmdk-input-wrapper]_svg]:w-5 [&_[cmdk-input]]:h-12 [&_[cmdk-item]]:px-2 [&_[cmdk-item]]:py-3 [&_[cmdk-item]_svg]:h-4 [&_[cmdk-item]_svg]:w-4">
          <Command.Input placeholder="Search pages, scans..." />
          <Command.List>
            <Command.Empty>No results found.</Command.Empty>
            <Command.Group heading="Pages">
              {pages.map((page) => (
                <Command.Item
                  key={page.to}
                  value={page.label}
                  onSelect={() => handleSelect(page.to)}
                >
                  <page.icon className="mr-2 h-4 w-4" />
                  {page.label}
                </Command.Item>
              ))}
            </Command.Group>
            {scans && scans.length > 0 && (
              <Command.Group heading="Recent Scans">
                {scans.slice(0, 8).map((scan) => (
                  <Command.Item
                    key={scan.id}
                    value={`${scan.target} ${scan.id}`}
                    onSelect={() => handleSelect(`/scans/${scan.id}`)}
                  >
                    <Radar className="mr-2 h-4 w-4" />
                    {scan.target}
                    <span className="ml-auto text-xs text-muted-foreground">{scan.id.substring(0, 8)}</span>
                  </Command.Item>
                ))}
              </Command.Group>
            )}
            {instances?.instances && instances.instances.length > 0 && (
              <Command.Group heading="Active Instances">
                {instances.instances.slice(0, 6).map((inst) => (
                  <Command.Item
                    key={inst.id}
                    value={`${inst.target} ${inst.id}`}
                    onSelect={() => handleSelect(`/scans/${inst.id}`)}
                  >
                    <Server className="mr-2 h-4 w-4" />
                    {inst.target}
                    <span className="ml-auto text-xs text-muted-foreground">{inst.status}</span>
                  </Command.Item>
                ))}
              </Command.Group>
            )}
          </Command.List>
        </Command>
      </DialogContent>
    </Dialog>
  );
}
