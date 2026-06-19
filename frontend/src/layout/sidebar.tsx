import { useState } from "react";
import { NavLink } from "react-router-dom";
import { cn } from "@/lib/utils";
import { useScanCount } from "@/lib/scan-counter";
import {
  ChevronDown,
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
  Command,
  Puzzle,
  Mail,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  Users,
  Fingerprint,
  GitBranch,
  RotateCw,
  Swords,
  MessageSquare,
  Globe,
  BookTemplate,
  MessageCircle,
  Monitor,
  Siren,
  Skull,
  Zap,
  Radio,
  Rss,
  KeyRound,
} from "lucide-react";

interface NavSection {
  title: string;
  items: { to: string; icon: React.ElementType; label: string }[];
}

const navSections: NavSection[] = [
  {
    title: "Core",
    items: [
      { to: "/", icon: LayoutDashboard, label: "Overview" },
      { to: "/scans", icon: Radar, label: "Scans" },
      { to: "/scans/new", icon: PlusCircle, label: "New Scan" },
      { to: "/findings", icon: ListTodo, label: "Findings" },
      { to: "/live", icon: Activity, label: "Live Feed" },
      { to: "/reports", icon: FileText, label: "Reports" },
    ],
  },
  {
    title: "Security Testing",
    items: [
      { to: "/red-team", icon: Network, label: "Red Team" },
      { to: "/purple-team", icon: Swords, label: "Purple Team" },
      { to: "/external-asm", icon: Globe, label: "External ASM" },
      { to: "/cloud-scanner", icon: Search, label: "Cloud Scanner" },
      { to: "/internal-agents", icon: Monitor, label: "Internal Agents" },
      { to: "/packet-injection", icon: Zap, label: "Packet Injection" },
      { to: "/network-simulation", icon: Rss, label: "Net Simulation" },
      { to: "/c2-advanced", icon: Radio, label: "Advanced C2" },
    ],
  },
  {
    title: "Monitoring & Ops",
    items: [
      { to: "/instances", icon: Server, label: "Instances" },
      { to: "/schedules", icon: Clock, label: "Schedules" },
      { to: "/exposure-monitoring", icon: AlertTriangle, label: "Exposure Monitor" },
      { to: "/validation-loops", icon: RotateCw, label: "Validation Loops" },
      { to: "/email", icon: Mail, label: "Email Triage" },
    ],
  },
  {
    title: "Risk & Compliance",
    items: [
      { to: "/compliance", icon: Shield, label: "Compliance" },
      { to: "/compliance-frameworks", icon: BookTemplate, label: "Compliance Frameworks" },
      { to: "/executive-risk", icon: TrendingUp, label: "Executive Risk" },
      { to: "/bounty", icon: Bug, label: "Bounty" },
    ],
  },
  {
    title: "Analysis",
    items: [
      { to: "/malware", icon: Skull, label: "Malware Analysis" },
      { to: "/ransomware", icon: Siren, label: "Ransomware" },
      { to: "/attack-graph", icon: Network, label: "Attack Graph" },
      { to: "/knowledge-graph", icon: GitBranch, label: "Knowledge Graph" },
      { to: "/evidence-integrity", icon: Fingerprint, label: "Evidence Integrity" },
    ],
  },
  {
    title: "Collaboration & Config",
    items: [
      { to: "/projects", icon: Target, label: "Projects" },
      { to: "/integrations", icon: Puzzle, label: "Integrations" },
      { to: "/approvals", icon: CheckCircle, label: "Approvals" },
      { to: "/collaboration", icon: MessageCircle, label: "Collaboration" },
      { to: "/copilot", icon: MessageSquare, label: "AI Copilot" },
      { to: "/enterprise-identity", icon: Users, label: "Enterprise Identity" },
      { to: "/settings", icon: Settings, label: "Settings" },
    ],
  },
];

interface SidebarProps {
  mobile?: boolean;
  onClose?: () => void;
}

function NavGroup({ section, onClose }: { section: NavSection; onClose?: () => void }) {
  const [open, setOpen] = useState(true);
  return (
    <div className="mb-1">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-1 rounded-md px-2 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors"
      >
        <ChevronDown className={cn("h-3 w-3 transition-transform", !open && "-rotate-90")} />
        {section.title}
      </button>
      {open && (
        <div className="ml-1 space-y-0.5">
          {section.items.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={() => onClose?.()}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors",
                  isActive
                    ? "bg-accent text-accent-foreground font-medium"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )
              }
            >
              <item.icon className="h-3.5 w-3.5 shrink-0" />
              <span className="truncate">{item.label}</span>
            </NavLink>
          ))}
        </div>
      )}
    </div>
  );
}

export function Sidebar({ onClose }: SidebarProps) {
  const { remaining, max, exhausted } = useScanCount();
  return (
    <div className="flex h-full flex-col">
      <div className="flex h-14 items-center border-b px-5">
        <h1 className="text-lg font-bold tracking-tight">Ares</h1>
        <span className="ml-2 text-xs text-muted-foreground">v2.0</span>
      </div>
      <nav className="flex-1 overflow-y-auto p-3 space-y-0.5">
        {navSections.map((section) => (
          <NavGroup key={section.title} section={section} onClose={onClose} />
        ))}
      </nav>
      <div className="border-t p-3 space-y-2">
        <div className="flex items-center gap-2 rounded-md bg-muted/50 px-3 py-2 text-xs">
          <KeyRound className={cn("h-3 w-3 shrink-0", exhausted ? "text-destructive" : "text-primary")} />
          <span className={cn(exhausted ? "text-destructive" : "text-muted-foreground")}>
            {exhausted ? "No scans remaining" : `${remaining} / ${max} scans remaining`}
          </span>
        </div>
        <div className="flex items-center gap-2 rounded-md bg-muted px-3 py-2 text-xs text-muted-foreground">
          <Command className="h-3.5 w-3.5" />
          <span className="hidden md:inline">Ctrl+K for actions</span>
          <span className="md:hidden">Ctrl+K</span>
        </div>
      </div>
    </div>
  );
}
