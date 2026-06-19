import { Link } from "react-router-dom";
import { useProjects } from "@/api/queries";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/states";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Target, ArrowRight } from "lucide-react";
import { timeAgo } from "@/lib/utils";

export function ProjectsPage() {
  const { data: projects, isLoading } = useProjects();
  if (isLoading) return (<div className="p-6"><div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">{[1, 2, 3, 4, 5, 6].map((i) => <Skeleton key={i} className="h-40 rounded-lg" />)}</div></div>);
  return (
    <div className="p-6 space-y-6">
      <div><h1 className="text-2xl font-bold">Projects</h1><p className="text-muted-foreground mt-1">Client engagement projects.</p></div>
      {!projects || projects.length === 0 ? (<EmptyState title="No projects" description="Projects will appear here once created." />) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {projects.map((project) => (
            <Link key={project.id} to={`/scans`} className="block">
              <Card className="card-hover h-full">
                <CardHeader className="pb-3"><div className="flex items-center gap-2"><Target className="h-5 w-5 text-muted-foreground" /><CardTitle className="text-base">{project.name}</CardTitle></div></CardHeader>
                <CardContent className="space-y-3">
                  <p className="text-sm font-mono text-muted-foreground truncate">{project.target}</p>
                  <div className="flex items-center justify-between"><Badge variant={project.status === "active" ? "success" : "muted"}>{project.status}</Badge><span className="text-xs text-muted-foreground">{timeAgo(project.lastScan)}</span></div>
                  <div className="flex items-center justify-between text-sm"><span className="text-muted-foreground">Findings</span><span className="font-bold">{project.totalFindings}</span></div>
                  <div className="flex items-center justify-between text-sm text-muted-foreground"><span>Last scan</span><ArrowRight className="h-3.5 w-3.5" /></div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
