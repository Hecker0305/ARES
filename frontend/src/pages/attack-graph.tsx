import { useAttackGraph, useAttackChains } from "@/api/queries";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/states";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Network, Download } from "lucide-react";

export function AttackGraphPage() {
  const { data: graph, isLoading } = useAttackGraph();
  const { data: chains } = useAttackChains();

  if (isLoading) return <div className="p-6"><Skeleton className="h-96 rounded-lg" /></div>;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Attack Graph</h1>
          <p className="text-muted-foreground mt-1">Visualize attack chains and vulnerability relationships.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline">
            <Download className="h-4 w-4" />
            Export DOT
          </Button>
          <Button variant="outline">
            <Download className="h-4 w-4" />
            Export Mermaid
          </Button>
        </div>
      </div>

      {/* Stats */}
      {graph && (
        <div className="grid gap-4 md:grid-cols-3">
          <Card>
            <CardContent className="pt-6">
              <p className="text-sm text-muted-foreground">Total Nodes</p>
              <p className="text-3xl font-bold">{graph.statistics.total_nodes}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <p className="text-sm text-muted-foreground">Total Edges</p>
              <p className="text-3xl font-bold">{graph.statistics.total_edges}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <p className="text-sm text-muted-foreground">Attack Chains</p>
              <p className="text-3xl font-bold">{graph.statistics.total_chains}</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Attack Chains */}
      {chains && chains.length > 0 ? (
        <div className="space-y-3">
          {chains.map((chain) => (
            <Card key={chain.id}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Network className="h-4 w-4" />
                    {chain.name}
                  </CardTitle>
                  <Badge
                    variant={
                      chain.severity === "critical"
                        ? "destructive"
                        : chain.severity === "high"
                          ? "warning"
                          : "muted"
                    }
                  >
                    {chain.severity}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-2 flex-wrap">
                  {chain.steps.map((step, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <Badge variant="outline" className="text-xs">
                        {step}
                      </Badge>
                      {i < chain.steps.length - 1 && (
                        <span className="text-muted-foreground">→</span>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <EmptyState
          title="No attack chains"
          description="Run scans to discover attack chains and build the graph."
        />
      )}

      {/* Graph Visualization Placeholder */}
      {graph && graph.nodes.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Graph Visualization</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-96 rounded-lg border bg-muted/20 flex items-center justify-center">
              <div className="text-center">
                <Network className="h-12 w-12 text-muted-foreground/50 mx-auto mb-4" />
                <p className="text-muted-foreground">
                  {graph.nodes.length} nodes, {graph.edges.length} edges
                </p>
                <p className="text-sm text-muted-foreground mt-1">
                  Export as DOT or Mermaid for visualization
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
