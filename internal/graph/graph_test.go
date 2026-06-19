package graph

import (
	"fmt"
	"testing"
)

func TestNewGraph(t *testing.T) {
	g := New()
	if g == nil {
		t.Fatal("expected non-nil graph")
	}
	if g.NodeCount() != 0 {
		t.Errorf("expected 0 nodes, got %d", g.NodeCount())
	}
}

func TestAddNode(t *testing.T) {
	g := New()
	n := g.AddNode("host-1", NodeAsset, "192.168.1.1")
	if n == nil {
		t.Fatal("expected non-nil node")
	}
	if n.ID != "host-1" {
		t.Errorf("expected ID 'host-1', got %s", n.ID)
	}
	if g.NodeCount() != 1 {
		t.Errorf("expected 1 node, got %d", g.NodeCount())
	}
}

func TestGetNode(t *testing.T) {
	g := New()
	g.AddNode("vuln-1", NodeVuln, "SQL Injection")
	n := g.GetNode("vuln-1")
	if n == nil {
		t.Fatal("expected non-nil node")
	}
	if n.Label != "SQL Injection" {
		t.Errorf("expected label 'SQL Injection', got %s", n.Label)
	}
	if g.GetNode("nonexistent") != nil {
		t.Error("expected nil for nonexistent node")
	}
}

func TestRemoveNode(t *testing.T) {
	g := New()
	g.AddNode("n1", NodeAsset, "host1")
	g.AddNode("n2", NodeVuln, "vuln")
	g.AddEdge("n1", "n2", EdgeExploits)
	g.RemoveNode("n2")
	if g.GetNode("n2") != nil {
		t.Error("expected node to be removed")
	}
	if g.NodeCount() != 1 {
		t.Errorf("expected 1 node, got %d", g.NodeCount())
	}
}

func TestAddEdge(t *testing.T) {
	g := New()
	g.AddNode("src", NodeAsset, "source")
	g.AddNode("dst", NodeVuln, "target")
	e := g.AddEdge("src", "dst", EdgeExploits)
	if e == nil {
		t.Fatal("expected non-nil edge")
	}
	if e.SourceID != "src" || e.TargetID != "dst" {
		t.Errorf("unexpected edge endpoints: %s -> %s", e.SourceID, e.TargetID)
	}
	if g.EdgeCount() != 1 {
		t.Errorf("expected 1 edge, got %d", g.EdgeCount())
	}
}

func TestAddEdgeMissingNode(t *testing.T) {
	g := New()
	g.AddNode("src", NodeAsset, "source")
	e := g.AddEdge("src", "missing", EdgeExploits)
	if e != nil {
		t.Error("expected nil edge for missing target")
	}
	e2 := g.AddEdge("missing", "src", EdgeExploits)
	if e2 != nil {
		t.Error("expected nil edge for missing source")
	}
}

func TestGetOutgoing(t *testing.T) {
	g := New()
	g.AddNode("n1", NodeAsset, "host1")
	g.AddNode("n2", NodeVuln, "vuln1")
	g.AddNode("n3", NodeVuln, "vuln2")
	g.AddEdge("n1", "n2", EdgeExploits)
	g.AddEdge("n1", "n3", EdgeLeadsTo)

	out := g.GetOutgoing("n1")
	if len(out) != 2 {
		t.Errorf("expected 2 outgoing edges, got %d", len(out))
	}
}

func TestGetIncoming(t *testing.T) {
	g := New()
	g.AddNode("n1", NodeAsset, "host1")
	g.AddNode("n2", NodeVuln, "vuln1")
	g.AddEdge("n1", "n2", EdgeExploits)

	in := g.GetIncoming("n2")
	if len(in) != 1 {
		t.Errorf("expected 1 incoming edge, got %d", len(in))
	}
}

func TestFindChains(t *testing.T) {
	g := New()
	g.AddNode("a", NodeAsset, "host")
	g.AddNode("b", NodeVuln, "SSRF")
	g.AddNode("c", NodeSecret, "internal_creds")
	g.AddNode("d", NodeEndpoint, "admin_panel")
	g.AddEdge("a", "b", EdgeExploits)
	g.AddEdge("b", "c", EdgeLeadsTo)
	g.AddEdge("c", "d", EdgeAuthenticates)

	chains := g.FindChains("a", "d", 5)
	if len(chains) == 0 {
		t.Fatal("expected at least 1 chain")
	}
	if len(chains[0].Nodes) != 4 {
		t.Errorf("expected 4 nodes in chain, got %d", len(chains[0].Nodes))
	}
}

func TestFindChainsMaxDepth(t *testing.T) {
	g := New()
	g.AddNode("a", NodeAsset, "start")
	g.AddNode("b", NodeVuln, "mid")
	g.AddNode("c", NodeEndpoint, "end")
	g.AddEdge("a", "b", EdgeExploits)
	g.AddEdge("b", "c", EdgeExploits)

	chains := g.FindChains("a", "c", 1)
	if len(chains) != 0 {
		t.Error("expected no chains when maxDepth=1 for depth-2 path")
	}
}

func TestHighestScorePath(t *testing.T) {
	g := New()
	g.AddNode("a", NodeAsset, "host")
	g.AddNode("b", NodeVuln, "low_risk")
	g.AddNode("c", NodeVuln, "critical")
	g.AddNode("d", NodeEndpoint, "admin")
	g.AddEdge("a", "b", EdgeExploits)
	g.AddEdge("a", "c", EdgeExploits)
	g.AddEdge("b", "d", EdgeLeadsTo)
	g.AddEdge("c", "d", EdgeLeadsTo)
	g.UpdateNodeScore("c", 0.95)
	g.UpdateNodeScore("b", 0.3)

	chain := g.HighestScorePath("a", "d", 5)
	if chain == nil {
		t.Fatal("expected non-nil best chain")
	}
}

func TestSuggestNextTargets(t *testing.T) {
	g := New()
	g.AddNode("a", NodeAsset, "attacker")
	g.AddNode("b", NodeVuln, "SQLi")
	g.AddNode("c", NodeSecret, "db_creds")
	g.AddNode("d", NodeEndpoint, "internal_db")
	g.AddEdge("a", "b", EdgeExploits)
	g.AddEdge("b", "c", EdgeLeadsTo)
	g.AddEdge("c", "d", EdgeAuthenticates)
	g.UpdateNodeScore("b", 0.8)
	g.UpdateNodeScore("c", 0.7)
	g.UpdateNodeScore("d", 0.9)
	g.UpdateEdgeWeight("a", "b", 0.9)

	suggestions := g.SuggestNextTargets("a", 0.5)
	if len(suggestions) == 0 {
		t.Error("expected at least 1 suggestion")
	}
}

func TestAssessDifficulty(t *testing.T) {
	g := New()
	g.AddNode("a", NodeAsset, "start")
	g.AddNode("b", NodeSecret, "secret")
	g.AddEdge("a", "b", EdgeExploits)
	g.UpdateEdgeWeight("a", "b", 0.9)

	chains := g.FindChains("a", "b", 5)
	if len(chains) == 0 {
		t.Fatal("expected at least 1 chain")
	}
	difficulty := g.AssessDifficulty(chains[0])
	if difficulty != "trivial" {
		t.Errorf("expected 'trivial', got %s", difficulty)
	}
}

func TestAllNodes(t *testing.T) {
	g := New()
	g.AddNode("n1", NodeAsset, "host1")
	g.AddNode("n2", NodeVuln, "vuln1")
	nodes := g.AllNodes()
	if len(nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(nodes))
	}
}

func TestAllEdges(t *testing.T) {
	g := New()
	g.AddNode("a", NodeAsset, "host")
	g.AddNode("b", NodeVuln, "vuln")
	g.AddEdge("a", "b", EdgeExploits)
	edges := g.AllEdges()
	if len(edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(edges))
	}
}

func TestSetNodeProperty(t *testing.T) {
	g := New()
	g.AddNode("n1", NodeAsset, "host")
	g.SetNodeProperty("n1", "ip", "10.0.0.1")
	g.SetNodeProperty("n1", "os", "linux")
	node := g.GetNode("n1")
	if node.Properties["ip"] != "10.0.0.1" {
		t.Errorf("expected property ip=10.0.0.1, got %v", node.Properties["ip"])
	}
}

func TestToJSON(t *testing.T) {
	g := New()
	g.AddNode("n1", NodeAsset, "test")
	data, err := g.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestNodeTypes(t *testing.T) {
	types := map[NodeType]string{
		NodeAsset:      "asset",
		NodeVuln:       "vulnerability",
		NodeSecret:     "secret",
		NodeEndpoint:   "endpoint",
		NodeCredential: "credential",
		NodeService:    "service",
		NodeTechnique:  "technique",
	}
	for nt, expected := range types {
		if string(nt) != expected {
			t.Errorf("expected %s, got %s", expected, string(nt))
		}
	}
}

func TestEdgeTypes(t *testing.T) {
	types := map[EdgeType]string{
		EdgeExploits:      "exploits",
		EdgeLeadsTo:       "leads_to",
		EdgeRequires:      "requires",
		EdgeBypasses:      "bypasses",
		EdgeMitigates:     "mitigates",
		EdgeDiscovers:     "discovers",
		EdgeAuthenticates: "authenticates_to",
	}
	for et, expected := range types {
		if string(et) != expected {
			t.Errorf("expected %s, got %s", expected, string(et))
		}
	}
}

func TestUpdateNodeScore(t *testing.T) {
	g := New()
	g.AddNode("n1", NodeAsset, "host")
	g.UpdateNodeScore("n1", 0.85)
	node := g.GetNode("n1")
	if node.Score != 0.85 {
		t.Errorf("expected score 0.85, got %f", node.Score)
	}
}

func TestUpdateEdgeWeight(t *testing.T) {
	g := New()
	g.AddNode("a", NodeAsset, "src")
	g.AddNode("b", NodeVuln, "dst")
	g.AddEdge("a", "b", EdgeExploits)
	g.UpdateEdgeWeight("a", "b", 0.95)
	out := g.GetOutgoing("a")
	if out[0].Weight != 0.95 {
		t.Errorf("expected weight 0.95, got %f", out[0].Weight)
	}
}

func TestEmptyChain(t *testing.T) {
	g := New()
	chains := g.FindChains("nonexistent", "also_missing", 5)
	if len(chains) != 0 {
		t.Error("expected empty chains for missing nodes")
	}
}

func TestConcurrentAccess(t *testing.T) {
	g := New()
	done := make(chan bool)
	for i := 0; i < 50; i++ {
		go func(idx int) {
			g.AddNode(fmt.Sprintf("n%d", idx), NodeAsset, fmt.Sprintf("node%d", idx))
			done <- true
		}(i)
	}
	for i := 0; i < 50; i++ {
		<-done
	}
	if g.NodeCount() != 50 {
		t.Errorf("expected 50 nodes, got %d", g.NodeCount())
	}
}
