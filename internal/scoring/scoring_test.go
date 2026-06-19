package scoring

import (
	"testing"
)

func TestNewAttackGraph(t *testing.T) {
	g := NewAttackGraph()
	if g == nil {
		t.Error("NewAttackGraph() returned nil")
	}
	if g.nodes == nil {
		t.Error("nodes map is nil")
	}
	if g.edges == nil {
		t.Error("edges map is nil")
	}
}

func TestAttackGraph_AddNode(t *testing.T) {
	g := NewAttackGraph()
	node := &AttackNode{
		ID:       "test-node",
		Type:     "recon",
		PInit:    0.5,
		PDetect:  0.1,
		Impact:   0.8,
		Cost:     0.2,
		VulnType: "sqli",
	}

	g.AddNode(node)

	if _, ok := g.nodes["test-node"]; !ok {
		t.Error("Node not added to graph")
	}
}

func TestAttackGraph_AddEdge(t *testing.T) {
	g := NewAttackGraph()
	g.AddNode(&AttackNode{ID: "node1"})
	g.AddNode(&AttackNode{ID: "node2"})

	g.AddEdge("node1", "node2")

	edges := g.edges["node1"]
	if len(edges) != 1 || edges[0] != "node2" {
		t.Errorf("Edge not added correctly")
	}
}

func TestAttackGraph_Expand(t *testing.T) {
	g := NewAttackGraph()
	g.AddNode(&AttackNode{ID: "root", Type: "recon"})
	g.AddNode(&AttackNode{ID: "child1", Type: "exploit"})
	g.AddNode(&AttackNode{ID: "child2", Type: "exploit"})

	g.AddEdge("root", "child1")
	g.AddEdge("root", "child2")

	nodes := g.Expand("root", 2)
	if len(nodes) != 3 {
		t.Errorf("Expand() returned %d nodes, want 3", len(nodes))
	}
}

func TestScoringEngine_CalculateEV(t *testing.T) {
	graph := NewAttackGraph()
	engine := NewScoringEngine(graph)

	node := &AttackNode{
		PInit:     0.5,
		PDetect:   0.1,
		Impact:    0.8,
		Cost:      0.2,
		VulnType:  "sqli",
		CVSSScore: 7.5,
	}

	ctx := map[string]interface{}{"waf_detected": false}
	ev, err := engine.CalculateEV(node, ctx)
	if err != nil {
		t.Fatalf("CalculateEV() error = %v", err)
	}

	if ev <= 0 {
		t.Errorf("CalculateEV() = %v, want > 0", ev)
	}
}

func TestScoringEngine_CalculateEV_WithWAF(t *testing.T) {
	graph := NewAttackGraph()
	engine := NewScoringEngine(graph)

	engine.UpdateWAFModifier("sqli", 0.5)

	node := &AttackNode{
		PInit:     0.5,
		PDetect:   0.1,
		Impact:    0.8,
		Cost:      0.2,
		VulnType:  "sqli",
		CVSSScore: 7.5,
	}

	ctx := map[string]interface{}{"waf_detected": true}
	ev, err := engine.CalculateEV(node, ctx)
	if err != nil {
		t.Fatalf("CalculateEV() error = %v", err)
	}

	if ev <= 0 {
		t.Errorf("CalculateEV() with WAF = %v, want > 0", ev)
	}
}

func TestScoringEngine_RankNodes(t *testing.T) {
	graph := NewAttackGraph()
	engine := NewScoringEngine(graph)

	nodes := []*AttackNode{
		{ID: "low", PInit: 0.3, PDetect: 0.1, Impact: 0.3, Cost: 0.5, CVSSScore: 3.0},
		{ID: "high", PInit: 0.8, PDetect: 0.1, Impact: 0.9, Cost: 0.1, CVSSScore: 9.0},
	}

	ranked, err := engine.RankNodes(nodes, map[string]interface{}{})
	if err != nil {
		t.Fatalf("RankNodes() error = %v", err)
	}

	if ranked[0].ID != "high" {
		t.Errorf("RankNodes() first = %q, want high", ranked[0].ID)
	}
}

func TestScoringEngine_SuggestNextAttack(t *testing.T) {
	graph := NewAttackGraph()
	engine := NewScoringEngine(graph)

	graph.AddNode(&AttackNode{ID: "target1", Type: "recon", PInit: 0.8, PDetect: 0.1, Impact: 0.9, Cost: 0.1, CVSSScore: 8.0})
	graph.AddNode(&AttackNode{ID: "target2", Type: "recon", PInit: 0.2, PDetect: 0.1, Impact: 0.2, Cost: 0.5, CVSSScore: 3.0})

	suggestion, err := engine.SuggestNextAttack([]string{"target1", "target2"}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("SuggestNextAttack() error = %v", err)
	}

	if suggestion != "target1" {
		t.Errorf("SuggestNextAttack() = %q, want target1", suggestion)
	}
}

func TestAgentChain_AddAgent(t *testing.T) {
	chain := NewAgentChain()
	chain.AddAgent("agent1", "recon", []string{"target1", "target2"})

	if len(chain.agents) != 1 {
		t.Errorf("agents length = %d, want 1", len(chain.agents))
	}

	agent := chain.agents["agent1"]
	if agent.Role != "recon" {
		t.Errorf("agent role = %q, want recon", agent.Role)
	}
}

func TestAgentChain_Connect(t *testing.T) {
	chain := NewAgentChain()
	chain.AddAgent("a1", "recon", []string{"t1"})
	chain.AddAgent("a2", "exploit", []string{"t2"})
	chain.Connect("t1", "t2")

	edges := chain.graph.edges["t1"]
	if len(edges) != 1 || edges[0] != "t2" {
		t.Error("Edge not connected properly")
	}
}

func TestAgentChain_Execute(t *testing.T) {
	chain := NewAgentChain()
	chain.AddAgent("agent1", "recon", []string{"target1"})

	err := chain.Execute()
	if err != nil {
		t.Errorf("Execute() error = %v", err)
	}

	if chain.agents["agent1"].State != "completed" {
		t.Errorf("agent state = %q, want completed", chain.agents["agent1"].State)
	}
}

func TestAgentChain_GetReport(t *testing.T) {
	chain := NewAgentChain()
	chain.AddAgent("a1", "recon", []string{"t1"})
	chain.AddAgent("a2", "exploit", []string{"t2"})

	report := chain.GetReport()

	if len(report) == 0 {
		t.Error("GetReport() returned empty string")
	}
}
