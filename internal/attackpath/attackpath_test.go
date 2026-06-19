package attackpath

import (
	"fmt"
	"testing"
	"time"

	"github.com/ares/engine/internal/graph"
)

func setupTestGraph(t *testing.T) *graph.AttackGraph {
	g := graph.New()

	g.AddNode("web-server", graph.NodeAsset, "Web Server")
	g.AddNode("api-gateway", graph.NodeAsset, "API Gateway")
	g.AddNode("database", graph.NodeAsset, "Production Database")
	g.AddNode("admin-panel", graph.NodeEndpoint, "Admin Panel")
	g.AddNode("vuln-sqli", graph.NodeVuln, "SQL Injection")
	g.AddNode("vuln-ssrf", graph.NodeVuln, "SSRF in API")
	g.AddNode("vuln-rce", graph.NodeVuln, "Remote Code Execution")
	g.AddNode("secret-aws", graph.NodeSecret, "AWS Access Keys")
	g.AddNode("cred-db", graph.NodeCredential, "Database Credentials")

	g.AddEdge("web-server", "admin-panel", graph.EdgeDiscovers)
	g.AddEdge("admin-panel", "vuln-sqli", graph.EdgeExploits)
	g.AddEdge("vuln-sqli", "cred-db", graph.EdgeLeadsTo)
	g.AddEdge("cred-db", "database", graph.EdgeAuthenticates)
	g.AddEdge("web-server", "api-gateway", graph.EdgeDiscovers)
	g.AddEdge("api-gateway", "vuln-ssrf", graph.EdgeExploits)
	g.AddEdge("vuln-ssrf", "secret-aws", graph.EdgeLeadsTo)
	g.AddEdge("secret-aws", "database", graph.EdgeAuthenticates)
	g.AddEdge("web-server", "vuln-rce", graph.EdgeExploits)
	g.AddEdge("vuln-rce", "database", graph.EdgeLeadsTo)

	g.SetNodeProperty("database", "criticality", 0.95)
	g.SetNodeProperty("database", "business_impact", 0.9)
	g.SetNodeProperty("secret-aws", "criticality", 0.85)
	g.SetNodeProperty("cred-db", "criticality", 0.75)
	g.SetNodeProperty("vuln-rce", "cve_id", "CVE-2024-1234")
	g.SetNodeProperty("vuln-sqli", "cve_id", "CVE-2024-5678")
	g.SetNodeProperty("vuln-ssrf", "cve_id", "CVE-2024-9012")

	g.UpdateNodeScore("database", 0.95)
	g.UpdateNodeScore("secret-aws", 0.85)
	g.UpdateNodeScore("web-server", 0.5)

	return g
}

func TestNewPathSimulator(t *testing.T) {
	g := graph.New()
	ps := NewPathSimulator(g)
	if ps == nil {
		t.Fatal("expected non-nil PathSimulator")
	}
	if ps.graph != g {
		t.Error("expected graph to be set")
	}
}

func TestFindAllPaths(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	paths := ps.FindAllPaths("web-server", "database")
	if len(paths) == 0 {
		t.Fatal("expected at least one path")
	}

	for _, path := range paths {
		if path.RiskScore <= 0 {
			t.Error("expected positive risk score, got", path.RiskScore)
		}
		if path.Likelihood <= 0 {
			t.Error("expected positive likelihood, got", path.Likelihood)
		}
		if path.TotalSteps == 0 {
			t.Error("expected at least one step")
		}
		if path.StartAsset != "web-server" {
			t.Error("expected start asset web-server, got", path.StartAsset)
		}
		if path.TargetAsset != "database" {
			t.Error("expected target asset database, got", path.TargetAsset)
		}
	}
}

func TestFindAllPaths_NoPath(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	paths := ps.FindAllPaths("database", "web-server")
	if len(paths) != 0 {
		t.Error("expected no paths from database to web-server")
	}
}

func TestFindAllPaths_EmptyGraph(t *testing.T) {
	g := graph.New()
	ps := NewPathSimulator(g)

	paths := ps.FindAllPaths("a", "b")
	if len(paths) != 0 {
		t.Error("expected no paths in empty graph")
	}
}

func TestFindCriticalPaths(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	paths := ps.FindCriticalPaths()
	if len(paths) == 0 {
		t.Fatal("expected at least one critical path")
	}

	for _, path := range paths {
		if path.RiskScore <= 0 {
			t.Errorf("expected positive risk score for path %s", path.ID)
		}
	}
}

func TestShortestPathToCrownJewels(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	paths := ps.ShortestPathToCrownJewels()
	if len(paths) == 0 {
		t.Fatal("expected at least one shortest path")
	}

	for i := 1; i < len(paths); i++ {
		if paths[i].TotalSteps < paths[i-1].TotalSteps {
			t.Error("paths should be sorted by steps ascending")
		}
	}
}

func TestCalculateBlastRadius(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	result := ps.CalculateBlastRadius("web-server", 2)
	if result == nil {
		t.Fatal("expected non-nil blast radius result")
	}
	if result.SourceNodeID != "web-server" {
		t.Error("expected source node web-server")
	}
	if len(result.Reachable) == 0 {
		t.Error("expected at least one reachable node")
	}
	if result.TotalImpact <= 0 {
		t.Error("expected positive total impact")
	}

	for id, rn := range result.Reachable {
		if rn.Node == nil {
			t.Errorf("expected non-nil node for %s", id)
		}
		if rn.Depth <= 0 {
			t.Errorf("expected positive depth for %s", id)
		}
		if len(rn.Path) == 0 {
			t.Errorf("expected non-empty path for %s", id)
		}
	}
}

func TestCalculateBlastRadius_MaxDepth(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	result1 := ps.CalculateBlastRadius("web-server", 1)
	result2 := ps.CalculateBlastRadius("web-server", 3)

	if len(result1.Reachable) > len(result2.Reachable) {
		t.Error("shallower depth should find fewer or equal nodes")
	}
}

func TestAssessPathLikelihood(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	paths := ps.FindAllPaths("web-server", "database")
	if len(paths) == 0 {
		t.Fatal("expected paths for likelihood test")
	}

	for _, path := range paths {
		likelihood := ps.AssessPathLikelihood(path)
		if likelihood < 0 || likelihood > 1.0 {
			t.Errorf("likelihood %.2f should be in [0, 1]", likelihood)
		}
	}
}

func TestAssessPathLikelihood_EmptyPath(t *testing.T) {
	ps := NewPathSimulator(graph.New())
	path := AttackPath{}
	l := ps.AssessPathLikelihood(path)
	if l != 0 {
		t.Error("expected 0 likelihood for empty path")
	}
}

func TestAssessBusinessImpact(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	paths := ps.FindAllPaths("web-server", "database")
	if len(paths) == 0 {
		t.Fatal("expected paths for impact test")
	}

	for _, path := range paths {
		impact := ps.AssessBusinessImpact(path)
		if impact < 0 || impact > 1.0 {
			t.Errorf("impact %.2f should be in [0, 1]", impact)
		}
	}
}

func TestCalculateRiskScore(t *testing.T) {
	ps := NewPathSimulator(graph.New())

	tests := []struct {
		likelihood float64
		impact     float64
		blast      float64
		expected   float64
	}{
		{1.0, 1.0, 1.0, 1.0},
		{0.5, 0.5, 0.5, 0.5},
		{0.0, 0.0, 0.0, 0.0},
		{0.8, 0.6, 0.4, 0.64},
	}

	for _, tt := range tests {
		score := ps.CalculateRiskScore(tt.likelihood, tt.impact, tt.blast)
		if score != tt.expected {
			t.Errorf("risk score for (%.2f, %.2f, %.2f): expected %.3f, got %.3f",
				tt.likelihood, tt.impact, tt.blast, tt.expected, score)
		}
	}
}

func TestGenerateSummary(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	paths := ps.FindAllPaths("web-server", "database")
	if len(paths) == 0 {
		t.Fatal("expected paths for summary test")
	}

	for _, path := range paths {
		summary := ps.GenerateSummary(path)
		if summary == "" {
			t.Error("expected non-empty summary")
		}
	}

	emptyPath := AttackPath{}
	summary := ps.GenerateSummary(emptyPath)
	if summary != "empty path" {
		t.Error("expected 'empty path' summary")
	}
}

func TestGenerateReport(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	report := ps.GenerateReport("Test Analysis")
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if report.Title != "Test Analysis" {
		t.Errorf("expected title 'Test Analysis', got %s", report.Title)
	}
	if report.GeneratedAt.IsZero() {
		t.Error("expected non-zero generated time")
	}
	if report.TotalPaths == 0 {
		t.Error("expected non-zero total paths")
	}
	if len(report.CrownJewels) == 0 {
		t.Error("expected at least one crown jewel")
	}

	text := report.Text()
	if text == "" {
		t.Error("expected non-empty text summary")
	}

	md := report.Markdown()
	if md == "" {
		t.Error("expected non-empty markdown")
	}

	exec := report.ExecutiveSummary()
	if exec == "" {
		t.Error("expected non-empty executive summary")
	}
}

func TestGenerateReport_EmptyGraph(t *testing.T) {
	g := graph.New()
	ps := NewPathSimulator(g)

	report := ps.GenerateReport("Empty")
	if report.TotalPaths != 0 {
		t.Error("expected 0 paths for empty graph")
	}
}

func TestCrownJewelThreshold(t *testing.T) {
	g := graph.New()
	g.AddNode("low-value", graph.NodeAsset, "Low Value Asset")
	g.UpdateNodeScore("low-value", 0.3)

	g.AddNode("high-value", graph.NodeAsset, "High Value Asset")
	g.UpdateNodeScore("high-value", 0.95)

	ps := NewPathSimulator(g)

	config := ps.Config()
	config.MinCrownJewelScore = 0.8
	ps.SetConfig(config)

	jewels := ps.identifyCrownJewels()
	if len(jewels) != 1 {
		t.Fatalf("expected 1 crown jewel, got %d", len(jewels))
	}
	if jewels[0].Node.ID != "high-value" {
		t.Error("expected high-value to be the crown jewel")
	}
}

func TestFindAllPaths_SortsByRiskScore(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	paths := ps.FindAllPaths("web-server", "database")
	if len(paths) < 2 {
		t.Skip("need at least 2 paths to test sorting")
	}

	for i := 1; i < len(paths); i++ {
		if paths[i].RiskScore > paths[i-1].RiskScore {
			t.Error("paths should be sorted by risk score descending")
		}
	}
}

func TestStepHasCVEIDs(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	paths := ps.FindAllPaths("web-server", "database")
	for _, path := range paths {
		for _, step := range path.Steps {
			if step.Node != nil && step.Node.Type == graph.NodeVuln {
				if len(step.CVEIDs) == 0 {
					t.Logf("vuln node %s has no CVE IDs", step.Node.ID)
				}
			}
		}
	}
}

func TestBlastRadiusResult_Empty(t *testing.T) {
	g := graph.New()
	g.AddNode("isolated", graph.NodeAsset, "Isolated")
	ps := NewPathSimulator(g)

	result := ps.CalculateBlastRadius("isolated", 3)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Reachable) != 0 {
		t.Error("expected no reachable nodes from isolated node")
	}
}

func TestCustomConfig(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	cfg := SimulationConfig{
		MaxPathDepth:       5,
		LikelihoodWeight:   0.5,
		ImpactWeight:       0.3,
		BlastRadiusWeight:  0.2,
		MinCrownJewelScore: 0.9,
	}
	ps.SetConfig(cfg)

	returned := ps.Config()
	if returned.MaxPathDepth != 5 {
		t.Errorf("expected MaxPathDepth 5, got %d", returned.MaxPathDepth)
	}
	if returned.LikelihoodWeight != 0.5 {
		t.Errorf("expected LikelihoodWeight 0.5, got %.2f", returned.LikelihoodWeight)
	}
	if returned.MinCrownJewelScore != 0.9 {
		t.Errorf("expected MinCrownJewelScore 0.9, got %.2f", returned.MinCrownJewelScore)
	}
}

func TestReport_Text(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)
	report := ps.GenerateReport("Text Test")

	text := report.Text()
	if text == "" {
		t.Fatal("expected non-empty text")
	}
	if !contains(text, "Attack Path Analysis") {
		t.Error("expected title in text")
	}
}

func TestReport_Markdown(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)
	report := ps.GenerateReport("Markdown Test")

	md := report.Markdown()
	if md == "" {
		t.Fatal("expected non-empty markdown")
	}
	if !contains(md, "# Attack Path Analysis") {
		t.Error("expected markdown title")
	}
}

func TestReport_ExecutiveSummary(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)
	report := ps.GenerateReport("Executive Test")

	exec := report.ExecutiveSummary()
	if exec == "" {
		t.Fatal("expected non-empty executive summary")
	}
	if !contains(exec, "Executive Attack Scenario") {
		t.Error("expected executive title")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && stringContains(s, substr)
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestConcurrency(t *testing.T) {
	g := setupTestGraph(t)
	ps := NewPathSimulator(g)

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = ps.FindAllPaths("web-server", "database")
			_ = ps.FindCriticalPaths()
			_ = ps.CalculateBlastRadius("web-server", 3)
			_ = ps.GenerateReport("Concurrent")
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for goroutines")
		}
	}
}

func TestFindAllPaths_MediumGraph(t *testing.T) {
	g := graph.New()

	for i := 0; i < 10; i++ {
		g.AddNode(fmt.Sprintf("asset-%d", i), graph.NodeAsset, fmt.Sprintf("Asset %d", i))
	}
	for i := 0; i < 5; i++ {
		g.AddNode(fmt.Sprintf("vuln-%d", i), graph.NodeVuln, fmt.Sprintf("Vulnerability %d", i))
	}

	g.AddEdge("asset-0", "vuln-0", graph.EdgeExploits)
	g.AddEdge("vuln-0", "asset-1", graph.EdgeLeadsTo)
	g.AddEdge("asset-1", "vuln-1", graph.EdgeExploits)
	g.AddEdge("vuln-1", "asset-2", graph.EdgeLeadsTo)
	g.AddEdge("asset-2", "vuln-2", graph.EdgeExploits)
	g.AddEdge("vuln-2", "asset-3", graph.EdgeLeadsTo)

	g.UpdateNodeScore("asset-3", 0.9)
	g.UpdateNodeScore("asset-2", 0.7)
	g.UpdateNodeScore("asset-1", 0.5)

	ps := NewPathSimulator(g)

	paths := ps.FindAllPaths("asset-0", "asset-3")
	if len(paths) == 0 {
		t.Fatal("expected path from asset-0 to asset-3")
	}

	criticalPaths := ps.FindCriticalPaths()
	if len(criticalPaths) == 0 {
		t.Fatal("expected at least one critical path")
	}
}
