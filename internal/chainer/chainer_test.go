package chainer

import (
	"testing"

	"github.com/ares/engine/internal/graph"
)

func TestNewChainer(t *testing.T) {
	g := graph.New()
	c := New(g)
	if c == nil {
		t.Fatal("expected non-nil chainer")
	}
}

func TestAnalyze_NoFindings(t *testing.T) {
	g := graph.New()
	c := New(g)
	chains := c.Analyze([]string{"nonexistent"})
	if len(chains) != 0 {
		t.Error("expected no chains for nonexistent findings")
	}
}

func TestAnalyze_SSRFChain(t *testing.T) {
	g := graph.New()
	c := New(g)
	chains := c.Analyze([]string{"ssrf"})
	if len(chains) == 0 {
		t.Fatal("expected chain for ssrf")
	}
	if chains[0].Impact != "critical" {
		t.Errorf("expected critical impact, got %s", chains[0].Impact)
	}
}

func TestAnalyze_SQLiChain(t *testing.T) {
	g := graph.New()
	c := New(g)
	chains := c.Analyze([]string{"sqli"})
	if len(chains) == 0 {
		t.Fatal("expected chain for sqli")
	}
}

func TestAnalyze_MultiPrereqChain(t *testing.T) {
	g := graph.New()
	c := New(g)
	chains := c.Analyze([]string{"weak_jwt", "exposed_admin"})
	hasAdminChain := false
	for _, chain := range chains {
		if chain.Summary == "weak_jwt → exposed_admin → admin_access" {
			hasAdminChain = true
			break
		}
	}
	if !hasAdminChain {
		t.Error("expected admin_access chain from weak_jwt + exposed_admin")
	}
}

func TestHighValueChains(t *testing.T) {
	g := graph.New()
	c := New(g)
	c.Analyze([]string{"ssrf"})
	high := c.HighValueChains(0.5)
	if len(high) == 0 {
		t.Error("expected at least 1 high-value chain")
	}
}

func TestImpactSummary(t *testing.T) {
	g := graph.New()
	c := New(g)
	c.Analyze([]string{"ssrf", "sqli", "xss"})
	summary := c.ImpactSummary()
	if len(summary) == 0 {
		t.Error("expected non-empty impact summary")
	}
}

func TestAllChains(t *testing.T) {
	g := graph.New()
	c := New(g)
	c.Analyze([]string{"ssrf"})
	all := c.AllChains()
	if len(all) == 0 {
		t.Error("expected chains")
	}
}

func TestReset(t *testing.T) {
	g := graph.New()
	c := New(g)
	c.Analyze([]string{"sqli"})
	c.Reset()
	if len(c.AllChains()) != 0 {
		t.Error("expected empty after reset")
	}
}

func TestScoreChain(t *testing.T) {
	g := graph.New()
	c := New(g)
	steps := []ChainStep{
		{Type: "ssrf", Confidence: 0.9},
		{Type: "cloud_credentials", Confidence: 0.8, Impact: "critical"},
	}
	score := c.scoreChain(steps)
	if score <= 0 {
		t.Error("expected positive score")
	}
}

func TestChainRulesExistence(t *testing.T) {
	if len(chainRules) == 0 {
		t.Error("expected at least 1 chain rule")
	}
	names := make(map[string]bool)
	for _, rule := range chainRules {
		if names[rule.Name] {
			t.Errorf("duplicate rule name: %s", rule.Name)
		}
		names[rule.Name] = true
	}
}
