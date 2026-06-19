package explain

import (
	"testing"

	"github.com/ares/engine/internal/chainer"
	"github.com/ares/engine/internal/graph"
	"github.com/ares/engine/internal/verifier"
)

func TestNew(t *testing.T) {
	g := graph.New()
	v := verifier.NewEngine()
	c := chainer.New(g)
	gen := New(g, c, v)
	if gen == nil {
		t.Fatal("expected non-nil generator")
	}
}

func TestGenerateNarrative(t *testing.T) {
	g := graph.New()
	v := verifier.NewEngine()
	c := chainer.New(g)
	gen := New(g, c, v)
	narrative := gen.GenerateNarrative("sqli", "http://example.com", "' OR '1'='1", "extracted data", 0.95)
	_ = narrative
}

func TestFindingsSummary(t *testing.T) {
	g := graph.New()
	v := verifier.NewEngine()
	c := chainer.New(g)
	gen := New(g, c, v)
	summary := gen.FindingsSummary([]ExploitNarrative{
		{Title: "SQLi", Severity: "critical"},
	})
	if summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestFullReport(t *testing.T) {
	g := graph.New()
	v := verifier.NewEngine()
	c := chainer.New(g)
	gen := New(g, c, v)
	report := gen.FullReport([]ExploitNarrative{
		{Title: "SQLi", Severity: "critical", Target: "example.com"},
	})
	if report == "" {
		t.Error("expected non-empty report")
	}
}

func TestExploitNarrativeStruct(t *testing.T) {
	n := ExploitNarrative{
		FindingID:    "FIND-001",
		Title:        "SQL Injection",
		Severity:     "critical",
		Confidence:   0.95,
		Reproducible: true,
	}
	if n.Confidence != 0.95 {
		t.Errorf("expected 0.95, got %f", n.Confidence)
	}
}
