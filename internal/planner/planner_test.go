package planner

import (
	"testing"

	"github.com/ares/engine/internal/graph"
	"github.com/ares/engine/internal/policy"
)

func TestNewPlanner(t *testing.T) {
	g := graph.New()
	pe := policy.New()
	p := New(nil, pe, g)
	if p == nil {
		t.Fatal("expected non-nil planner")
	}
}

func TestDecomposeTarget(t *testing.T) {
	g := graph.New()
	pe := policy.New()
	p := New(nil, pe, g)
	objectives := p.DecomposeTarget("example.com")
	if len(objectives) == 0 {
		t.Fatal("expected objectives")
	}
	if objectives[0].Goal == "" {
		t.Error("expected non-empty goal")
	}
}

func TestGeneratePlan(t *testing.T) {
	g := graph.New()
	pe := policy.New()
	p := New(nil, pe, g)
	objectives := p.DecomposeTarget("test.com")
	plan := p.GeneratePlan("test.com", objectives)
	if plan.ID == "" {
		t.Error("expected non-empty plan ID")
	}
	if plan.Chain.Summary == "" {
		t.Error("expected non-empty chain summary")
	}
}

func TestMarkCompleted(t *testing.T) {
	g := graph.New()
	pe := policy.New()
	p := New(nil, pe, g)
	p.DecomposeTarget("example.com")
	obj := p.objectives[0]
	p.MarkCompleted(obj.ID)
	if !p.objectives[0].Completed {
		t.Error("expected objective to be completed")
	}
}

func TestNextPhase(t *testing.T) {
	g := graph.New()
	pe := policy.New()
	p := New(nil, pe, g)
	p.DecomposeTarget("example.com")
	phase, _ := p.NextPhase()
	if phase != PhaseRecon {
		t.Errorf("expected PhaseRecon, got %d", phase)
	}
}

func TestSuggestNextActions(t *testing.T) {
	g := graph.New()
	pe := policy.New()
	p := New(nil, pe, g)
	p.DecomposeTarget("example.com")
	suggestions := p.SuggestNextActions("example.com")
	if len(suggestions) == 0 {
		t.Error("expected suggestions")
	}
}

func TestActivePlan(t *testing.T) {
	g := graph.New()
	pe := policy.New()
	p := New(nil, pe, g)
	p.DecomposeTarget("test.com")
	p.GeneratePlan("test.com", nil)
	plan, found := p.ActivePlan("test.com")
	if !found {
		t.Error("expected active plan")
	}
	_ = plan
}

func TestStatus(t *testing.T) {
	g := graph.New()
	pe := policy.New()
	p := New(nil, pe, g)
	p.DecomposeTarget("test.com")
	status := p.Status()
	if status["total_objectives"].(int) == 0 {
		t.Error("expected non-zero objectives after DecomposeTarget")
	}
}

func TestAgentsForPhase(t *testing.T) {
	g := graph.New()
	pe := policy.New()
	p := New(nil, pe, g)
	agents := p.AgentsForPhase(PhaseExploit)
	if len(agents) == 0 {
		t.Error("expected agents for exploit phase")
	}
}

func TestAutoPlan(t *testing.T) {
	g := graph.New()
	pe := policy.New()
	p := New(nil, pe, g)
	plan := p.GeneratePlan("test.com", nil)
	if plan.ID == "" {
		t.Error("expected auto-generated plan with ID")
	}
}

func TestClassifyTarget(t *testing.T) {
	g := graph.New()
	pe := policy.New()
	p := New(nil, pe, g)
	if cls := p.classifyTarget("example.com"); cls != "web" {
		t.Errorf("expected 'web' for example.com, got %s", cls)
	}
	if cls := p.classifyTarget("api.internal"); cls != "api" {
		t.Errorf("expected 'api' for api.internal, got %s", cls)
	}
	if cls := p.classifyTarget("graphql.internal"); cls != "api" {
		t.Errorf("expected 'api' for graphql.internal, got %s", cls)
	}
}
