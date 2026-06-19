package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/ares/engine/internal/chainer"
	"github.com/ares/engine/internal/gateway"
	"github.com/ares/engine/internal/graph"
	"github.com/ares/engine/internal/guardrails"
	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/planner"
	"github.com/ares/engine/internal/policy"
	"github.com/ares/engine/internal/sandbox"
	"github.com/ares/engine/internal/verifier"
)

func TestNew(t *testing.T) {
	o := New(Pipeline{})
	if o == nil {
		t.Fatal("expected non-nil orchestrator")
	}
}

func TestStatus(t *testing.T) {
	o := New(Pipeline{})
	status := o.Status()
	if status == nil {
		t.Error("expected non-nil status")
	}
}

func TestResults(t *testing.T) {
	o := New(Pipeline{})
	results := o.Results()
	if results == nil {
		t.Error("expected non-nil results")
	}
}

func TestExecute(t *testing.T) {
	llmCfg := llm.Config{Provider: "ollama", BaseURL: "http://localhost:11434/v1", Model: "llama3.1:70b"}
	llmClient, err := llm.NewClient(llmCfg)
	if err != nil {
		t.Fatalf("LLM client error: %v", err)
	}

	g := graph.New()
	v := verifier.NewEngine()
	c := chainer.New(g)
	pl := planner.New(llmClient, policy.New(), g)
	pe := policy.New()
	sbCfg := sandbox.Config{Level: sandbox.SandboxBasic, WorkDir: t.TempDir()}
	pip := Pipeline{
		LLM:        llmClient,
		Planner:    pl,
		Graph:      g,
		Gateway:    gateway.New(pe, guardrails.NewEngine(guardrails.NewDefaultConfig()), sandbox.NewManager(sbCfg)),
		Policy:     pe,
		Verifier:   v,
		Guardrails: guardrails.NewEngine(guardrails.NewDefaultConfig()),
		Chainer:    c,
		Sandbox:    sandbox.NewManager(sbCfg),
	}
	o := New(pip)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = o.Execute(ctx, "localhost")
}

func TestPhaseResultStruct(t *testing.T) {
	pr := PhaseResult{
		Phase:    "recon",
		Success:  true,
		Duration: time.Second,
	}
	if !pr.Success {
		t.Error("expected success")
	}
}
