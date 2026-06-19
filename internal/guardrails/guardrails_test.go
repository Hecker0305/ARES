package guardrails

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	if cfg.MaxTokenLen != 128000 {
		t.Errorf("expected 128000, got %d", cfg.MaxTokenLen)
	}
	if !cfg.EnablePromptGuard {
		t.Error("expected prompt guard enabled")
	}
}

func TestNewEngine(t *testing.T) {
	e := NewEngine(NewDefaultConfig())
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestCheckPrompt(t *testing.T) {
	e := NewEngine(NewDefaultConfig())
	detections := e.CheckPrompt("normal safe prompt without injection")
	if detections != nil {
		t.Logf("got %d detections for safe prompt", len(detections))
	}
}

func TestCheckOutput(t *testing.T) {
	e := NewEngine(NewDefaultConfig())
	detections := e.CheckOutput("normal safe output")
	if detections != nil {
		t.Logf("got %d detections for safe output", len(detections))
	}
}

func TestSanitizeOutput(t *testing.T) {
	e := NewEngine(NewDefaultConfig())
	result := e.SanitizeOutput("test output")
	if result == "" {
		t.Error("expected non-empty output")
	}
}

func TestShouldBlock(t *testing.T) {
	e := NewEngine(NewDefaultConfig())
	if e.ShouldBlock(nil) {
		t.Error("expected not to block nil detections")
	}
}

func TestNewToolAbuseDetector(t *testing.T) {
	d := NewToolAbuseDetector([]string{"nmap", "curl"})
	if d == nil {
		t.Fatal("expected non-nil detector")
	}
}

func TestNewRecursiveLoopDetector(t *testing.T) {
	d := NewRecursiveLoopDetector(60, 10)
	if d == nil {
		t.Fatal("expected non-nil detector")
	}
}
