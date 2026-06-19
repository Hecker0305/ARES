package runtime

import (
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	g := New(DefaultBudget())
	if g == nil {
		t.Fatal("expected non-nil governor")
	}
}

func TestDefaultBudget(t *testing.T) {
	b := DefaultBudget()
	if b.MaxTokens <= 0 {
		t.Error("expected positive MaxTokens")
	}
	if b.MaxMemoryMB <= 0 {
		t.Error("expected positive MaxMemoryMB")
	}
}

func TestAcquireReleaseToken(t *testing.T) {
	g := New(Budget{MaxTokens: 100})
	g.AcquireToken(50)
	g.AcquireToken(100)
	g.ReleaseToken(50)
	g.AcquireToken(50)
}

func TestAcquireExecution(t *testing.T) {
	g := New(Budget{MaxExecutions: 3})
	if !g.AcquireExecution() {
		t.Error("expected acquire execution to succeed")
	}
	if !g.AcquireExecution() {
		t.Error("expected 2nd acquire to succeed")
	}
	g.ReleaseExecution()
	if g.Usage().ExecutionsUsed != 1 {
		t.Errorf("expected 1 execution used, got %d", g.Usage().ExecutionsUsed)
	}
}

func TestAcquireGoroutine(t *testing.T) {
	g := New(Budget{MaxGoroutines: 2})
	if !g.AcquireGoroutine() {
		t.Error("expected acquire goroutine to succeed")
	}
	if !g.AcquireGoroutine() {
		t.Error("expected 2nd acquire to succeed")
	}
	if g.AcquireGoroutine() {
		t.Error("expected 3rd acquire to fail")
	}
	g.ReleaseGoroutine()
	if !g.AcquireGoroutine() {
		t.Error("expected acquire after release")
	}
}

func TestAcquireReplay(t *testing.T) {
	g := New(Budget{MaxReplays: 1})
	if !g.AcquireReplay() {
		t.Error("expected acquire replay to succeed")
	}
	g.ReleaseReplay()
}

func TestAcquireBrowserOp(t *testing.T) {
	g := New(Budget{MaxBrowserOps: 2})
	if !g.AcquireBrowserOp() {
		t.Error("expected acquire browser op")
	}
	g.ReleaseBrowserOp()
}

func TestUsage(t *testing.T) {
	g := New(Budget{MaxTokens: 1000, MaxMemoryMB: 512, MaxExecutions: 10})
	g.AcquireToken(100)
	g.AcquireExecution()
	u := g.Usage()
	if u.TokensUsed != 100 {
		t.Errorf("expected 100 tokens used, got %d", u.TokensUsed)
	}
	if u.ExecutionsUsed != 1 {
		t.Errorf("expected 1 execution, got %d", u.ExecutionsUsed)
	}
}

func TestBudget(t *testing.T) {
	b := Budget{MaxTokens: 5000}
	g := New(b)
	got := g.Budget()
	if got.MaxTokens != 5000 {
		t.Errorf("expected 5000, got %d", got.MaxTokens)
	}
}

func TestUptime(t *testing.T) {
	g := New(DefaultBudget())
	_ = g.Uptime()
}

func TestCanAccept(t *testing.T) {
	g := New(Budget{MaxTokens: 100, MaxExecutions: 5, MaxMemoryMB: 512})
	_ = g.CanAccept("test-target")
}

func TestReset(t *testing.T) {
	g := New(Budget{MaxExecutions: 5})
	g.AcquireExecution()
	g.AcquireExecution()
	g.Reset()
	u := g.Usage()
	if u.ExecutionsUsed != 0 {
		t.Errorf("expected 0 after reset, got %d", u.ExecutionsUsed)
	}
}

func TestGovernorConcurrency(t *testing.T) {
	g := New(Budget{MaxTokens: 10000, MaxExecutions: 100})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.AcquireToken(50)
			g.ReleaseToken(50)
			g.AcquireExecution()
			g.ReleaseExecution()
			g.Usage()
		}()
	}
	wg.Wait()
}
