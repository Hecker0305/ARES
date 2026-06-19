package control

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/safety"
	"github.com/ares/engine/internal/security"
)

func TestNoGoroutineLeakOnPolicyEvaluation(t *testing.T) {
	// Force GC and get baseline goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	baseline := runtime.NumGoroutine()

	// Create and exercise policy engine repeatedly
	pe := NewPolicyEngine(GovernorConfig{
		MaxTokens:     1000,
		MaxMemoryMB:   512,
		MaxGoroutines: 10,
		MaxExecutions: 100,
	})

	for i := 0; i < 1000; i++ {
		req := UnifiedRequest{
			ID:          string(rune(i)),
			Source:      EnforcementToolCall,
			Action:      "terminal_execute",
			Target:      "test-target",
			RiskLevel:   RiskLow,
			IsNetworkOp: false,
			TokenCost:   1,
			TraceID:     "test-trace",
		}
		resp := pe.Evaluate(req)
		if !resp.Allowed && resp.Reason == "" {
			t.Errorf("evaluation returned denied with empty reason at iteration %d", i)
		}
	}

	// Clean up and check for leaks
	pe = nil
	runtime.GC()
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	final := runtime.NumGoroutine()
	leaked := final - baseline

	// Allow a small tolerance for background goroutines
	if leaked > 5 {
		t.Errorf("potential goroutine leak: baseline=%d, final=%d, leaked=%d", baseline, final, leaked)
	}

	logger.Info("goroutine leak check passed", logger.Fields{
		"baseline": baseline,
		"final":    final,
		"diff":     leaked,
	})
}

func TestNoGoroutineLeakOnGovernorBudget(t *testing.T) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	baseline := runtime.NumGoroutine()

	g := NewGovernor(GovernorConfig{
		MaxTokens:     1000,
		MaxMemoryMB:   512,
		MaxGoroutines: 10,
		MaxExecutions: 100,
	})

	// Exercise budget checks concurrently
	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				g.CanExecute(10)
				g.RateLimiter("test", 10, 20).Allow()
				g.Usage()
			}
			done <- struct{}{}
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	g = nil
	runtime.GC()
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	final := runtime.NumGoroutine()
	leaked := final - baseline

	if leaked > 5 {
		t.Errorf("potential goroutine leak: baseline=%d, final=%d, leaked=%d", baseline, final, leaked)
	}
}

func TestNoGoroutineLeakOnSafetyModeCheck(t *testing.T) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	baseline := runtime.NumGoroutine()

	sm := safety.NewSafetyModeManager(safety.SafeMode)

	for i := 0; i < 10000; i++ {
		// Exercise various safety checks
		sm.CanPerform("terminal_execute", safety.RiskMedium, true)
		sm.CanPerform("http_request", safety.RiskLow, true)
		sm.RequireApproval(safety.RiskHigh)
		_ = sm.CurrentMode()
	}

	sm = nil
	runtime.GC()
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	final := runtime.NumGoroutine()
	leaked := final - baseline

	if leaked > 5 {
		t.Errorf("potential goroutine leak: baseline=%d, final=%d, leaked=%d", baseline, final, leaked)
	}
}

func TestKernelValidationNoLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	baseline := runtime.NumGoroutine()

	// Use the default kernel singleton
	k := security.GetK()

	for i := 0; i < 10000; i++ {
		req := security.ActionRequest{
			Type:     security.ActionToolCall,
			ToolName: "test_tool",
			Source:   "test",
		}
		_ = k.ValidateAction(context.TODO(), req)
	}

	runtime.GC()
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	final := runtime.NumGoroutine()
	leaked := final - baseline

	if leaked > 5 {
		t.Errorf("potential goroutine leak: baseline=%d, final=%d, leaked=%d", baseline, final, leaked)
	}
}
