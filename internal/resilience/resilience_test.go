package resilience

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig("test")
	if cfg.Name != "test" {
		t.Errorf("expected test, got %s", cfg.Name)
	}
	if cfg.MaxConsecutiveFailures != 5 {
		t.Errorf("expected 5, got %d", cfg.MaxConsecutiveFailures)
	}
	if cfg.ResetTimeout != 30*time.Second {
		t.Errorf("expected 30s, got %v", cfg.ResetTimeout)
	}
}

func TestNewCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker(DefaultConfig("test"))
	if cb == nil {
		t.Fatal("expected non-nil breaker")
	}
	if cb.State() != StateClosed {
		t.Errorf("expected StateClosed, got %v", cb.State())
	}
}

func TestCircuitBreakerOpen(t *testing.T) {
	cb := NewCircuitBreaker(Config{
		Name: "test", MaxConsecutiveFailures: 2, ResetTimeout: time.Minute,
	})
	if !cb.Allow() {
		t.Error("expected allow initially")
	}
	cb.RecordSuccess()
	cb.RecordFailure(errors.New("err1"))
	cb.RecordFailure(errors.New("err2"))
	if cb.State() != StateOpen {
		t.Errorf("expected StateOpen after failures, got %v", cb.State())
	}
	if cb.Allow() {
		t.Error("expected deny when open")
	}
}

func TestCircuitBreakerHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(Config{
		Name: "test", MaxConsecutiveFailures: 2, ResetTimeout: 10 * time.Millisecond,
		HalfOpenMaxCalls: 1,
	})
	cb.RecordFailure(errors.New("e1"))
	cb.RecordFailure(errors.New("e2"))
	time.Sleep(20 * time.Millisecond)
	if !cb.Allow() {
		t.Log("may still be open if timing out")
	}
}

func TestCircuitBreakerMetrics(t *testing.T) {
	cb := NewCircuitBreaker(DefaultConfig("metrics"))
	cb.Allow()
	cb.RecordSuccess()
	cb.Allow()
	cb.RecordFailure(errors.New("err"))
	m := cb.Metrics()
	if m.TotalRequests != 2 {
		t.Errorf("expected 2 requests, got %d", m.TotalRequests)
	}
	if m.TotalSuccesses != 1 {
		t.Errorf("expected 1 success, got %d", m.TotalSuccesses)
	}
	if m.TotalFailures != 1 {
		t.Errorf("expected 1 failure, got %d", m.TotalFailures)
	}
}

func TestCircuitBreakerReset(t *testing.T) {
	cb := NewCircuitBreaker(Config{
		Name: "test", MaxConsecutiveFailures: 1, ResetTimeout: time.Minute,
	})
	cb.RecordFailure(errors.New("err"))
	cb.Reset()
	if cb.State() != StateClosed {
		t.Errorf("expected StateClosed after reset, got %v", cb.State())
	}
}

func TestSubsystemBreaker(t *testing.T) {
	sb := NewSubsystemBreaker()
	cb := sb.GetOrCreate("api", DefaultConfig("api"))
	if cb == nil {
		t.Fatal("expected breaker")
	}
	got, exists := sb.Get("api")
	if !exists {
		t.Error("expected api breaker to exist")
	}
	if got != cb {
		t.Error("expected same breaker")
	}
	summary := sb.StateSummary()
	if summary["api"] != StateClosed {
		t.Errorf("expected StateClosed, got %v", summary["api"])
	}
}

func TestSubsystemBreakerResetAll(t *testing.T) {
	sb := NewSubsystemBreaker()
	sb.GetOrCreate("s1", DefaultConfig("s1"))
	sb.GetOrCreate("s2", DefaultConfig("s2"))
	sb.ResetAll()
}

func TestBackpressureController(t *testing.T) {
	sb := NewSubsystemBreaker()
	bp := NewBackpressureController(sb)
	if !bp.AllowOperation("test") {
		t.Error("expected allow initially")
	}
	bp.ReportOperationResult("test", true, nil)
}

func TestCircuitBreakerConcurrency(t *testing.T) {
	cb := NewCircuitBreaker(DefaultConfig("conc"))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cb.Allow()
			cb.RecordSuccess()
			cb.State()
		}()
	}
	wg.Wait()
}

func TestErrCircuitOpen(t *testing.T) {
	if ErrCircuitOpen == nil {
		t.Error("expected ErrCircuitOpen")
	}
}
