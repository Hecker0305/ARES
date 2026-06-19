package hooks

import (
	"sync"
	"testing"
	"time"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("expected non-nil registry")
	}
}

func TestRegisterAndFire(t *testing.T) {
	r := NewRegistry()
	called := false
	r.Register(OnToolCallHook, func(e HookEvent) HookResult {
		called = true
		return HookResult{}
	})
	result := r.Fire(OnToolCallHook, HookEvent{ScanID: "test"})
	if !called {
		t.Error("expected handler to be called")
	}
	if result.Blocked {
		t.Error("expected not blocked")
	}
}

func TestFireBlocked(t *testing.T) {
	r := NewRegistry()
	r.Register(OnToolCallHook, func(e HookEvent) HookResult {
		return HookResult{Blocked: true, Message: "blocked"}
	})
	r.Register(OnToolCallHook, func(e HookEvent) HookResult {
		t.Error("second handler should not be called after block")
		return HookResult{}
	})
	result := r.Fire(OnToolCallHook, HookEvent{ScanID: "test"})
	if !result.Blocked {
		t.Error("expected blocked")
	}
	if result.Message != "blocked" {
		t.Errorf("expected 'blocked', got %s", result.Message)
	}
}

func TestMultipleHandlers(t *testing.T) {
	r := NewRegistry()
	count := 0
	var mu sync.Mutex
	for i := 0; i < 3; i++ {
		r.Register(OnToolResultHook, func(e HookEvent) HookResult {
			mu.Lock()
			count++
			mu.Unlock()
			return HookResult{}
		})
	}
	r.Fire(OnToolResultHook, HookEvent{ScanID: "test"})
	mu.Lock()
	if count != 3 {
		t.Errorf("expected 3 handler calls, got %d", count)
	}
	mu.Unlock()
}

func TestFireNoHandlers(t *testing.T) {
	r := NewRegistry()
	result := r.Fire(OnToolCallHook, HookEvent{ScanID: "test"})
	if result.Blocked {
		t.Error("expected not blocked when no handlers")
	}
}

func TestOnFinishAttempt(t *testing.T) {
	tests := []struct {
		state   ScanState
		blocked bool
	}{
		{ScanState{UnverifiedCount: 1}, true},
		{ScanState{UnverifiedCount: 0, ConfirmedCount: 0, StartTime: time.Now()}, true},
		{ScanState{UnverifiedCount: 0, ConfirmedCount: 5, StartTime: time.Now().Add(-15 * time.Minute)}, false},
	}
	for _, tt := range tests {
		result := OnFinishAttempt(tt.state)
		if result.Blocked != tt.blocked {
			t.Errorf("OnFinishAttempt(%+v) blocked=%v, want %v", tt.state, result.Blocked, tt.blocked)
		}
	}
}

func TestOnRepeatCommand(t *testing.T) {
	tests := []struct {
		cmd     string
		history []string
		blocked bool
	}{
		{"ls", []string{}, false},
		{"ls", []string{"ls"}, false},
		{"ls", []string{"ls", "ls", "ls"}, true},
		{"ls", []string{"ls", "ls", "ls", "ls"}, true},
	}
	for _, tt := range tests {
		result := OnRepeatCommand(tt.cmd, tt.history)
		if result.Blocked != tt.blocked {
			t.Errorf("OnRepeatCommand(%q, %v) blocked=%v, want %v", tt.cmd, tt.history, result.Blocked, tt.blocked)
		}
	}
}

func TestConcurrency(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Register(OnToolCallHook, func(e HookEvent) HookResult {
				return HookResult{}
			})
		}()
	}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Fire(OnToolCallHook, HookEvent{ScanID: "test"})
		}()
	}
	wg.Wait()
}
