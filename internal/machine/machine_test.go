package machine

import (
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	sm := New("test-machine", StateDiscovered)
	if sm == nil {
		t.Fatal("expected non-nil state machine")
	}
	if sm.Current() != StateDiscovered {
		t.Errorf("expected Discovered, got %s", sm.Current())
	}
}

func TestTransition(t *testing.T) {
	sm := New("test", StateDiscovered)
	err := sm.Transition(StateFingerprinted)
	if err != nil {
		t.Errorf("Transition error: %v", err)
	}
	if sm.Current() != StateFingerprinted {
		t.Errorf("expected Fingerprinted, got %s", sm.Current())
	}
}

func TestTransitionInvalid(t *testing.T) {
	sm := New("test", StateDiscovered)
	err := sm.Transition(StateVerified)
	if err == nil {
		t.Error("expected error for invalid transition")
	}
}

func TestForce(t *testing.T) {
	sm := New("test", StateDiscovered)
	err := sm.Force(StateClosed, "test force", "test-user")
	if err != nil {
		t.Errorf("Force error: %v", err)
	}
	if sm.Current() != StateClosed {
		t.Errorf("expected Closed after force, got %s", sm.Current())
	}
}

func TestCanTransition(t *testing.T) {
	sm := New("test", StateDiscovered)
	if !sm.CanTransition(StateFingerprinted) {
		t.Error("expected valid transition")
	}
	if sm.CanTransition(StateClosed) {
		t.Error("expected invalid transition")
	}
}

func TestHistory(t *testing.T) {
	sm := New("test", StateDiscovered)
	sm.Transition(StateFingerprinted)
	sm.Transition(StateTesting)
	history := sm.History()
	if len(history) < 2 {
		t.Errorf("expected at least 2 history entries, got %d", len(history))
	}
}

func TestIsTerminal(t *testing.T) {
	sm := New("test", StateDiscovered)
	if sm.IsTerminal() {
		t.Error("expected not terminal initially")
	}
	sm.Force(StateClosed, "test force", "test-user")
	if !sm.IsTerminal() {
		t.Error("expected terminal after Close")
	}
}

func TestOnEnter(t *testing.T) {
	sm := New("test", StateDiscovered)
	called := false
	sm.OnEnter(StateFingerprinted, func() { called = true })
	sm.Transition(StateFingerprinted)
	if !called {
		t.Error("expected callback to fire")
	}
}

func TestAddTransition(t *testing.T) {
	sm := New("test", StateDiscovered)
	sm.AddTransition(StateDiscovered, StateClosed)
	if !sm.CanTransition(StateClosed) {
		t.Error("expected new transition to be valid")
	}
}

func TestID(t *testing.T) {
	sm := New("my-machine", StateDiscovered)
	if sm.ID() != "my-machine" {
		t.Errorf("expected my-machine, got %s", sm.ID())
	}
}

func TestString(t *testing.T) {
	sm := New("test", StateFingerprinted)
	s := sm.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
}

func TestConcurrency(t *testing.T) {
	sm := New("conc", StateDiscovered)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.Current()
			sm.CanTransition(StateFingerprinted)
			sm.History()
		}()
	}
	wg.Wait()
}

func TestStateValues(t *testing.T) {
	if StateDiscovered != "discovered" {
		t.Error("Discovered mismatch")
	}
	if StateTesting != "testing" {
		t.Error("Testing mismatch")
	}
	if StateVerified != "verified" {
		t.Error("Verified mismatch")
	}
	if StateFalsePositive != "false_positive" {
		t.Error("FalsePositive mismatch")
	}
	if StateEscalated != "escalated" {
		t.Error("Escalated mismatch")
	}
	if StateClosed != "closed" {
		t.Error("Closed mismatch")
	}
}
