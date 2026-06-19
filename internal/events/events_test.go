package events

import (
	"sync"
	"testing"
	"time"
)

func TestNewBus(t *testing.T) {
	b := New()
	if b == nil {
		t.Fatal("expected non-nil bus")
	}
}

func TestPublishSubscribe(t *testing.T) {
	b := New()
	received := make(chan Event, 1)
	b.Subscribe(VulnerabilityFound, func(e Event) {
		received <- e
	})

	evt := NewEvent(VulnerabilityFound, "scanner", map[string]interface{}{"id": "CVE-2024-0001"})
	b.Publish(evt)

	select {
	case e := <-received:
		if e.Type != VulnerabilityFound {
			t.Errorf("expected VulnerabilityFound, got %s", e.Type)
		}
		if e.Source != "scanner" {
			t.Errorf("expected source scanner, got %s", e.Source)
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for event")
	}
}

func TestPublishSubscribeAll(t *testing.T) {
	b := New()
	received := make(chan Event, 3)
	b.SubscribeAll(func(e Event) {
		received <- e
	})

	b.Publish(NewEvent(AgentStarted, "agent", nil))
	b.Publish(NewEvent(VulnerabilityFound, "scanner", nil))
	b.Publish(NewEvent(PhaseChanged, "engine", nil))

	time.Sleep(100 * time.Millisecond)
	if len(received) != 3 {
		t.Errorf("expected 3 events, got %d", len(received))
	}
}

func TestHistory(t *testing.T) {
	b := New()
	b.Publish(NewEvent(AgentStarted, "agent", nil))
	b.Publish(NewEvent(AgentCompleted, "agent", nil))

	history := b.History("")
	if len(history) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(history))
	}

	filtered := b.History(AgentStarted)
	if len(filtered) != 1 {
		t.Errorf("expected 1 filtered entry, got %d", len(filtered))
	}
	if filtered[0].Type != AgentStarted {
		t.Errorf("expected AgentStarted, got %s", filtered[0].Type)
	}
}

func TestClear(t *testing.T) {
	b := New()
	b.Publish(NewEvent(AgentStarted, "agent", nil))
	b.Clear()
	if len(b.History("")) != 0 {
		t.Error("expected empty history after clear")
	}
}

func TestStats(t *testing.T) {
	b := New()
	b.Publish(NewEvent(AgentStarted, "agent", nil))
	b.Publish(NewEvent(VulnerabilityFound, "scanner", nil))
	b.Publish(NewEvent(VulnerabilityFound, "scanner", nil))

	stats := b.Stats()
	if stats["agent.started"] != 1 {
		t.Errorf("expected 1 agent.started, got %d", stats["agent.started"])
	}
	if stats["vulnerability.found"] != 2 {
		t.Errorf("expected 2 vulnerability.found, got %d", stats["vulnerability.found"])
	}
}

func TestHistoryLimit(t *testing.T) {
	b := New()
	b.maxHistory = 5
	for i := 0; i < 10; i++ {
		b.Publish(NewEvent(AgentStarted, "agent", nil))
	}
	history := b.History("")
	if len(history) > 5 {
		t.Errorf("expected at most 5 history entries, got %d", len(history))
	}
}

func TestEventDefaults(t *testing.T) {
	evt := NewEvent(VulnerabilityFound, "test", nil)
	if evt.ID == "" {
		t.Error("expected non-empty ID")
	}
	if evt.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestNewEventWithTrace(t *testing.T) {
	evt := NewEventWithTrace(VulnerabilityFound, "scanner", "trace-123", nil)
	if evt.TraceID != "trace-123" {
		t.Errorf("expected trace-123, got %s", evt.TraceID)
	}
}

func TestEventString(t *testing.T) {
	evt := NewEvent(VulnerabilityFound, "scanner", nil)
	s := evt.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
}

func TestBusConcurrency(t *testing.T) {
	b := New()
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Subscribe(VulnerabilityFound, func(e Event) {})
		}()
	}

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Publish(NewEvent(VulnerabilityFound, "test", nil))
		}()
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.History(VulnerabilityFound)
			b.Stats()
		}()
	}

	wg.Wait()
}

func TestMultipleSubscribers(t *testing.T) {
	b := New()
	count := 0
	var mu sync.Mutex

	for i := 0; i < 5; i++ {
		b.Subscribe(VulnerabilityFound, func(e Event) {
			mu.Lock()
			count++
			mu.Unlock()
		})
	}

	b.Publish(NewEvent(VulnerabilityFound, "test", nil))
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if count != 5 {
		t.Errorf("expected 5 handler calls, got %d", count)
	}
	mu.Unlock()
}
