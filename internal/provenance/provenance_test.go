package provenance

import (
	"sync"
	"testing"
	"time"
)

func TestNewStore(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestRecord(t *testing.T) {
	s := New()
	s.Record(Entry{
		Type:     EntryDecision,
		Agent:    "agent-1",
		Action:   "allow",
		Decision: "allowed",
	})
	if len(s.All()) != 1 {
		t.Errorf("expected 1 entry, got %d", len(s.All()))
	}
}

func TestRecordDecision(t *testing.T) {
	s := New()
	s.RecordDecision("agent-1", "scan", "allow", "within policy", nil)
	entries := s.Query("agent-1")
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Type != EntryDecision {
		t.Errorf("expected EntryDecision, got %s", entries[0].Type)
	}
}

func TestRecordExecution(t *testing.T) {
	s := New()
	s.RecordExecution("agent-1", "nmap", "example.com", "-sV", "open ports: 80,443", time.Second)
	entries := s.Query("agent-1")
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Type != EntryExecution {
		t.Errorf("expected EntryExecution, got %s", entries[0].Type)
	}
}

func TestRecordVerification(t *testing.T) {
	s := New()
	s.RecordVerification("agent-1", "FIND-001", "confirmed", 0.95)
	entries := s.QueryByType(EntryVerification)
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestQueryByType(t *testing.T) {
	s := New()
	s.RecordDecision("agent-1", "scan", "allow", "ok", nil)
	s.RecordExecution("agent-1", "nmap", "target", "", "output", time.Second)

	decisions := s.QueryByType(EntryDecision)
	if len(decisions) != 1 {
		t.Errorf("expected 1 decision, got %d", len(decisions))
	}
	executions := s.QueryByType(EntryExecution)
	if len(executions) != 1 {
		t.Errorf("expected 1 execution, got %d", len(executions))
	}
}

func TestQueryByTrace(t *testing.T) {
	s := New()
	s.Record(Entry{TraceID: "trace-1", Type: EntryDecision})
	s.Record(Entry{TraceID: "trace-1", Type: EntryExecution})
	s.Record(Entry{TraceID: "trace-2", Type: EntryDecision})

	entries := s.QueryByTrace("trace-1")
	if len(entries) != 2 {
		t.Errorf("expected 2 entries for trace-1, got %d", len(entries))
	}
}

func TestQueryByTarget(t *testing.T) {
	s := New()
	s.Record(Entry{Target: "example.com", Type: EntryExecution})
	s.Record(Entry{Target: "test.com", Type: EntryDecision})

	entries := s.QueryByTarget("example.com")
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestDefaultID(t *testing.T) {
	s := New()
	s.Record(Entry{Type: EntryDecision})
	entries := s.All()
	if len(entries) != 1 || entries[0].ID == "" {
		t.Error("expected auto-generated ID")
	}
}

func TestDefaultTimestamp(t *testing.T) {
	s := New()
	s.Record(Entry{Type: EntryDecision})
	entries := s.All()
	if entries[0].Timestamp.IsZero() {
		t.Error("expected auto-generated timestamp")
	}
}

func TestMaxSize(t *testing.T) {
	s := New()
	s.maxSize = 5
	for i := 0; i < 10; i++ {
		s.Record(Entry{Type: EntryDecision})
	}
	entries := s.All()
	if len(entries) > 5 {
		t.Errorf("expected at most 5 entries, got %d", len(entries))
	}
}

func TestChain(t *testing.T) {
	s := New()
	root := Entry{ID: "root", TraceID: "trace-1", Type: EntryDecision}
	child := Entry{ID: "child", TraceID: "trace-1", ParentID: "root", Type: EntryExecution}
	grandchild := Entry{ID: "grandchild", TraceID: "trace-1", ParentID: "child", Type: EntryExecution}
	s.Record(root)
	s.Record(child)
	s.Record(grandchild)

	chain := s.Chain("trace-1")
	_ = chain
}

func TestStats(t *testing.T) {
	s := New()
	s.RecordDecision("agent-1", "scan", "allow", "", nil)
	s.RecordExecution("agent-1", "nmap", "t", "", "o", time.Second)

	stats := s.Stats()
	if stats["total"].(int) != 2 {
		t.Errorf("expected total 2, got %d", stats["total"])
	}
}

func TestEntryString(t *testing.T) {
	e := Entry{
		Type:      EntryDecision,
		Agent:     "agent-1",
		Action:    "allow",
		Duration:  time.Second,
		Timestamp: time.Now(),
	}
	s := e.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
}

func TestConcurrency(t *testing.T) {
	s := New()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.RecordDecision("agent", "scan", "allow", "", nil)
			s.Query("agent")
			s.Stats()
		}()
	}
	wg.Wait()
}
