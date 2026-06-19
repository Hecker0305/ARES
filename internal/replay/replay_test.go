package replay

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	r := New("./test_replay")
	if r == nil {
		t.Fatal("expected non-nil recorder")
	}
}

func TestStartSession(t *testing.T) {
	r := New(t.TempDir())
	s := r.StartSession("example.com")
	if s == nil {
		t.Fatal("expected non-nil session")
	}
	if s.Target != "example.com" {
		t.Errorf("expected example.com, got %s", s.Target)
	}
}

func TestRecordAction(t *testing.T) {
	r := New(t.TempDir())
	s := r.StartSession("target.com")
	r.Record(RecordedAction{
		ID:        "act-1",
		Type:      ActionCommand,
		Command:   "nmap -sV target.com",
		Timestamp: time.Now(),
	})
	if len(s.Actions) != 1 {
		t.Errorf("expected 1 action, got %d", len(s.Actions))
	}
}

func TestEndSession(t *testing.T) {
	r := New(t.TempDir())
	s := r.StartSession("test.com")
	r.Record(RecordedAction{
		ID:   "act-1",
		Type: ActionCommand,
	})
	r.EndSession()
	if s.EndTime.IsZero() {
		t.Error("expected end time set")
	}
}

func TestListSessions(t *testing.T) {
	r := New(t.TempDir())
	r.StartSession("replay.com")
	r.Record(RecordedAction{
		ID:   "act-1",
		Type: ActionHTTP,
	})
	r.EndSession()

	sessions := r.Sessions()
	if len(sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessions))
	}
}
