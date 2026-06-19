package escalation

import (
	"testing"
	"time"
)

func TestNewQueue(t *testing.T) {
	q := NewQueue()
	if q == nil {
		t.Fatal("expected non-nil queue")
	}
}

func TestAddAndGet(t *testing.T) {
	q := NewQueue()
	nf := &NearFinding{Title: "SQL Injection", Endpoint: "/api/users", Confidence: 0.85, Phase: "exploit", CreatedAt: time.Now()}
	q.Add(nf)
	found := q.Get(nf.ID)
	if found == nil {
		t.Fatal("expected finding")
	}
	if found.Title != "SQL Injection" {
		t.Errorf("expected SQL Injection, got %s", found.Title)
	}
}

func TestConfirm(t *testing.T) {
	q := NewQueue()
	nf := &NearFinding{Title: "XSS", Confidence: 0.9, Phase: "exploit", CreatedAt: time.Now()}
	q.Add(nf)
	err := q.Confirm(nf.ID, "confirmed by operator", "operator")
	if err != nil {
		t.Errorf("Confirm error: %v", err)
	}
}

func TestDismiss(t *testing.T) {
	q := NewQueue()
	nf := &NearFinding{Title: "FP", Confidence: 0.5, Phase: "recon", CreatedAt: time.Now()}
	q.Add(nf)
	err := q.Dismiss(nf.ID, "false positive", "operator")
	if err != nil {
		t.Errorf("Dismiss error: %v", err)
	}
}

func TestPending(t *testing.T) {
	q := NewQueue()
	nf := &NearFinding{Title: "P", Confidence: 0.8, Phase: "exploit", CreatedAt: time.Now()}
	q.Add(nf)
	time.Sleep(50 * time.Millisecond)
	pending := q.Pending()
	if len(pending) != 1 {
		t.Errorf("expected 1 pending, got %d", len(pending))
	}
}

func TestGetNonexistent(t *testing.T) {
	q := NewQueue()
	if q.Get("nonexistent") != nil {
		t.Error("expected nil")
	}
}

func TestConfirmNonexistent(t *testing.T) {
	q := NewQueue()
	err := q.Confirm("nonexistent", "", "operator")
	if err == nil {
		t.Error("expected error")
	}
}

func TestDismissNonexistent(t *testing.T) {
	q := NewQueue()
	err := q.Dismiss("nonexistent", "", "operator")
	if err == nil {
		t.Error("expected error")
	}
}

func TestConfirmInsufficientRole(t *testing.T) {
	q := NewQueue()
	q.SetRequiredRole("admin")
	nf := &NearFinding{Title: "Test", Confidence: 0.9, Phase: "exploit", CreatedAt: time.Now()}
	q.Add(nf)
	err := q.Confirm(nf.ID, "test", "viewer")
	if err == nil {
		t.Error("expected permission error for insufficient role")
	}
}

func TestShouldEscalate(t *testing.T) {
	if !ShouldEscalate(0.85, "evidence found") {
		t.Error("expected escalation for high confidence + evidence")
	}
	if ShouldEscalate(0.5, "") {
		t.Error("expected no escalation for low confidence + no evidence")
	}
}

func TestBuildEscalation(t *testing.T) {
	nf := BuildEscalation("target.com", "/api", "sqli", 0.9, "extracted data", "exploit")
	if nf.VulnType != "sqli" {
		t.Errorf("expected sqli, got %s", nf.VulnType)
	}
}
