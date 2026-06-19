package audit

import (
	"path/filepath"
	"testing"
)

func TestNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.audit.jsonl")
	trail, err := New("target.com", path)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if trail == nil {
		t.Fatal("expected non-nil trail")
	}
	trail.Close()
}

func TestLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.audit.jsonl")
	trail, _ := New("target.com", path)
	trail.Log("test", "event", "info")
	trail.Close()
}

func TestLogFinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "finding.audit.jsonl")
	trail, _ := New("target.com", path)
	trail.LogFinding("FIND-001", "SQL Injection", "critical")
	trail.Close()
}

func TestClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "close.audit.jsonl")
	trail, _ := New("target.com", path)
	trail.Close()
}

func TestLogMultiple(t *testing.T) {
	path := filepath.Join(t.TempDir(), "multi.audit.jsonl")
	trail, _ := New("target.com", path)
	trail.LogFinding("F1", "XSS", "high")
	trail.LogFinding("F2", "SQLi", "critical")
	trail.Log("scan", "completed", "info")
	trail.Close()
}
