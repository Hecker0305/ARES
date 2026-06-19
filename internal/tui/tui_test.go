package tui

import (
	"sync"
	"testing"
)

func TestNewTUIModel(t *testing.T) {
	m := NewTUIModel()
	if m == nil {
		t.Fatal("expected non-nil model")
	}
}

func TestUpdateScan(t *testing.T) {
	m := NewTUIModel()
	m.UpdateScan("scan-1", "running")
	m.UpdateScan("scan-2", "completed")
}

func TestAddFinding(t *testing.T) {
	m := NewTUIModel()
	m.AddFinding(FindingStyle{
		Type:      "sqli",
		Severity:  "critical",
		Target:    "example.com",
		Timestamp: "2024-01-01",
	})
}

func TestSummary(t *testing.T) {
	m := NewTUIModel()
	m.UpdateScan("scan-1", "running")
	m.AddFinding(FindingStyle{Type: "xss", Severity: "high", Target: "test.com"})
	summary := m.Summary()
	if summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestSetActiveScans(t *testing.T) {
	m := NewTUIModel()
	m.SetActiveScans(5)
}

func TestGetStatus(t *testing.T) {
	m := NewTUIModel()
	status := m.GetStatus()
	if status == nil {
		t.Error("expected non-nil status")
	}
}

func TestFindingsStyleString(t *testing.T) {
	f := FindingStyle{
		Type:      "sqli",
		Severity:  "critical",
		Target:    "example.com",
		Timestamp: "12:00:00",
	}
	s := f.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
}

func TestConcurrency(t *testing.T) {
	m := NewTUIModel()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.UpdateScan("scan", "running")
			m.AddFinding(FindingStyle{Type: "sqli", Severity: "high"})
			m.Summary()
		}()
	}
	wg.Wait()
}
