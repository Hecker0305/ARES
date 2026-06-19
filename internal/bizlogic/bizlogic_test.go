package bizlogic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	cfg := TestConfig{
		Target:  "http://example.com",
		BaseURL: "http://example.com",
		Timeout: 30 * time.Second,
	}
	e := New(cfg)
	if e == nil {
		t.Fatal("New() returned nil")
	}
	if e.client == nil {
		t.Error("Engine.client is nil")
	}
	if e.client.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", e.client.Timeout)
	}
}

func TestEngineFindingsAndClear(t *testing.T) {
	cfg := TestConfig{
		Target:  "http://example.com",
		BaseURL: "http://example.com",
		Timeout: 30 * time.Second,
	}
	e := New(cfg)
	findings := e.Findings()
	if findings == nil {
		t.Error("Findings() returned nil on fresh engine")
	}
	if len(findings) != 0 {
		t.Errorf("Findings() length = %d, want 0", len(findings))
	}

	e.mu.Lock()
	e.findings = append(e.findings, Finding{Type: "WorkflowBypass", Description: "test"})
	e.mu.Unlock()

	findings = e.Findings()
	if len(findings) != 1 {
		t.Errorf("Findings() length = %d, want 1", len(findings))
	}
}

func TestFindingsCopied(t *testing.T) {
	cfg := TestConfig{
		Target:  "http://example.com",
		BaseURL: "http://example.com",
		Timeout: 30 * time.Second,
	}
	e := New(cfg)
	e.mu.Lock()
	e.findings = append(e.findings, Finding{Type: "WorkflowBypass", Description: "original"})
	e.mu.Unlock()

	findings := e.Findings()
	findings[0].Description = "modified"

	e.mu.Lock()
	if e.findings[0].Description != "original" {
		t.Error("Findings() returned non-copied slice")
	}
	e.mu.Unlock()
}

func TestRunEmptyTarget(t *testing.T) {
	cfg := TestConfig{
		Target:  "http://localhost:99999",
		BaseURL: "http://localhost:99999",
		Timeout: 1 * time.Second,
	}
	e := New(cfg)
	findings := e.Run(context.Background())
	if findings == nil {
		t.Error("Run() returned nil")
	}
}

func TestRunConcurrentSafety(t *testing.T) {
	cfg := TestConfig{
		Target:  "http://example.com",
		BaseURL: "http://example.com",
		Timeout: 30 * time.Second,
	}
	e := New(cfg)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.mu.Lock()
			e.findings = append(e.findings, Finding{Type: "WorkflowBypass"})
			e.mu.Unlock()
		}()
	}
	wg.Wait()
	findings := e.Findings()
	if len(findings) != 10 {
		t.Errorf("expected 10 concurrent findings, got %d", len(findings))
	}
}

func TestResultsCopied(t *testing.T) {
	cfg := TestConfig{
		Target:  "http://example.com",
		BaseURL: "http://example.com",
		Timeout: 30 * time.Second,
	}
	e := New(cfg)
	e.mu.Lock()
	e.findings = append(e.findings, Finding{Type: "PriceManipulation", Description: "original"})
	e.mu.Unlock()

	res := e.Findings()
	res[0].Description = "modified"

	e.mu.Lock()
	if e.findings[0].Description != "original" {
		t.Error("Findings() returned non-copied slice")
	}
	e.mu.Unlock()
}

func TestRunWithMockServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	cfg := TestConfig{
		Target:  ts.URL,
		BaseURL: ts.URL,
		Timeout: 5 * time.Second,
	}
	e := New(cfg)
	findings := e.Run(context.Background())
	if findings == nil {
		t.Error("Run() returned nil")
	}
}

func TestAddFinding(t *testing.T) {
	cfg := TestConfig{
		Target:  "http://example.com",
		BaseURL: "http://example.com",
		Timeout: 30 * time.Second,
	}
	e := New(cfg)
	e.addFinding(Finding{
		Type:     "IDOR",
		Severity: "high",
		Title:    "Test IDOR",
	})
	findings := e.Findings()
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "bizlogic-1" {
		t.Errorf("expected ID bizlogic-1, got %s", findings[0].ID)
	}
}
