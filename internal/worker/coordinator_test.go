package worker

import (
	"testing"

	aresconfig "github.com/ares/engine/internal/config"
	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/webhook"
)

func TestNewCoordinator(t *testing.T) {
	cfg := aresconfig.Default()
	client, err := llm.NewClient(llm.Config{
		Provider: "ollama",
		BaseURL:  "http://localhost:11434/v1",
		Model:    "llama3.1:70b",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	whMgr := webhook.NewWebhookManager("")
	c := NewCoordinator(3, client, "report.txt", "text", nil, nil, &cfg, whMgr)
	if c == nil {
		t.Fatal("expected non-nil coordinator")
	}
	if c.maxWorkers != 3 {
		t.Errorf("expected 3 workers, got %d", c.maxWorkers)
	}
	if c.outputFmt != "text" {
		t.Errorf("expected text, got %s", c.outputFmt)
	}
}

func TestNewCoordinatorDefaultFormat(t *testing.T) {
	cfg := aresconfig.Default()
	client, _ := llm.NewClient(llm.Config{
		Provider: "ollama",
		BaseURL:  "http://localhost:11434/v1",
		Model:    "llama3.1:70b",
	})
	whMgr := webhook.NewWebhookManager("")
	c := NewCoordinator(1, client, "report.txt", "", nil, nil, &cfg, whMgr)
	if c.outputFmt != "text" {
		t.Errorf("expected default text, got %s", c.outputFmt)
	}
}

func TestMapFindingToEvidenceType(t *testing.T) {
	cfg := aresconfig.Default()
	client, _ := llm.NewClient(llm.Config{
		Provider: "ollama",
		BaseURL:  "http://localhost:11434/v1",
		Model:    "llama3.1:70b",
	})
	whMgr := webhook.NewWebhookManager("")
	c := NewCoordinator(1, client, "report.txt", "text", nil, nil, &cfg, whMgr)

	tests := []struct {
		title string
		want  string
	}{
		{"SQL Injection", "database_info"},
		{"Cross-Site Scripting", "xss_reflection"},
		{"File Inclusion", "file_content"},
		{"Command Injection", "database_info"},
		{"Server-Side Request Forgery", "file_content"},
		{"Open Redirect", "file_content"},
		{"Insecure Direct Object Reference", "file_content"},
		{"Sensitive Data Exposure", "file_content"},
		{"Unknown Type", "file_content"},
		{"Network Scan", "network_info"},
		{"Password Found", "credential"},
		{"Web Shell Detected", "web_shell"},
		{"Persistence Mechanism", "persistence"},
		{"RCE Exploit", "command_output"},
	}
	for _, tc := range tests {
		got := string(c.mapFindingToEvidenceType(tc.title))
		if got != tc.want {
			t.Errorf("mapFindingToEvidenceType(%q) = %q, want %q", tc.title, got, tc.want)
		}
	}
}
