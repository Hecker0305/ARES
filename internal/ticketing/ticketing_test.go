package ticketing

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ares/engine/internal/coderemediation"
)

func TestTicketManagerIntegration(t *testing.T) {
	tm := NewTicketManager()
	_ = tm

	// Test code remediation integration
	fixGenerator := coderemediation.NewFixGenerator()

	req := coderemediation.FixRequest{
		FindingType: "sqli",
		Language:    "go",
		Context:     `db.Query("SELECT * FROM users WHERE id = " + id)`,
		FilePath:    "main.go",
	}

	fixSnippet := fixGenerator.GenerateFix(req)

	if fixSnippet.Language != "go" {
		t.Errorf("Expected language 'go', got %s", fixSnippet.Language)
	}

	if !strings.Contains(fixSnippet.FixedCode, "?") {
		t.Errorf("Expected parameterized query fix, got: %s", fixSnippet.FixedCode)
	}

	if fixSnippet.Diff == "" {
		t.Error("Expected non-empty diff")
	}
}

func TestTicketManagerProviders(t *testing.T) {
	tm := NewTicketManager()

	// Test adding provider
	cfg := &TicketConfig{
		Provider: ProviderGitHub,
		URL:      "https://api.github.com",
		Token:    "test-token",
		Owner:    "test-owner",
		Repo:     "test-repo",
		Enabled:  true,
	}

	tm.AddProvider("test-github", cfg)

	retrieved := tm.GetProvider("test-github")
	if retrieved == nil {
		t.Error("Provider not found after adding")
	}

	if retrieved.Provider != ProviderGitHub {
		t.Errorf("Expected provider %s, got %s", ProviderGitHub, retrieved.Provider)
	}

	// Test listing providers (should hide token)
	providers := tm.ListProviders()
	if providers["test-github"] == nil {
		t.Error("Provider not found in list")
	}

	if providers["test-github"].Token != "" {
		t.Error("Token should be hidden in list")
	}

	// Test removing provider
	tm.RemoveProvider("test-github")
	if tm.GetProvider("test-github") != nil {
		t.Error("Provider should be removed")
	}
}

func TestSeverityToPriority(t *testing.T) {
	tests := []struct {
		severity string
		priority string
	}{
		{"critical", "Highest"},
		{"high", "High"},
		{"medium", "Medium"},
		{"low", "Low"},
		{"unknown", "Lowest"},
	}

	for _, test := range tests {
		result := severityToPriority(test.severity)
		if result != test.priority {
			t.Errorf("Severity %s should map to priority %s, got %s", test.severity, test.priority, result)
		}
	}
}

func TestHTTPHandlers(t *testing.T) {
	tm := NewTicketManager()
	handler := NewProviderHandler(tm)

	// Test adding provider via HTTP
	reqBody := `{
		"id": "test-http",
		"provider": "github",
		"url": "https://api.github.com",
		"token": "test-token",
		"owner": "test-owner",
		"repo": "test-repo",
		"enabled": true
	}`

	req := httptest.NewRequest("POST", "/api/ticketing/providers", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp["status"] != "provider added" {
		t.Errorf("Expected 'provider added' status, got %s", resp["status"])
	}

	// Test listing providers
	req = httptest.NewRequest("GET", "/api/ticketing/providers", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestRemediationPR(t *testing.T) {
	tm := NewTicketManager()

	// Add GitHub provider
	cfg := &TicketConfig{
		Provider: ProviderGitHub,
		URL:      "https://api.github.com",
		Token:    "test-token",
		Owner:    "test-owner",
		Repo:     "test-repo",
		Enabled:  true,
	}

	tm.AddProvider("test-pr", cfg)

	// Test detection language function
	lang := detectLanguage("test.go")
	if lang != "go" {
		t.Errorf("Expected 'go' for .go file, got %s", lang)
	}

	lang = detectLanguage("test.py")
	if lang != "python" {
		t.Errorf("Expected 'python' for .py file, got %s", lang)
	}

	lang = detectLanguage("test.js")
	if lang != "javascript" {
		t.Errorf("Expected 'javascript' for .js file, got %s", lang)
	}

	// Test PR creation (mock - will fail without real GitHub API)
	finding := FindingInfo{
		ID:          "test-finding-123",
		Title:       "SQL Injection Test",
		Severity:    "high",
		Target:      "http://test.com",
		Description: "Test SQL injection vulnerability",
		Evidence:    map[string]string{"code": "SELECT * FROM users WHERE id = 1"},
		CVSS:        7.5,
		Type:        "sqli",
	}

	pr := tm.CreateRemediationPR("test-scan-123", "http://test.com", finding, "fixed code", "fix.go")

	if pr == nil {
		// Expected since we don't have real GitHub credentials
		t.Log("PR creation failed as expected (no real GitHub token)")
	} else {
		if pr.ProviderID != "test-pr" {
			t.Errorf("Expected provider ID 'test-pr', got %s", pr.ProviderID)
		}
		if pr.ScanID != "test-scan-123" {
			t.Errorf("Expected scan ID 'test-scan-123', got %s", pr.ScanID)
		}
		if pr.FindingID != "test-finding-123" {
			t.Errorf("Expected finding ID 'test-finding-123', got %s", pr.FindingID)
		}
		if pr.Status != "open" {
			t.Errorf("Expected status 'open', got %s", pr.Status)
		}
	}
}

func TestGenerateAndApplyRemediation(t *testing.T) {
	tm := NewTicketManager()

	// Add GitHub provider
	cfg := &TicketConfig{
		Provider: ProviderGitHub,
		URL:      "https://api.github.com",
		Token:    "test-token",
		Owner:    "test-owner",
		Repo:     "test-repo",
		Enabled:  true,
	}

	tm.AddProvider("test-generate", cfg)

	finding := FindingInfo{
		ID:          "test-finding-456",
		Title:       "XSS Test",
		Severity:    "medium",
		Target:      "http://test.com",
		Description: "Test XSS vulnerability",
		Evidence:    map[string]string{"code": `w.Write([]byte(userInput))`},
		CVSS:        6.1,
		Type:        "xss",
	}

	pr := tm.GenerateAndApplyRemediation("test-scan-456", "http://test.com", finding, "main.go")

	if pr == nil {
		// Expected since we don't have real GitHub credentials
		t.Log("Remediation generation failed as expected (no real GitHub token)")
	} else {
		if pr.FindingID != "test-finding-456" {
			t.Errorf("Expected finding ID 'test-finding-456', got %s", pr.FindingID)
		}
	}
}
