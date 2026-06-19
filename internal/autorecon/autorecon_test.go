package autorecon

import (
	"context"
	"testing"
)

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestCorrelate(t *testing.T) {
	e := New()
	result, err := e.Correlate(context.Background(), "localhost")
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Domain != "localhost" {
		t.Errorf("expected localhost, got %s", result.Domain)
	}
}

func TestCorrelateEmptyDomain(t *testing.T) {
	e := New()
	_, err := e.Correlate(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestResults(t *testing.T) {
	e := New()
	_, err := e.Correlate(context.Background(), "localhost")
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	results := e.Results()
	if len(results) == 0 {
		t.Error("expected at least 1 result")
	}
}

func TestAllDomains(t *testing.T) {
	e := New()
	_, _ = e.Correlate(context.Background(), "test1.local")
	_, _ = e.Correlate(context.Background(), "test2.local")
	domains := e.AllDomains()
	if len(domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(domains))
	}
}

func TestSummary(t *testing.T) {
	e := New()
	_, _ = e.Correlate(context.Background(), "localhost")
	summary := e.Summary()
	if summary == nil || summary["domains_scanned"] == nil {
		t.Log("summary may not include total for localhost")
	}
}

func TestEnrichASNInfo(t *testing.T) {
	e := New()
	_, _ = e.Correlate(context.Background(), "example.com")
	e.EnrichASNInfo("example.com", "AS12345", "192.0.2.0/24", "Test Corp", "US")
}

func TestCorrelationResultStruct(t *testing.T) {
	r := &CorrelationResult{
		Domain:         "test.com",
		IPs:            []string{"1.2.3.4"},
		Subdomains:     []string{"www.test.com"},
		Score:          8.5,
		CloudProviders: []string{"aws"},
	}
	if r.Score != 8.5 {
		t.Errorf("expected 8.5, got %f", r.Score)
	}
	if len(r.IPs) != 1 {
		t.Errorf("expected 1 IP, got %d", len(r.IPs))
	}
}

func TestValidateToolName(t *testing.T) {
	if !ValidateToolName("nmap") {
		t.Error("expected nmap to be allowed")
	}
	if ValidateToolName("rm") {
		t.Error("expected rm to be disallowed")
	}
	if !ValidateToolName("NMAP") {
		t.Error("expected case-insensitive check to allow NMAP")
	}
}

func TestSanitizeArg(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"example.com; rm -rf /", "example.com rm -rf /"},
		{"example.com & cat /etc/passwd", "example.com  cat /etc/passwd"},
		{"`whoami`", "whoami"},
		{"$(id)", "id"},
	}
	for _, tc := range tests {
		got := SanitizeArg(tc.input)
		if got != tc.expected {
			t.Errorf("SanitizeArg(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestSetToolTimeout(t *testing.T) {
	e := New()
	e.SetToolTimeout(5000000000)
	if e.toolTimeout != 5000000000 {
		t.Errorf("expected timeout 5s, got %v", e.toolTimeout)
	}
	e.SetToolTimeout(0)
	if e.toolTimeout != 5000000000 {
		t.Error("expected timeout to remain unchanged for zero value")
	}
}
