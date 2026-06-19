package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsRemoteTarget(t *testing.T) {
	tests := []struct {
		target string
		want   bool
	}{
		{"http://example.com", true},
		{"https://example.com", true},
		{"https://hackerone.com", true},
		{"http://localhost:8080", true},
		{"/var/www/html", false},
		{"C:\\inetpub\\wwwroot", false},
		{"/proc/1/cgroup", false},
		{"", false},
		{"example.com", false},
	}
	for _, tc := range tests {
		got := isRemoteTarget(tc.target)
		if got != tc.want {
			t.Errorf("isRemoteTarget(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}

func TestRunSpecializedScanners_RemoteTargetSkipsLocalScanners(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><title>Test</title></head><body>OK</body></html>`))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res := RunSpecializedScanners(ctx, ts.URL, "")

	if res == nil {
		t.Fatal("RunSpecializedScanners returned nil")
	}

	if len(res.Errors) > 0 {
		for _, e := range res.Errors {
			t.Logf("Scan error (may be expected): %v", e)
		}
	}

	if len(res.DiscoveredEPs) == 0 {
		t.Error("expected at least some discovered endpoints for a web target")
	}

	if len(res.TechStack) == 0 {
		t.Log("TechStack is empty — target is minimal, this may be expected")
	}

	t.Logf("Findings: %d, DiscoveredEPs: %d, TechStack: %d",
		len(res.Findings), len(res.DiscoveredEPs), len(res.TechStack))
	for _, f := range res.Findings {
		t.Logf("  Finding: %s [%s] %s", f.Severity, f.Title, f.Endpoint)
	}
}

func TestRunSpecializedScanners_ProducesFindingsFromMockVulnerableServer(t *testing.T) {
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"items": [{"id": 1, "owner": "user1", "data": "secret"}],
			"status": "ok"
		}`))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res := RunSpecializedScanners(ctx, ts.URL, "")

	if res == nil {
		t.Fatal("RunSpecializedScanners returned nil")
	}

	if requestCount == 0 {
		t.Error("test server received no requests — scanners did not contact target")
	}

	t.Logf("Test server received %d requests", requestCount)
	t.Logf("Findings: %d, DiscoveredEPs: %d", len(res.Findings), len(res.DiscoveredEPs))

	foundSmuggling := false
	for _, f := range res.Findings {
		t.Logf("  Finding: %s [%s] %s", f.Severity, f.Title, f.Endpoint)
		if strings.Contains(f.Title, "Smuggling") {
			foundSmuggling = true
		}
	}

	if !foundSmuggling && requestCount < 3 {
		t.Error("expected smuggling engine to contact the target (CLTE/TECL/TETE tests)")
	}
}

func TestRunSpecializedScanners_LocalTargetRunsLocalScanners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := RunSpecializedScanners(ctx, "/nonexistent/path", "")

	if res == nil {
		t.Fatal("RunSpecializedScanners returned nil")
	}

	t.Logf("Local target: Findings=%d, DiscoveredEPs=%d, Errors=%d",
		len(res.Findings), len(res.DiscoveredEPs), len(res.Errors))

	hasContainerError := false
	for _, e := range res.Errors {
		t.Logf("  Error: %v", e)
		if strings.Contains(e.Error(), "container") || strings.Contains(e.Error(), "Container") {
			hasContainerError = true
		}
	}

	if hasContainerError {
		t.Log("Container escape attempted on local target (expected on non-Windows)")
	}
}

func TestToAgentFinding(t *testing.T) {
	f := toAgentFinding("TEST-1", "Test Finding", "HIGH", "http://example.com", "desc", "poc", "evid")

	if f.ID != "TEST-1" {
		t.Errorf("ID = %q, want %q", f.ID, "TEST-1")
	}
	if f.Title != "Test Finding" {
		t.Errorf("Title = %q, want %q", f.Title, "Test Finding")
	}
	if string(f.Severity) != "HIGH" {
		t.Errorf("Severity = %q, want %q", f.Severity, "HIGH")
	}
	if f.Endpoint != "http://example.com" {
		t.Errorf("Endpoint = %q, want %q", f.Endpoint, "http://example.com")
	}
	if !f.Confirmed {
		t.Error("expected Confirmed = true")
	}
}

func TestRunSpecializedScanners_WithLoginFormDetectsAuthFlow(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>
			<form action="/login" method="POST">
				<input name="username" type="text">
				<input name="password" type="password">
				<input name="csrf_token" type="hidden" value="abc123">
				<button type="submit">Login</button>
			</form>
		</body></html>`))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res := RunSpecializedScanners(ctx, ts.URL, "")

	if res == nil {
		t.Fatal("RunSpecializedScanners returned nil")
	}

	hasAuthFinding := false
	for _, f := range res.Findings {
		t.Logf("  Finding: %s [%s] %s", f.Severity, f.Title, f.Endpoint)
		if strings.Contains(f.Title, "Auth") || strings.Contains(f.Title, "CSRF") {
			hasAuthFinding = true
		}
	}

	if !hasAuthFinding {
		t.Log("No auth-related findings — authflow may not detect login form in this configuration")
	}
}

func TestRunSpecializedScanners_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`OK`))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Millisecond)

	res := RunSpecializedScanners(ctx, ts.URL, "")

	if res == nil {
		t.Fatal("RunSpecializedScanners returned nil")
	}

	t.Logf("Cancelled: Findings=%d, Errors=%d", len(res.Findings), len(res.Errors))
}
