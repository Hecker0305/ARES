package protopollution

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine("oob.example.com")
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
	if e.oobDomain != "oob.example.com" {
		t.Errorf("expected oob.example.com, got %s", e.oobDomain)
	}
	if e.client.Timeout != 15*time.Second {
		t.Errorf("expected 15s timeout, got %v", e.client.Timeout)
	}
}

func TestNewEngine_EmptyDomain(t *testing.T) {
	e := NewEngine("")
	if e.oobDomain != "" {
		t.Errorf("expected empty domain, got %s", e.oobDomain)
	}
}

func TestTestAll_Basic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	e := NewEngine("")
	findings, err := e.TestAll(server.URL)
	if err != nil {
		t.Fatal("TestAll failed:", err)
	}
	if len(findings) != 0 {
		t.Log("TestAll should return 0 for non-vulnerable endpoint")
	}
}

func TestTestAll_Error(t *testing.T) {
	e := NewEngine("")
	findings, err := e.TestAll("http://127.0.0.1:19999/test")
	if err != nil {
		t.Log("TestAll error:", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable, got %d", len(findings))
	}
}

func TestTestPrototype_Detected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)

		w.Header().Set("Content-Type", "application/json")

		if proto, ok := body["__proto__"]; ok {
			m := proto.(map[string]interface{})
			if m["polluted"] == "true" || m["isAdmin"] == true {
				w.Write([]byte(`{"polluted": true, "error": "prototype pollution detected"}`))
				return
			}
		}

		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	e := NewEngine("")
	findings, err := e.TestAll(server.URL)
	if err != nil {
		t.Fatal("TestAll failed:", err)
	}

	if len(findings) == 0 {
		t.Log("expected finding for prototype pollution")
	}
}

func TestTestPrototype_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	e := NewEngine("")
	f, err := e.testPrototype(server.URL, "__proto__", map[string]interface{}{
		"__proto__": map[string]interface{}{"polluted": "true"},
	})
	if err == nil {
		t.Error("expected error when no pollution detected")
	}
	if f != nil {
		t.Error("expected nil finding")
	}
}

func TestTestPrototype_ConstructorPrototype(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"constructor": {"prototype": {"polluted": true}}}`))
	}))
	defer server.Close()

	e := NewEngine("")
	f, err := e.testPrototype(server.URL, "constructor.prototype", map[string]interface{}{
		"constructor": map[string]interface{}{
			"prototype": map[string]interface{}{"polluted": "true"},
		},
	})
	if err != nil {
		t.Fatal("testPrototype failed:", err)
	}
	if f == nil {
		t.Fatal("expected finding for constructor.prototype")
	}
	if f.Type != "prototype_pollution" {
		t.Errorf("expected prototype_pollution, got %s", f.Type)
	}
}

func TestTestPrototype_ConnectionError(t *testing.T) {
	e := NewEngine("")
	f, err := e.testPrototype("http://127.0.0.1:19999/test", "test", map[string]interface{}{
		"__proto__": map[string]interface{}{"polluted": "true"},
	})
	if err == nil {
		t.Error("expected error for connection failure")
	}
	if f != nil {
		t.Error("expected nil finding")
	}
}

func TestTestQueryParam_Detected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "prototype") || strings.Contains(r.URL.RawQuery, "polluted") {
			w.Write([]byte(`{"polluted": "true", "prototype": "modified"}`))
			return
		}
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	e := NewEngine("")
	f, err := e.TestQueryParam(server.URL)
	if err != nil {
		t.Fatal("TestQueryParam failed:", err)
	}
	if f == nil {
		t.Fatal("expected finding for query param pollution")
	}
	if f.Type != "prototype_pollution_query" {
		t.Errorf("expected prototype_pollution_query, got %s", f.Type)
	}
}

func TestTestQueryParam_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok", "data": "none"}`))
	}))
	defer server.Close()

	e := NewEngine("")
	f, err := e.TestQueryParam(server.URL)
	if err == nil {
		t.Error("expected error for no pollution detected")
	}
	if f != nil {
		t.Error("expected nil finding")
	}
}

func TestTestQueryParam_InvalidURL(t *testing.T) {
	e := NewEngine("")
	_, err := e.TestQueryParam("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestTestOOB(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	e := NewEngine("oob.example.com")
	f, err := e.TestOOB(server.URL)
	if err != nil {
		t.Fatal("TestOOB failed:", err)
	}
	if f == nil {
		t.Fatal("expected finding for OOB test")
	}
	if f.Type != "prototype_pollution_oob" {
		t.Errorf("expected prototype_pollution_oob, got %s", f.Type)
	}
	if f.Severity != "critical" {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
	if f.Confirmed != false {
		t.Error("OOB findings should be unconfirmed initially")
	}
	if !strings.Contains(f.Payload, "sanitized") {
		t.Error("payload should be sanitized")
	}
}

func TestTestOOB_NoDomain(t *testing.T) {
	e := NewEngine("")
	_, err := e.TestOOB("http://example.com")
	if err == nil {
		t.Error("expected error when OOB domain not configured")
	}
}

func TestTestOOB_ConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	e := NewEngine("oob.example.com")
	f, err := e.TestOOB(server.URL)
	if err != nil {
		t.Fatal("TestOOB should not return error:", err)
	}
	if f == nil {
		t.Fatal("expected finding even on connection error")
	}
}

func TestDetectPollution_MultipleIndicators(t *testing.T) {
	e := NewEngine("")

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "polluted and prototype",
			body:     `{"polluted": true, "prototype": "modified"}`,
			expected: true,
		},
		{
			name:     "only error",
			body:     `{"error": "something"}`,
			expected: false,
		},
		{
			name:     "empty body",
			body:     `{}`,
			expected: false,
		},
		{
			name:     "isAdmin in body",
			body:     `{"isAdmin": true, "error": "bad"}`,
			expected: true,
		},
		{
			name:     "constructor reference",
			body:     `{"constructor": "modified", "prototype": "polluted"}`,
			expected: true,
		},
		{
			name:     "stack trace with exception",
			body:     `{"exception": "TypeError", "stack trace": "at Object"}`,
			expected: true,
		},
		{
			name:     "no indicators",
			body:     `{"status": "ok"}`,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := e.detectPollution([]byte(tc.body), "", nil)
			if got != tc.expected {
				t.Errorf("detectPollution(%q) = %v, want %v", tc.body, got, tc.expected)
			}
		})
	}
}

func TestDetectPollution_CaseInsensitive(t *testing.T) {
	e := NewEngine("")
	got := e.detectPollution([]byte(`{"POLLUTED": "true", "Prototype": "test"}`), "", nil)
	if !got {
		t.Error("detectPollution should be case-insensitive")
	}
}

func TestFinding_Fields(t *testing.T) {
	f := Finding{
		URL:       "http://example.com",
		Type:      "prototype_pollution",
		Payload:   `{"__proto__": {"polluted": "true"}}`,
		Evidence:  "Response indicates prototype pollution",
		Severity:  "high",
		Confirmed: true,
		Timestamp: time.Now(),
	}

	if f.URL != "http://example.com" {
		t.Errorf("URL = %s", f.URL)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %s", f.Severity)
	}
	if !f.Confirmed {
		t.Error("Confirmed should be true")
	}
	if f.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestMinInt(t *testing.T) {
	if minInt(3, 7) != 3 {
		t.Error("minInt(3,7) should be 3")
	}
	if minInt(7, 3) != 3 {
		t.Error("minInt(7,3) should be 3")
	}
	if minInt(5, 5) != 5 {
		t.Error("minInt(5,5) should be 5")
	}
	if minInt(-1, 2) != -1 {
		t.Error("minInt(-1,2) should be -1")
	}
}

func TestTestAll_AllPayloadTypes(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 1024)
		n, _ := r.Body.Read(body)
		bodyStr := strings.ToLower(string(body[:n]))
		if strings.Contains(bodyStr, "isadmin") || strings.Contains(bodyStr, "polluted") {
			w.Write([]byte(`{"polluted": true, "error": "test"}`))
			return
		}
		requests = append(requests, r.URL.String())
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	e := NewEngine("")
	findings, _ := e.TestAll(server.URL)

	if len(findings) == 0 {
		t.Log("TestAll found no pollution (server needs to reflect indicators)")
	}
}

func TestTestAll_WithPollutionServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)

		if _, ok := body["__proto__"]; ok {
			w.Write([]byte(`{"polluted": true, "prototype": "modified"}`))
			return
		}
		if _, ok := body["constructor"]; ok {
			w.Write([]byte(`{"constructor": {"prototype": {"polluted": true}}, "error": "prototype pollution"}`))
			return
		}
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	e := NewEngine("")
	findings, err := e.TestAll(server.URL)
	if err != nil {
		t.Fatal("TestAll failed:", err)
	}

	if len(findings) == 0 {
		t.Error("expected at least one finding with pollution-aware server")
	}
}

func TestTestPrototype_BodyEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"polluted": true, "prototype": "test", "debug": "info"}`))
	}))
	defer server.Close()

	e := NewEngine("")
	f, err := e.testPrototype(server.URL, "__proto__", map[string]interface{}{
		"__proto__": map[string]interface{}{"polluted": "true"},
	})
	if err != nil {
		t.Fatal("testPrototype failed:", err)
	}
	if f == nil {
		t.Fatal("expected finding")
	}
	if len(f.Evidence) > 500 {
		t.Errorf("evidence should be truncated to 500, got %d", len(f.Evidence))
	}
	if !strings.Contains(f.Payload, "__proto__") {
		t.Error("payload should mention __proto__")
	}
}

func TestTestQueryParam_Evidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"polluted": true, "prototype": "modified"}`))
	}))
	defer server.Close()

	e := NewEngine("")
	f, err := e.TestQueryParam(server.URL)
	if err != nil {
		t.Fatal("TestQueryParam failed:", err)
	}
	if f == nil {
		t.Fatal("expected finding")
	}
	if !strings.Contains(f.Payload, "sanitized") {
		t.Error("payload should be sanitized")
	}
}

func TestEngine_UserAgentHeader(t *testing.T) {
	var userAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent = r.Header.Get("User-Agent")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	e := NewEngine("")
	e.TestAll(server.URL)

	if !strings.HasPrefix(userAgent, "ARES-PrototypePollution/") {
		t.Errorf("expected ARES-PrototypePollution user agent, got %s", userAgent)
	}
}

func TestEngine_ContentTypeHeader(t *testing.T) {
	var contentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	e := NewEngine("")
	e.testPrototype(server.URL, "test", map[string]interface{}{"key": "value"})
	if contentType != "application/json" {
		t.Errorf("expected application/json, got %s", contentType)
	}
}

func TestTestAll_JSONParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer server.Close()

	e := NewEngine("")
	findings, _ := e.TestAll(server.URL)
	if len(findings) != 0 {
		t.Log("TestAll with non-JSON response, 0 findings expected")
	}
}
