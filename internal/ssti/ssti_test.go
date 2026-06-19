package ssti

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine("oob.example.com")
	if e == nil {
		t.Fatal("expected non-nil Engine")
	}
	if e.client.Timeout != 15*time.Second {
		t.Errorf("expected timeout 15s, got %v", e.client.Timeout)
	}
	if e.oobDomain != "oob.example.com" {
		t.Errorf("expected oobDomain oob.example.com, got %s", e.oobDomain)
	}
}

func TestNewEngine_EmptyOOB(t *testing.T) {
	e := NewEngine("")
	if e.oobDomain != "" {
		t.Errorf("expected empty oobDomain, got %s", e.oobDomain)
	}
}

func TestTestAll_DetectsExpectedOutput(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("49"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestAll(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for '49' response")
	}
	for _, f := range findings {
		if !f.Confirmed {
			t.Errorf("finding %s should be confirmed", f.Engine)
		}
		if f.Severity != "high" {
			t.Errorf("finding %s severity should be high, got %s", f.Engine, f.Severity)
		}
	}
}

func TestTestAll_NoMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("nothing suspicious"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestAll(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestTestAll_EmptyTarget(t *testing.T) {
	e := NewEngine("")
	findings, err := e.TestAll("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty target, got %d", len(findings))
	}
}

func TestTestGET_ValidURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte("49"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestGET(ts.URL, "q")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings via GET")
	}
}

func TestTestGET_InvalidURL(t *testing.T) {
	e := NewEngine("")
	findings, err := e.TestGET("://invalid", "q")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for invalid URL, got %d", len(findings))
	}
}

func TestTestPOST_ValidURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("expected form content-type, got %s", r.Header.Get("Content-Type"))
		}
		w.Write([]byte("49"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestPOST(ts.URL, "param")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings via POST")
	}
}

func TestTestJSON_ValidURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", r.Header.Get("Content-Type"))
		}
		w.Write([]byte("49"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestJSON(ts.URL, "param")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings via JSON")
	}
}

func TestTestOOB_NoDomain(t *testing.T) {
	e := NewEngine("")
	_, err := e.TestOOB("http://example.com")
	if err == nil {
		t.Fatal("expected error when OOB domain is not configured")
	}
}

func TestTestOOB_WithDomain(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	e := NewEngine("oob.example.com")
	finding, err := e.TestOOB(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding == nil {
		t.Fatal("expected finding")
	}
	if finding.Engine != "jinja2-oob" {
		t.Errorf("expected engine jinja2-oob, got %s", finding.Engine)
	}
	if finding.Severity != "critical" {
		t.Errorf("expected severity critical, got %s", finding.Severity)
	}
	if finding.Confirmed {
		t.Error("expected OOB finding to be unconfirmed")
	}
}

func TestDetectSSTI_ExpectedMatch(t *testing.T) {
	e := NewEngine("")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("some content with config keyword"))
	}))
	defer ts.Close()

	findings, _ := e.TestAll(ts.URL)
	if len(findings) == 0 {
		t.Error("expected detection when response contains 'config'")
	}
}

func TestDetectSSTI_TemplateErrorKeyword(t *testing.T) {
	e := NewEngine("")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("template error occurred"))
	}))
	defer ts.Close()

	findings, _ := e.TestAll(ts.URL)
	if len(findings) == 0 {
		t.Error("expected detection when response contains 'template' and 'error'")
	}
}

func TestDetectSSTI_EngineKeywords(t *testing.T) {
	e := NewEngine("")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("jinja runtime error"))
	}))
	defer ts.Close()

	findings, _ := e.TestAll(ts.URL)
	if len(findings) == 0 {
		t.Error("expected detection when response contains 'jinja'")
	}
}

func TestMinInt(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{0, 0, 0},
		{-1, 5, -1},
		{100, 100, 100},
	}
	for _, tt := range tests {
		got := minInt(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("minInt(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestAllPayloadSets_Complete(t *testing.T) {
	e := NewEngine("")
	expectedEngines := []TemplateEngine{EngineJinja2, EngineTwig, EngineFreemarker, EnginePebble, EngineERB}
	for _, eng := range expectedEngines {
		payloads := e.getSafePayloads(eng)
		if len(payloads) == 0 {
			t.Errorf("payload set for %s is empty", eng)
		}
		for _, p := range payloads {
			if p.payload == "" {
				t.Errorf("empty payload in %s set", p.engine)
			}
		}
	}
}

func TestEngineMethod_NoDataRace(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("49"))
	}))
	defer ts.Close()

	e := NewEngine("")
	done := make(chan bool)
	go func() {
		e.TestAll(ts.URL)
		done <- true
	}()
	go func() {
		e.TestGET(ts.URL, "q")
		done <- true
	}()
	go func() {
		e.TestPOST(ts.URL, "p")
		done <- true
	}()
	for i := 0; i < 3; i++ {
		<-done
	}
}
