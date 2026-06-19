package traversal

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

func TestTestAll_DetectsPasswd(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestAll(ts.URL, "file")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for /etc/passwd-like response")
	}
	for _, f := range findings {
		if f.Confirmed != true {
			t.Errorf("finding %s should be confirmed", f.Type)
		}
		if f.Severity != "high" {
			t.Errorf("finding %s severity should be high, got %s", f.Type, f.Severity)
		}
	}
}

func TestTestAll_NoMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestAll(ts.URL, "file")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestTestPOST(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("expected form content-type, got %s", r.Header.Get("Content-Type"))
		}
		w.Write([]byte("root:x:0:0:"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestPOST(ts.URL, "file")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings via POST")
	}
}

func TestTestJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", r.Header.Get("Content-Type"))
		}
		w.Write([]byte("root:x:0:0:"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestJSON(ts.URL, "file")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings via JSON")
	}
}

func TestTestOOB_NoDomain(t *testing.T) {
	e := NewEngine("")
	_, err := e.TestOOB("http://example.com", "file")
	if err == nil {
		t.Fatal("expected error for missing OOB domain")
	}
}

func TestTestBlind_NoDomain(t *testing.T) {
	e := NewEngine("")
	_, err := e.TestBlind("http://example.com", "file")
	if err == nil {
		t.Fatal("expected error for missing OOB domain")
	}
}

func TestTraversalPayloads_NotEmpty(t *testing.T) {
	if len(traversalPayloads) == 0 {
		t.Fatal("traversalPayloads should not be empty")
	}
	for _, p := range traversalPayloads {
		if p.name == "" {
			t.Error("payload has empty name")
		}
		if p.payload == "" {
			t.Errorf("payload %q has empty payload string", p.name)
		}
		if p.check == nil {
			t.Errorf("payload %q has nil check function", p.name)
		}
	}
}

func TestMinInt(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{3, 7, 3},
		{7, 3, 3},
		{0, 0, 0},
		{-5, 2, -5},
		{42, 42, 42},
	}
	for _, tt := range tests {
		got := minInt(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("minInt(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCheckFunctions_Passwd(t *testing.T) {
	for _, p := range traversalPayloads {
		if p.name == "Basic /etc/passwd" {
			if !p.check("root:x:0:0:root:/root:/bin/bash") {
				t.Error("check should match root line")
			}
			if p.check("no match here") {
				t.Error("check should not match arbitrary text")
			}
			return
		}
	}
	t.Error("Basic /etc/passwd payload not found")
}

func TestCheckFunctions_Windows(t *testing.T) {
	for _, p := range traversalPayloads {
		if p.name == "Windows win.ini" {
			if !p.check("[fonts]") {
				t.Error("check should match [fonts]")
			}
			if !p.check("[extensions]") {
				t.Error("check should match [extensions]")
			}
			return
		}
	}
	t.Error("Windows win.ini payload not found")
}

func TestCheckFunctions_ProcVersion(t *testing.T) {
	for _, p := range traversalPayloads {
		if p.name == "Proc version" {
			if !p.check("Linux version 5.10.0") {
				t.Error("check should match Linux version string")
			}
			return
		}
	}
	t.Error("Proc version payload not found")
}

func TestEvidenceTruncation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 2000)
		for i := range b {
			b[i] = 'A'
		}
		w.Write(b)
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestAll(ts.URL, "file")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if len(f.Evidence) > 500 {
			t.Errorf("evidence truncated to %d, expected max 500", len(f.Evidence))
		}
	}
}

func TestTestAll_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestAll(ts.URL, "file")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on server error, got %d", len(findings))
	}
}
