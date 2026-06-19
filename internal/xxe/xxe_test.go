package xxe

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
	e.SetSkipTargetValidation(true)
	findings, err := e.TestAll(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for /etc/passwd-like response")
	}
	for _, f := range findings {
		if !f.Confirmed {
			t.Errorf("finding %s should be confirmed", f.Type)
		}
		if f.Severity != "critical" {
			t.Errorf("finding %s severity should be critical, got %s", f.Type, f.Severity)
		}
	}
}

func TestTestAll_NoMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	e := NewEngine("")
	e.SetSkipTargetValidation(true)
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
	e.SetSkipTargetValidation(true)
	findings, err := e.TestAll("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty target, got %d", len(findings))
	}
}

func TestTestOOB_NoDomain(t *testing.T) {
	e := NewEngine("")
	_, err := e.TestOOB("http://example.com")
	if err == nil {
		t.Fatal("expected error for missing OOB domain")
	}
}

func TestTestOOB_WithDomain(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	e := NewEngine("oob.example.com")
	e.SetSkipTargetValidation(true)
	finding, err := e.TestOOB(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding == nil {
		t.Fatal("expected finding")
	}
	if finding.Type != "xxe_oob" {
		t.Errorf("expected type xxe_oob, got %s", finding.Type)
	}
	if finding.Severity != "critical" {
		t.Errorf("expected severity critical, got %s", finding.Severity)
	}
	if finding.Confirmed {
		t.Error("expected OOB finding to be unconfirmed")
	}
}

func TestTestBlindXXE_NoDomain(t *testing.T) {
	e := NewEngine("")
	_, err := e.TestBlindXXE("http://example.com")
	if err == nil {
		t.Fatal("expected error for missing OOB domain")
	}
}

func TestTestBlindXXE_WithDomain(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	e := NewEngine("oob.example.com")
	e.SetSkipTargetValidation(true)
	finding, err := e.TestBlindXXE(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding == nil {
		t.Fatal("expected finding")
	}
	if finding.Type != "xxe_blind_dns" {
		t.Errorf("expected type xxe_blind_dns, got %s", finding.Type)
	}
	if finding.Severity != "high" {
		t.Errorf("expected severity high, got %s", finding.Severity)
	}
}

func TestTestDTDExfil_NoDomain(t *testing.T) {
	e := NewEngine("")
	_, err := e.TestDTDExfil("http://example.com")
	if err == nil {
		t.Fatal("expected error for missing OOB domain")
	}
}

func TestTestDTDExfil_WithDomain(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	e := NewEngine("oob.example.com")
	e.SetSkipTargetValidation(true)
	finding, err := e.TestDTDExfil(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding == nil {
		t.Fatal("expected finding")
	}
	if finding.Type != "xxe_dtd_exfil" {
		t.Errorf("expected type xxe_dtd_exfil, got %s", finding.Type)
	}
	if finding.Severity != "critical" {
		t.Errorf("expected severity critical, got %s", finding.Severity)
	}
}

func TestCheckFunctions_BasicXXE(t *testing.T) {
	for _, p := range xxePayloads {
		if p.name == "Basic XXE - /etc/passwd" {
			if !p.check("root:x:0:0:root:/root:/bin/bash") {
				t.Error("check should match root line")
			}
			if !p.check("nobody:x:65534:") {
				t.Error("check should match nobody line")
			}
			if p.check("no match here") {
				t.Error("check should not match arbitrary text")
			}
			return
		}
	}
	t.Error("Basic XXE payload not found")
}

func TestCheckFunctions_Windows(t *testing.T) {
	for _, p := range xxePayloads {
		if p.name == "XXE - Windows boot.ini" {
			if !p.check("[boot loader]") {
				t.Error("check should match [boot loader]")
			}
			return
		}
	}
	t.Error("XXE - Windows boot.ini payload not found")
}

func TestCheckFunctions_BillionLaughs(t *testing.T) {
	for _, p := range xxePayloads {
		if p.name == "XXE - Entity expansion (Billion Laughs)" {
			if !p.check("entity expansion error") {
				t.Error("check should match entity expansion error")
			}
			if !p.check("ERROR") {
				t.Error("check should match ERROR")
			}
			return
		}
	}
	t.Error("Billion Laughs payload not found")
}

func TestXXEPayloads_NotEmpty(t *testing.T) {
	if len(xxePayloads) == 0 {
		t.Fatal("xxePayloads should not be empty")
	}
	for _, p := range xxePayloads {
		if p.name == "" {
			t.Error("payload has empty name")
		}
		if p.payload == "" {
			t.Errorf("payload %q has empty payload", p.name)
		}
		if p.check == nil {
			t.Errorf("payload %q has nil check", p.name)
		}
	}
}

func TestMinInt(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{5, 3, 3},
		{0, 0, 0},
		{-10, 10, -10},
		{100, 100, 100},
	}
	for _, tt := range tests {
		got := minInt(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("minInt(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
