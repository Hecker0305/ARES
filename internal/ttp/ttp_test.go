package ttp

import "testing"

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("expected non-nil registry")
	}
}

func TestRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	pb, exists := r.Get("sqli")
	if !exists {
		t.Fatal("expected sqli playbook")
	}
	if pb.Class != "sqli" {
		t.Errorf("expected sqli, got %s", pb.Class)
	}
}

func TestList(t *testing.T) {
	r := NewRegistry()
	classes := r.List()
	if len(classes) == 0 {
		t.Error("expected at least 1 playbook")
	}
}

func TestVerify(t *testing.T) {
	r := NewRegistry()
	result := r.Verify("sqli", "http://example.com", map[string]string{"param": "test"})
	if result != nil {
		t.Logf("verify result: vuln=%s confirmed=%v", result.VulnClass, result.Confirmed)
	}
}

func TestIsConfirmed(t *testing.T) {
	results := []*VerificationResult{
		{VulnClass: "sqli", Confirmed: true},
		{VulnClass: "sqli", Confirmed: true},
	}
	if !IsConfirmed(results) {
		t.Error("expected confirmed with 2 true results")
	}
	results2 := []*VerificationResult{{VulnClass: "xss", Confirmed: true}}
	if IsConfirmed(results2) {
		t.Error("expected not confirmed with only 1 result")
	}
}

func TestSystemPromptSection(t *testing.T) {
	section := SystemPromptSection("example.com")
	if section == "" {
		t.Error("expected non-empty section")
	}
}

func TestVerificationResultStruct(t *testing.T) {
	v := &VerificationResult{
		VulnClass:   "sqli",
		Confirmed:   true,
		Confidence:  0.95,
		Severity:    "critical",
		CVSSScore:   9.8,
		Remediation: "Use parameterized queries",
	}
	if !v.Confirmed {
		t.Error("expected confirmed")
	}
}
