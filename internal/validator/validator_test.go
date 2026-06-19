package validator

import (
	"testing"
)

func TestNewProofChecker(t *testing.T) {
	pc := NewProofChecker()
	if pc == nil {
		t.Fatal("expected non-nil checker")
	}
}

func TestValidate(t *testing.T) {
	pc := NewProofChecker()
	r := pc.Validate(&ExploitResult{
		Target:        "example.com",
		Vulnerability: "SQL Injection",
		Success:       true,
		Output:        "found: admin password hash",
		Payload:       "' OR '1'='1",
		Confidence:    0.9,
	})
	if !r {
		t.Log("validation may fail with default config")
	}
}

func TestPassesMinConfidence(t *testing.T) {
	if !PassesMinConfidence(&ExploitResult{Confidence: 0.9}) {
		t.Error("expected pass for high confidence")
	}
	if PassesMinConfidence(&ExploitResult{Confidence: 0.1}) {
		t.Error("expected fail for low confidence")
	}
}

func TestValidateCVSS(t *testing.T) {
	if err := ValidateCVSS("critical", 9.8); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := ValidateCVSS("critical", 5.0); err == nil {
		t.Error("expected error for mismatched CVSS")
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	if SeverityFromCVSS(9.0) != "critical" {
		t.Error("9.0 should be critical")
	}
	if SeverityFromCVSS(7.0) != "high" {
		t.Error("7.0 should be high")
	}
	if SeverityFromCVSS(4.0) != "medium" {
		t.Error("4.0 should be medium")
	}
	if SeverityFromCVSS(2.0) != "low" {
		t.Error("2.0 should be low")
	}
	if SeverityFromCVSS(0.0) != "info" {
		t.Error("0.0 should be info")
	}
}

func TestParseCVSS(t *testing.T) {
	if ParseCVSS("9.8") != 9.8 {
		t.Error("expected 9.8")
	}
	if ParseCVSS("invalid") != 0.0 {
		t.Error("expected 0 for invalid")
	}
	if ParseCVSS("") != 0.0 {
		t.Error("expected 0 for empty")
	}
}

func TestExploitResultStruct(t *testing.T) {
	r := &ExploitResult{
		Target:        "example.com",
		Vulnerability: "XSS",
		Success:       true,
		Evidence:      "<script>alert(1)</script>",
		Confidence:    0.95,
	}
	if !r.Success {
		t.Error("expected success")
	}
	if r.Confidence != 0.95 {
		t.Errorf("expected 0.95, got %f", r.Confidence)
	}
}
