package types

import "testing"

func TestSeverityValues(t *testing.T) {
	if SeverityCritical != "critical" {
		t.Error("SeverityCritical mismatch")
	}
	if SeverityHigh != "high" {
		t.Error("SeverityHigh mismatch")
	}
	if SeverityMedium != "medium" {
		t.Error("SeverityMedium mismatch")
	}
	if SeverityLow != "low" {
		t.Error("SeverityLow mismatch")
	}
	if SeverityInfo != "info" {
		t.Error("SeverityInfo mismatch")
	}
}

func TestTrustLevelValues(t *testing.T) {
	if TrustUntrusted != 0 {
		t.Error("TrustUntrusted mismatch")
	}
	if TrustLow != 1 {
		t.Error("TrustLow mismatch")
	}
	if TrustMedium != 2 {
		t.Error("TrustMedium mismatch")
	}
	if TrustHigh != 3 {
		t.Error("TrustHigh mismatch")
	}
	if TrustVerified != 4 {
		t.Error("TrustVerified mismatch")
	}
}

func TestTaintValues(t *testing.T) {
	if TaintClean != 0 {
		t.Error("TaintClean mismatch")
	}
	if TaintLLM != 1 {
		t.Error("TaintLLM mismatch")
	}
	if TaintNetwork != 2 {
		t.Error("TaintNetwork mismatch")
	}
}

func TestFindingStatusValues(t *testing.T) {
	if StatusDiscovered != "discovered" {
		t.Error("StatusDiscovered mismatch")
	}
	if StatusVerified != "verified" {
		t.Error("StatusVerified mismatch")
	}
	if StatusFalsePos != "false_positive" {
		t.Error("StatusFalsePos mismatch")
	}
}

func TestFindingStruct(t *testing.T) {
	f := Finding{
		ID:       "FIND-001",
		Title:    "SQL Injection",
		VulnType: "sqli",
		Severity: SeverityCritical,
		CVSS:     9.8,
	}
	if f.ID != "FIND-001" {
		t.Errorf("expected FIND-001, got %s", f.ID)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("expected Critical, got %s", f.Severity)
	}
}

func TestCredentialStruct(t *testing.T) {
	c := Credential{
		Username: "admin",
		Password: "secret",
		Service:  "ssh",
	}
	if c.Username != "admin" {
		t.Errorf("expected admin, got %s", c.Username)
	}
}

func TestAttackPathStruct(t *testing.T) {
	ap := AttackPath{
		ID:    "AP-001",
		Score: 8.5,
		Steps: []AttackStep{
			{Order: 1, Technique: "recon"},
			{Order: 2, Technique: "exploit"},
		},
	}
	if len(ap.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(ap.Steps))
	}
}

func TestExploitResultStruct(t *testing.T) {
	er := ExploitResult{
		ID:      "ER-001",
		Success: true,
		Output:  "exploit succeeded",
	}
	if !er.Success {
		t.Error("expected success")
	}
}

func TestResourceBudgetStruct(t *testing.T) {
	b := ResourceBudget{
		MaxTokens:     100000,
		MaxMemoryMB:   4096,
		MaxGoroutines: 100,
	}
	if b.MaxTokens != 100000 {
		t.Errorf("expected 100000, got %d", b.MaxTokens)
	}
}
