package selfheal

import "testing"

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestGeneratePatch(t *testing.T) {
	e := New()
	patch := e.GeneratePatch("sqli")
	if patch == nil {
		t.Fatal("expected patch")
	}
	if patch.VulnType != "sqli" {
		t.Errorf("expected sqli, got %s", patch.VulnType)
	}
	if patch.SecureCode == "" {
		t.Error("expected secure code for sqli")
	}
}

func TestGenerateAllPatches(t *testing.T) {
	e := New()
	patches := e.GenerateAllPatches("xss")
	if len(patches) == 0 {
		t.Error("expected at least 1 patch")
	}
}

func TestGenerateRegressionTest(t *testing.T) {
	e := New()
	test := e.GenerateRegressionTest("sqli")
	if test == nil {
		t.Fatal("expected regression test")
	}
	if test.VulnType != "sqli" {
		t.Errorf("expected sqli, got %s", test.VulnType)
	}
}

func TestGeneratePolicyRecommendation(t *testing.T) {
	e := New()
	policy := e.GeneratePolicyRecommendation("xss")
	_ = policy
}

func TestBuildRemediationPlan(t *testing.T) {
	e := New()
	plan := e.BuildRemediationPlan([]string{"sqli", "xss"})
	if plan == nil {
		t.Fatal("expected plan")
	}
	if len(plan.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(plan.Findings))
	}
	if plan.ID == "" {
		t.Error("expected non-empty plan ID")
	}
}

func TestFormatRemediation(t *testing.T) {
	e := New()
	plan := e.BuildRemediationPlan([]string{"sqli"})
	formatted := e.FormatRemediation(plan)
	if formatted == "" {
		t.Error("expected non-empty formatted output")
	}
}

func TestPatchSuggestionStruct(t *testing.T) {
	p := PatchSuggestion{
		VulnType:   "rce",
		Title:      "Remote Code Execution",
		Severity:   "critical",
		SecureCode: "validate(input)",
	}
	if p.Severity != "critical" {
		t.Errorf("expected critical, got %s", p.Severity)
	}
}
