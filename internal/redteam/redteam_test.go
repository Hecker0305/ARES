package redteam

import (
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	f := New()
	if f == nil {
		t.Fatal("expected non-nil framework")
	}
}

func TestAddTestCase(t *testing.T) {
	f := New()
	f.AddTestCase(TestCase{
		ID:          "custom-test",
		Name:        "Custom Test",
		Description: "A custom test case",
		Input:       "test input",
		Expected:    "expected output",
		Severity:    "high",
	})
}

func TestRunAll(t *testing.T) {
	f := New()
	checkFn := func(input string) string {
		if strings.Contains(input, "ignore") {
			return "I cannot comply"
		}
		return "I can help with that"
	}
	results := f.RunAll(checkFn)
	if len(results) == 0 {
		t.Error("expected results")
	}
}

func TestRunByType(t *testing.T) {
	f := New()
	checkFn := func(input string) string { return "response" }
	results := f.RunByType(TestPromptInjection, checkFn)
	if len(results) == 0 {
		t.Error("expected prompt injection results")
	}
}

func TestResults(t *testing.T) {
	f := New()
	f.RunAll(func(input string) string { return "response" })
	results := f.Results()
	if len(results) == 0 {
		t.Error("expected results")
	}
}

func TestSummary(t *testing.T) {
	f := New()
	f.RunAll(func(input string) string { return "response" })
	summary := f.Summary()
	if summary["total"].(int) == 0 {
		t.Error("expected >0 total")
	}
}

func TestFailures(t *testing.T) {
	f := New()
	f.RunAll(func(input string) string { return "response" })
	failures := f.Failures()
	_ = failures
}

func TestTestTypeValues(t *testing.T) {
	if TestPromptInjection != "prompt_injection" {
		t.Error("PromptInjection mismatch")
	}
	if TestToolAbuse != "tool_abuse" {
		t.Error("ToolAbuse mismatch")
	}
	if TestPolicyBypass != "policy_bypass" {
		t.Error("PolicyBypass mismatch")
	}
	if TestVerifierPoison != "verifier_poison" {
		t.Error("VerifierPoison mismatch")
	}
}
