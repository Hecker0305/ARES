package policy

import (
	"testing"
)

func TestNewPolicyEngine(t *testing.T) {
	pe := New()
	if pe == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestDefaultEffectDeny(t *testing.T) {
	pe := New()
	result := pe.Evaluate(ActionExecCommand, ResourceProcess, "/bin/sh")
	if result.Allowed {
		t.Error("expected deny by default")
	}
}

func TestAllowRule(t *testing.T) {
	pe := New()
	pe.AddRule(Rule{
		ID:        "test-allow",
		Actions:   []Action{ActionFileRead},
		Resources: []Resource{ResourceFilesystem},
		Effect:    EffectAllow,
		Reason:    "testing allow rule",
	})
	result := pe.Evaluate(ActionFileRead, ResourceFilesystem, "/etc/passwd")
	if !result.Allowed {
		t.Error("expected allow")
	}
}

func TestDenyRule(t *testing.T) {
	pe := NewPermissive()
	pe.AddRule(Rule{
		ID:        "test-deny",
		Actions:   []Action{ActionExfiltrate},
		Resources: []Resource{ResourceNetwork},
		Effect:    EffectDeny,
		Reason:    "exfiltration denied",
	})
	result := pe.Evaluate(ActionExfiltrate, ResourceNetwork, "example.com")
	if result.Allowed {
		t.Error("expected deny")
	}
}

func TestWarnEffect(t *testing.T) {
	pe := New()
	pe.AddRule(Rule{
		ID:        "test-warn",
		Actions:   []Action{ActionWebRequest},
		Resources: []Resource{ResourceAPI},
		Effect:    EffectWarn,
		Reason:    "testing warn",
	})
	result := pe.Evaluate(ActionWebRequest, ResourceAPI, "example.com")
	if !result.Allowed {
		t.Error("expected warn to still allow")
	}
	if result.Effect != EffectWarn {
		t.Errorf("expected effect warn, got %s", result.Effect)
	}
}

func TestTargetMatching(t *testing.T) {
	pe := New()
	pe.AddRule(Rule{
		Actions:   []Action{ActionNetworkScan},
		Resources: []Resource{ResourceNetwork},
		Targets:   []string{"example.com"},
		Effect:    EffectAllow,
		Reason:    "only example.com allowed",
	})
	if pe.Evaluate(ActionNetworkScan, ResourceNetwork, "example.com").Allowed != true {
		t.Error("expected allow for example.com")
	}
	if pe.Evaluate(ActionNetworkScan, ResourceNetwork, "evil.com").Allowed {
		t.Error("expected deny for evil.com")
	}
}

func TestPriorityOrdering(t *testing.T) {
	pe := New()
	pe.AddRule(Rule{
		ID:        "low-priority-allow",
		Actions:   []Action{ActionFileRead},
		Resources: []Resource{ResourceFilesystem},
		Effect:    EffectAllow,
		Priority:  1,
		Reason:    "low priority allow",
	})
	pe.AddRule(Rule{
		ID:        "high-priority-deny",
		Actions:   []Action{ActionFileRead},
		Resources: []Resource{ResourceFilesystem},
		Effect:    EffectDeny,
		Priority:  100,
		Reason:    "high priority deny",
	})
	result := pe.Evaluate(ActionFileRead, ResourceFilesystem, "/etc/shadow")
	if result.Allowed {
		t.Error("expected deny from high-priority rule")
	}
}

func TestSecurityDefaults(t *testing.T) {
	pe := SecurityDefaults()
	if pe == nil {
		t.Fatal("expected non-nil security defaults")
	}
	result := pe.Evaluate(ActionExfiltrate, ResourceNetwork, "example.com")
	if result.Allowed {
		t.Error("expected exfiltration to be denied by default")
	}
	result = pe.Evaluate(ActionFileRead, ResourceFilesystem, "/etc/passwd")
	if !result.Allowed {
		t.Error("expected file reads to be allowed")
	}
}

func TestOverrideRule(t *testing.T) {
	pe := New()
	err := pe.AddOverrideRule(Rule{
		ID:        "test-override",
		Actions:   []Action{ActionExecCommand},
		Resources: []Resource{ResourceProcess},
		Targets:   []string{"/bin/ls"},
		Effect:    EffectAllow,
		Priority:  50,
		Reason:    "test override",
	})
	if err != nil {
		t.Fatalf("AddOverrideRule failed: %v", err)
	}
	result := pe.Evaluate(ActionExecCommand, ResourceProcess, "/bin/ls")
	if !result.Allowed {
		t.Error("expected override rule to allow")
	}
	if result.MatchedRule == nil || result.MatchedRule.ID != "test-override" {
		t.Error("expected test-override rule to match")
	}
}

func TestValidateExecutionPolicy(t *testing.T) {
	valid := DefaultStandardPolicy
	err := New().ValidateExecutionPolicy(valid)
	if err != nil {
		t.Errorf("expected valid policy, got: %v", err)
	}

	invalid := ExecutionPolicy{Name: "bad", MaxParallel: 0, TimeoutSec: 0}
	err = New().ValidateExecutionPolicy(invalid)
	if err == nil {
		t.Error("expected error for invalid policy")
	}
}

func TestIsActionAllowed(t *testing.T) {
	pe := New()
	pe.AddRule(Rule{
		Actions:   []Action{ActionModifySystem},
		Resources: []Resource{ResourceProcess},
		Effect:    EffectDeny,
		Reason:    "deny system mods",
	})
	if pe.IsActionAllowed(ActionModifySystem) {
		t.Error("expected ActionModifySystem to be denied")
	}
	if !pe.IsActionAllowed(ActionFileRead) {
		t.Error("expected ActionFileRead to be allowed by default")
	}
}

func TestRules(t *testing.T) {
	pe := New()
	pe.AddRule(Rule{ID: "r1", Effect: EffectAllow, Reason: "test"})
	rules := pe.Rules()
	if len(rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rules))
	}
}

func TestSetDefaultEffect(t *testing.T) {
	pe := New()
	pe.SetDefaultEffect(EffectAllow)
	result := pe.Evaluate(ActionExecCommand, ResourceProcess, "/bin/test")
	if !result.Allowed {
		t.Error("expected allow after setting default to allow")
	}
}

func TestDefaultPolicyConstants(t *testing.T) {
	if DefaultSafePolicy.MaxParallel != 3 {
		t.Errorf("expected safe policy MaxParallel=3, got %d", DefaultSafePolicy.MaxParallel)
	}
	if DefaultRestrictedPolicy.AllowExec {
		t.Error("restricted policy should not allow exec")
	}
	if !DefaultStandardPolicy.AllowExec {
		t.Error("standard policy should allow exec")
	}
}
