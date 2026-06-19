package safety

import (
	"testing"
)

func TestNewSafetyModeManager(t *testing.T) {
	m := NewSafetyModeManager(SafeMode)
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if m.CurrentMode() != SafeMode {
		t.Errorf("expected SafeMode, got %v", m.CurrentMode())
	}
}

func TestCanPerform(t *testing.T) {
	m := NewSafetyModeManager(AutonomousMode)
	ok, err := m.CanPerform("scan", 1, true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected allowed in autonomous mode")
	}
}

func TestCanPerformKillSwitch(t *testing.T) {
	m := NewSafetyModeManager(AutonomousMode)
	m.ActivateKillSwitch("admin", "testing")
	ok, err := m.CanPerform("scan", 1, true)
	if err == nil {
		t.Error("expected error with kill switch active")
	}
	if ok {
		t.Error("expected denied with kill switch active")
	}
}

func TestCanPerformObserveMode(t *testing.T) {
	m := NewSafetyModeManager(ObserveMode)
	ok, err := m.CanPerform("exploit", 5, true)
	if err == nil {
		t.Error("expected error in observe mode for high-risk action")
	}
	if ok {
		t.Error("expected denied in observe mode")
	}
}

func TestSetMode(t *testing.T) {
	m := NewSafetyModeManager(SafeMode)
	err := m.SetMode(AutonomousMode, "admin")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if m.CurrentMode() != AutonomousMode {
		t.Errorf("expected AutonomousMode, got %v", m.CurrentMode())
	}
}

func TestSetModeWithKillSwitch(t *testing.T) {
	m := NewSafetyModeManager(SafeMode)
	m.ActivateKillSwitch("test", "testing")
	err := m.SetMode(AutonomousMode, "test")
	if err == nil {
		t.Error("expected error when kill switch active")
	}
}

func TestCurrentMode(t *testing.T) {
	m := NewSafetyModeManager(SafeMode)
	mode := m.CurrentMode()
	if mode != SafeMode {
		t.Errorf("expected SafeMode, got %v", mode)
	}
}

func TestNewActionClassifier(t *testing.T) {
	c := NewActionClassifier()
	if c == nil {
		t.Fatal("expected non-nil classifier")
	}
}

func TestClassify(t *testing.T) {
	c := NewActionClassifier()
	classification := c.Classify("terminal_execute")
	if classification.RiskLevel != RiskHigh {
		t.Errorf("expected RiskHigh, got %v", classification.RiskLevel)
	}
	if !classification.RequiresApproval {
		t.Error("expected RequiresApproval")
	}
}

func TestClassifyUnknown(t *testing.T) {
	c := NewActionClassifier()
	classification := c.Classify("unknown_action")
	if classification.RiskLevel != RiskMedium {
		t.Errorf("expected RiskMedium for unknown, got %v", classification.RiskLevel)
	}
}

func TestClassifyCritical(t *testing.T) {
	c := NewActionClassifier()
	tests := []struct {
		action string
		risk   RiskLevel
	}{
		{"python_exec", RiskCritical},
		{"shell_exec", RiskCritical},
		{"ssh_connect", RiskCritical},
		{"c2_beacon", RiskCritical},
	}
	for _, tt := range tests {
		classification := c.Classify(tt.action)
		if classification.RiskLevel != tt.risk {
			t.Errorf("Classify(%q) = %v, want %v", tt.action, classification.RiskLevel, tt.risk)
		}
	}
}

func TestRegister(t *testing.T) {
	c := NewActionClassifier()
	c.Register(ActionClassification{
		Action:    "custom_action",
		RiskLevel: RiskLow,
	})
	classification := c.Classify("custom_action")
	if classification.RiskLevel != RiskLow {
		t.Errorf("expected RiskLow, got %v", classification.RiskLevel)
	}
}

func TestNewPolicyEngine(t *testing.T) {
	pe := NewPolicyEngine()
	if pe == nil {
		t.Fatal("expected non-nil policy engine")
	}
	if pe.CurrentMode() != SafeMode {
		t.Errorf("expected SafeMode, got %v", pe.CurrentMode())
	}
}

func TestCheckAction(t *testing.T) {
	pe := NewPolicyEngine()
	ok, err := pe.CheckAction("file_read")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected file_read to be allowed in safe mode")
	}
}

func TestCheckActionBlocked(t *testing.T) {
	pe := NewPolicyEngine()
	ok, err := pe.CheckAction("terminal_execute")
	if err == nil {
		t.Error("expected error for terminal_execute in safe mode")
	}
	if ok {
		t.Error("expected terminal_execute to be blocked in safe mode")
	}
}

func TestCheckActionWithKillSwitch(t *testing.T) {
	pe := NewPolicyEngine()
	pe.ActivateKillSwitch("test", "testing")
	ok, err := pe.CheckAction("file_read")
	if err == nil {
		t.Error("expected error with kill switch active")
	}
	if ok {
		t.Error("expected denied with kill switch active")
	}
}

func TestKillSwitch(t *testing.T) {
	pe := NewPolicyEngine()
	if pe.IsKillSwitchActive() {
		t.Error("expected kill switch inactive")
	}
	token := pe.ActivateKillSwitch("test", "reason")
	if !pe.IsKillSwitchActive() {
		t.Error("expected kill switch active")
	}
	err := pe.DeactivateKillSwitch("test", token)
	if err != nil {
		t.Errorf("unexpected error deactivating kill switch: %v", err)
	}
	if pe.IsKillSwitchActive() {
		t.Error("expected kill switch inactive after deactivation")
	}
}

func TestKillSwitchInvalidToken(t *testing.T) {
	pe := NewPolicyEngine()
	pe.ActivateKillSwitch("test", "reason")
	err := pe.DeactivateKillSwitch("test", "invalid-token")
	if err == nil {
		t.Error("expected error with invalid token")
	}
	if !pe.IsKillSwitchActive() {
		t.Error("expected kill switch to remain active after invalid token")
	}
}

func TestRequestAndApprove(t *testing.T) {
	pe := NewPolicyEngine()
	err := pe.RequestApproval("req-1", "terminal_execute", "Need to scan", RiskHigh)
	if err != nil {
		t.Errorf("RequestApproval error: %v", err)
	}
	pending := pe.GetPendingApprovals()
	if len(pending) != 1 {
		t.Errorf("expected 1 pending approval, got %d", len(pending))
	}
	err = pe.Approve("req-1", "admin")
	if err != nil {
		t.Errorf("Approve error: %v", err)
	}
}

func TestDenyRequest(t *testing.T) {
	pe := NewPolicyEngine()
	pe.RequestApproval("req-2", "exploit", "Need to exploit", RiskCritical)
	err := pe.Deny("req-2", "not authorized")
	if err != nil {
		t.Errorf("Deny error: %v", err)
	}
	pending := pe.GetPendingApprovals()
	for _, r := range pending {
		if r.ID == "req-2" {
			t.Error("expected denied request to be removed")
		}
	}
}

func TestGetStatus(t *testing.T) {
	pe := NewPolicyEngine()
	status := pe.GetStatus()
	if status.Mode != "safe" {
		t.Errorf("expected safe, got %s", status.Mode)
	}
	if status.KillSwitchActive {
		t.Error("expected kill switch inactive")
	}
}

func TestModeString(t *testing.T) {
	tests := []struct {
		mode OperationMode
		want string
	}{
		{ObserveMode, "observe"},
		{SafeMode, "safe"},
		{VerifyOnlyMode, "verify-only"},
		{AutonomousMode, "autonomous"},
		{AggressiveMode, "aggressive"},
		{InternalOnlyMode, "internal-only"},
		{OperationMode(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.mode.String()
		if got != tt.want {
			t.Errorf("OperationMode(%d).String() = %s, want %s", tt.mode, got, tt.want)
		}
	}
}

func TestPolicyErrors(t *testing.T) {
	if ErrKillSwitchActive == nil {
		t.Error("expected ErrKillSwitchActive")
	}
	if ErrRequiresApproval == nil {
		t.Error("expected ErrRequiresApproval")
	}
	if ErrBlockedBySafetyMode == nil {
		t.Error("expected ErrBlockedBySafetyMode")
	}
}
