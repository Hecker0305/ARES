package blindsqli

import (
	"strings"
	"testing"
)

func TestNewManager(t *testing.T) {
	m := NewManager(nil)
	if m == nil {
		t.Fatal("NewManager(nil) returned nil")
	}
	if m.db != nil {
		t.Fatal("expected nil db field")
	}
}

func TestManager_AskBinaryQuestion(t *testing.T) {
	m := NewManager(nil)
	q := m.AskBinaryQuestion("test-target", 0, 77)
	if !strings.Contains(q, "position 0") {
		t.Errorf("expected position 0 in question, got: %s", q)
	}
	if !strings.Contains(q, "77") {
		t.Errorf("expected char code 77 in question, got: %s", q)
	}
}

func TestManager_NewState_NilDB(t *testing.T) {
	m := NewManager(nil)
	if m.db == nil {
		t.Skip("requires *sql.DB; skipping")
	}
	err := m.NewState("target-1", "payload-1", "mysql")
	if err == nil {
		t.Fatal("expected error with nil db")
	}
}

func TestManager_GetState_NilDB(t *testing.T) {
	m := NewManager(nil)
	if m.db == nil {
		t.Skip("requires *sql.DB; skipping")
	}
	state, err := m.GetState("nonexistent")
	if err == nil {
		t.Fatal("expected error with nil db")
	}
	if state != nil {
		t.Fatal("expected nil state on error")
	}
}

func TestManager_RecordAnswer_NilDB(t *testing.T) {
	m := NewManager(nil)
	if m.db == nil {
		t.Skip("requires *sql.DB; skipping")
	}
	err := m.RecordAnswer("target-1", 0, 77, true)
	if err == nil {
		t.Fatal("expected error with nil db")
	}
}

func TestManager_ReconstructValue_NilDB(t *testing.T) {
	m := NewManager(nil)
	if m.db == nil {
		t.Skip("requires *sql.DB; skipping")
	}
	val, err := m.ReconstructValue("target-1")
	if err == nil {
		t.Fatal("expected error with nil db")
	}
	if val != "" {
		t.Fatal("expected empty value on error")
	}
}

func TestManager_UpdateIteration_NilDB(t *testing.T) {
	m := NewManager(nil)
	if m.db == nil {
		t.Skip("requires *sql.DB; skipping")
	}
	err := m.UpdateIteration("target-1", 5)
	if err == nil {
		t.Fatal("expected error with nil db")
	}
}

func TestManager_SetComplete_NilDB(t *testing.T) {
	m := NewManager(nil)
	if m.db == nil {
		t.Skip("requires *sql.DB; skipping")
	}
	err := m.SetComplete("target-1", "extracted-value")
	if err == nil {
		t.Fatal("expected error with nil db")
	}
}

func TestManager_GetPsuccess_NilDB(t *testing.T) {
	m := NewManager(nil)
	if m.db == nil {
		t.Skip("requires *sql.DB; skipping")
	}
	p := m.GetPsuccess("target-1", "blind_sqli")
	if p != 0.5 {
		t.Fatalf("expected 0.5 default, got %f", p)
	}
}

func TestManager_SerializeForLLM_NilDB(t *testing.T) {
	m := NewManager(nil)
	if m.db == nil {
		t.Skip("requires *sql.DB; skipping")
	}
	result, err := m.SerializeForLLM("target-1")
	if err == nil {
		t.Fatal("expected error with nil db")
	}
	if result != "" {
		t.Fatal("expected empty result on error")
	}
}

func TestState_ZeroValues(t *testing.T) {
	var s State
	if s.TargetID != "" {
		t.Error("expected empty TargetID")
	}
	if s.Complete {
		t.Error("expected Complete to be false")
	}
	if s.Iteration != 0 {
		t.Error("expected Iteration to be 0")
	}
}

func TestBinaryQuestion_Defaults(t *testing.T) {
	var bq BinaryQuestion
	if bq.Answer {
		t.Error("expected Answer to be false")
	}
	if bq.Position != 0 {
		t.Error("expected Position to be 0")
	}
}

func TestManager_AskBinaryQuestion_Format(t *testing.T) {
	m := NewManager(nil)
	tests := []struct {
		targetID string
		pos      int
		charCode int
	}{
		{"t1", 0, 65},
		{"t2", 5, 77},
		{"t3", 10, 122},
	}
	for _, tc := range tests {
		q := m.AskBinaryQuestion(tc.targetID, tc.pos, tc.charCode)
		if !strings.Contains(q, "YES") {
			t.Errorf("expected 'YES' keyword in question, got: %s", q)
		}
		if !strings.Contains(q, "NO") {
			t.Errorf("expected 'NO' keyword in question, got: %s", q)
		}
	}
}

func TestManager_GetPsuccess_VariousInputs(t *testing.T) {
	m := NewManager(nil)
	if m.db == nil {
		t.Skip("requires *sql.DB; skipping")
	}
	tests := []struct {
		targetID string
		vulnType string
	}{
		{"", ""},
		{"target-1", "blind_sqli"},
		{"target-2", "time_based"},
		{"target-3", "boolean_based"},
		{"target-4", "out_of_band"},
	}
	for _, tc := range tests {
		p := m.GetPsuccess(tc.targetID, tc.vulnType)
		if p != 0.5 {
			t.Errorf("GetPsuccess(%q, %q) = %f, want 0.5", tc.targetID, tc.vulnType, p)
		}
	}
}
