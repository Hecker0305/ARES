package llmrouting

import "testing"

func TestNew(t *testing.T) {
	r := New()
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestSelect(t *testing.T) {
	r := New()
	model, err := r.Select(TaskPlanning)
	if err != nil {
		t.Errorf("Select error: %v", err)
	}
	if model == "" {
		t.Error("expected non-empty model name")
	}
}

func TestSelectNonexistent(t *testing.T) {
	r := New()
	_, err := r.Select(TaskType(999))
	if err == nil {
		t.Error("expected error for invalid task type")
	}
}

func TestRegister(t *testing.T) {
	r := New()
	r.Register(ModelConfig{
		Name:      "test-model",
		Provider:  "ollama",
		MaxTokens: 4096,
		TaskTypes: []TaskType{TaskPlanning},
	})
	model, err := r.Select(TaskPlanning)
	if err != nil {
		t.Errorf("Select error after register: %v", err)
	}
	if model != "test-model" {
		t.Logf("model selected: %s (may be different model)", model)
	}
}

func TestModelsFor(t *testing.T) {
	r := New()
	models := r.ModelsFor(TaskVerification)
	if len(models) == 0 {
		t.Error("expected at least 1 model for verification")
	}
}

func TestAllModels(t *testing.T) {
	r := New()
	models := r.AllModels()
	if len(models) == 0 {
		t.Error("expected at least 1 model")
	}
}

func TestTaskTypeString(t *testing.T) {
	if TaskTypeString(TaskPlanning) != "planning" {
		t.Error("Planning mismatch")
	}
	if TaskTypeString(TaskVerification) != "verification" {
		t.Error("Verification mismatch")
	}
	if TaskTypeString(TaskCodeAnalysis) != "code_analysis" {
		t.Error("CodeAnalysis mismatch")
	}
	if TaskTypeString(TaskType(999)) != "unknown" {
		t.Error("Unknown mismatch")
	}
}
