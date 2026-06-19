package chaindsl

import "testing"

func TestNew(t *testing.T) {
	b := New()
	if b == nil {
		t.Fatal("expected non-nil builder")
	}
}

func TestAll(t *testing.T) {
	b := New()
	chains := b.All()
	if len(chains) == 0 {
		t.Error("expected default chains")
	}
}

func TestGet(t *testing.T) {
	b := New()
	all := b.All()
	if len(all) > 0 {
		def := b.Get(all[0].Name)
		if def == nil {
			t.Error("expected to find first chain")
		}
	}
}

func TestGetNonexistent(t *testing.T) {
	b := New()
	def := b.Get("nonexistent")
	if def != nil {
		t.Error("expected nil for nonexistent")
	}
}

func TestRegister(t *testing.T) {
	b := New()
	def := ChainDef{
		Name: "custom_chain",
		Steps: []StepDef{
			{ID: "step1", Technique: "recon"},
			{ID: "step2", Technique: "exploit", Prereqs: []string{"step1"}},
		},
	}
	b.Register(def)
	got := b.Get("custom_chain")
	if got == nil {
		t.Fatal("expected custom chain")
	}
	if len(got.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(got.Steps))
	}
}

func TestMatch(t *testing.T) {
	b := New()
	chains := b.Match([]string{"log4j", "rce"})
	if len(chains) == 0 {
		t.Log("no chains matched (may need specific findings)")
	}
}

func TestValidate(t *testing.T) {
	def := ChainDef{
		Name: "test",
		Steps: []StepDef{
			{ID: "s1", Technique: "t1"},
			{ID: "s2", Technique: "t2", Prereqs: []string{"s1"}},
		},
	}
	if err := def.Validate(); err != nil {
		t.Errorf("validation error: %v", err)
	}
}

func TestValidateNoName(t *testing.T) {
	def := ChainDef{Steps: []StepDef{{ID: "s1"}}}
	if err := def.Validate(); err == nil {
		t.Error("expected error for no name")
	}
}

func TestValidateNoSteps(t *testing.T) {
	def := ChainDef{Name: "test"}
	if err := def.Validate(); err == nil {
		t.Error("expected error for no steps")
	}
}

func TestString(t *testing.T) {
	def := ChainDef{
		Name: "test",
		Steps: []StepDef{
			{Technique: "recon"},
			{Technique: "exploit"},
		},
	}
	s := def.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
}
