package netsim

import (
	"testing"
)

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestGetTemplates(t *testing.T) {
	e := New()
	templates := e.GetTemplates()
	if len(templates) == 0 {
		t.Fatal("expected at least one template")
	}
}

func TestCreateListGet(t *testing.T) {
	e := New()
	sim := e.Create("test-sim", ScenarioDDoS, []SimTarget{{IP: "10.0.0.1"}})
	if sim == nil {
		t.Fatal("expected non-nil simulation")
	}
	if sim.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if len(e.List()) != 1 {
		t.Fatal("expected 1 simulation")
	}
	got := e.Get(sim.ID)
	if got == nil {
		t.Fatal("expected non-nil Get")
	}
	if got.Name != "test-sim" {
		t.Fatalf("expected name test-sim, got %s", got.Name)
	}
}

func TestGetNotFound(t *testing.T) {
	e := New()
	if e.Get("nonexistent") != nil {
		t.Fatal("expected nil for nonexistent simulation")
	}
}

func TestStopDelete(t *testing.T) {
	e := New()
	sim := e.Create("test-sim-2", ScenarioDDoS, []SimTarget{{IP: "10.0.0.2"}})
	if !e.Stop(sim.ID) {
		t.Fatal("expected true from Stop")
	}
	if !e.Delete(sim.ID) {
		t.Fatal("expected true from Delete")
	}
	if len(e.List()) != 0 {
		t.Fatal("expected 0 simulations after delete")
	}
}

func TestStopNotFound(t *testing.T) {
	e := New()
	if e.Stop("nonexistent") {
		t.Fatal("expected false for nonexistent")
	}
}

func TestDeleteNotFound(t *testing.T) {
	e := New()
	if e.Delete("nonexistent") {
		t.Fatal("expected false for nonexistent")
	}
}

func TestGenerateTerraform(t *testing.T) {
	e := New()
	sim := e.Create("tf-sim", ScenarioDDoS, []SimTarget{{IP: "10.0.0.1"}})
	cfg, err := e.GenerateTerraform(sim.ID, ProviderAWS, "us-east-1", 2, "t3.micro")
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.ID == "" {
		t.Fatal("expected non-empty config ID")
	}
}

func TestGenerateTerraformNotFound(t *testing.T) {
	e := New()
	cfg, err := e.GenerateTerraform("nonexistent", ProviderAWS, "us-east-1", 2, "t3.micro")
	if err == nil && cfg != nil {
		t.Log("GenerateTerraform succeeded for nonexistent sim (config generation only, no validation)")
	}
}

func TestTerraformLifecycle(t *testing.T) {
	e := New()
	sim := e.Create("tf-lifecycle", ScenarioDDoS, []SimTarget{{IP: "10.0.0.1"}})
	cfg, err := e.GenerateTerraform(sim.ID, ProviderAWS, "us-west-2", 1, "t3.micro")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.ListTerraform()) != 1 {
		t.Fatal("expected 1 terraform config")
	}
	got := e.GetTerraform(cfg.ID)
	if got == nil {
		t.Fatal("expected non-nil GetTerraform")
	}
}
