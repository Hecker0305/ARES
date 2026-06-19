package packetinjection

import (
	"testing"
)

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestTemplates(t *testing.T) {
	e := New()
	if len(e.templates) == 0 {
		t.Fatal("expected at least one template")
	}
}

func TestInjectArgValidation(t *testing.T) {
	e := New()
	_, err := e.Inject("", ProtoTCP, ModeRaw, 1, "syn_flood")
	if err == nil {
		t.Fatal("expected error for empty target")
	}
	_, err = e.Inject("10.0.0.1:80", ProtoTCP, ModeRaw, 0, "syn_flood")
	if err == nil {
		t.Fatal("expected error for zero count")
	}
}

func TestFuzzTemplates(t *testing.T) {
	e := New()
	if len(e.fuzzTemplates) == 0 {
		t.Fatal("expected fuzz templates")
	}
}

func TestMITMStartStop(t *testing.T) {
	e := New()
	relay := e.StartMITM("127.0.0.1:0", "127.0.0.1:9999")
	if relay == nil {
		t.Fatal("expected non-nil relay")
	}
	if relay.ID == "" {
		t.Fatal("expected relay ID")
	}
	if !e.StopMITM(relay.ID) {
		t.Fatal("expected true stopping valid relay")
	}
}

func TestMITMStopNonexistent(t *testing.T) {
	e := New()
	if e.StopMITM("nonexistent") {
		t.Fatal("expected false for nonexistent relay")
	}
}

func TestTemplatesUniqueIDs(t *testing.T) {
	e := New()
	seen := make(map[string]bool)
	for _, tmpl := range e.templates {
		if seen[tmpl.ID] {
			t.Fatalf("duplicate template ID: %s", tmpl.ID)
		}
		seen[tmpl.ID] = true
	}
}

func TestFuzzTemplatesUniqueIDs(t *testing.T) {
	e := New()
	seen := make(map[string]bool)
	for _, tmpl := range e.fuzzTemplates {
		if seen[tmpl.ID] {
			t.Fatalf("duplicate fuzz template ID: %s", tmpl.ID)
		}
		seen[tmpl.ID] = true
	}
}
