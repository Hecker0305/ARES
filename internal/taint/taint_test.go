package taint

import "testing"

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestTagAndCheck(t *testing.T) {
	e := New()
	e.Tag("id1", Network)
	tag, ok := e.Check("id1")
	if !ok {
		t.Error("expected tag to exist")
	}
	if tag.Source != Network {
		t.Errorf("expected Network source, got %v", tag.Source)
	}
}

func TestCheckClean(t *testing.T) {
	e := New()
	_, ok := e.Check("untagged")
	if ok {
		t.Error("expected no tag for untagged id")
	}
}

func TestPropagate(t *testing.T) {
	e := New()
	e.Tag("source", Payload)
	e.Propagate("source", "dest")
	tag, ok := e.Check("dest")
	if !ok {
		t.Fatal("expected propagated tag")
	}
	if !tag.Propagated {
		t.Error("expected propagated flag")
	}
}

func TestIsBlocked(t *testing.T) {
	e := New()
	// Network is blocked by default rules
	e.Tag("bad", Network)
	blocked, reason := e.IsBlocked("bad")
	if !blocked {
		t.Error("expected blocked for Network source")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestIsBlockedClean(t *testing.T) {
	e := New()
	e.Tag("clean", Clean)
	blocked, _ := e.IsBlocked("clean")
	if blocked {
		t.Error("expected Clean not to be blocked")
	}
}

func TestMustFlow(t *testing.T) {
	e := New()
	e.Tag("payload", Payload)
	err := e.MustFlow("payload", "target")
	if err != nil {
		t.Logf("flow error: %v", err)
	}
}

func TestAddRule(t *testing.T) {
	e := New()
	e.AddRule(Rule{Name: "custom-block", Sources: []Source{LLMOutput}, Blocked: true})
	e.Tag("test", LLMOutput)
	blocked, _ := e.IsBlocked("test")
	if !blocked {
		t.Error("expected blocked by custom rule")
	}
}

func TestClear(t *testing.T) {
	e := New()
	e.Tag("temp", Network)
	e.Clear()
	_, ok := e.Check("temp")
	if ok {
		t.Error("expected no tag after clear")
	}
}

func TestStats(t *testing.T) {
	e := New()
	e.Tag("a", Network)
	e.Tag("b", LLMOutput)
	e.Tag("c", Network)
	stats := e.Stats()
	if stats[Network] != 2 {
		t.Errorf("expected 2 Network tags, got %d", stats[Network])
	}
	if stats[LLMOutput] != 1 {
		t.Errorf("expected 1 LLMOutput tag, got %d", stats[LLMOutput])
	}
}

func TestSourceString(t *testing.T) {
	if Clean.String() != "clean" {
		t.Error("Clean mismatch")
	}
	if LLMOutput.String() != "llm" {
		t.Error("LLMOutput mismatch")
	}
	if Network.String() != "network" {
		t.Error("Network mismatch")
	}
	if FileSystem.String() != "filesystem" {
		t.Error("FileSystem mismatch")
	}
	if Browser.String() != "browser" {
		t.Error("Browser mismatch")
	}
	if Payload.String() != "payload" {
		t.Error("Payload mismatch")
	}
}
