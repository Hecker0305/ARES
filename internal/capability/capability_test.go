package capability

import "testing"

func TestNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("expected non-nil set")
	}
}

func TestAllowDeny(t *testing.T) {
	s := New()
	s.Allow("read", "write")
	s.Deny("write")
	if !s.Can("read") {
		t.Error("expected read to be allowed")
	}
	if s.Can("write") {
		t.Error("expected write to be denied")
	}
}

func TestAllowed(t *testing.T) {
	s := New()
	s.Allow("a", "b", "c")
	s.Deny("b")
	allowed := s.Allowed()
	if len(allowed) != 2 {
		t.Errorf("expected 2 allowed, got %d", len(allowed))
	}
}

func TestMerge(t *testing.T) {
	a := New()
	a.Allow("x", "y")
	b := New()
	b.Allow("y", "z")
	b.Deny("x")
	m, err := Merge(a, b)
	if err != nil {
		t.Fatalf("unexpected merge error: %v", err)
	}
	if !m.Can("y") {
		t.Error("expected y to be allowed (both)")
	}
	if m.Can("x") {
		t.Error("expected x to be denied (b denies)")
	}
	if !m.Can("z") {
		t.Error("expected z to be allowed (b allows)")
	}
}

func TestPredefinedSets(t *testing.T) {
	if !BrowserAgent.Can("dom.read") {
		t.Error("BrowserAgent should allow dom.read")
	}
	if BrowserAgent.Can("shell.exec") {
		t.Error("BrowserAgent should not allow shell.exec")
	}
	if !ReconAgent.Can("dns.resolve") {
		t.Error("ReconAgent should allow dns.resolve")
	}
	if !ExploitAgent.Can("exploit.run") {
		t.Error("ExploitAgent should allow exploit.run")
	}
	if !VerifierAgent.Can("replay") {
		t.Error("VerifierAgent should allow replay")
	}
	if VerifierAgent.Can("shell.exec") {
		t.Error("VerifierAgent should not allow shell.exec")
	}
}
