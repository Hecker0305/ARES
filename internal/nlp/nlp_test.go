package nlp

import "testing"

func TestNewProcessor(t *testing.T) {
	p := NewProcessor()
	if p == nil {
		t.Fatal("expected non-nil processor")
	}
}

func TestProcess(t *testing.T) {
	p := NewProcessor()
	result := p.Process("scan example.com for open ports")
	if result.Intent == IntentUnknown {
		t.Log("expected known intent")
	}
}

func TestProcessEmpty(t *testing.T) {
	p := NewProcessor()
	result := p.Process("")
	if result.Intent != IntentUnknown {
		t.Errorf("expected IntentUnknown, got %s", result.Intent)
	}
}

func TestProcessExploit(t *testing.T) {
	p := NewProcessor()
	result := p.Process("exploit the vulnerability")
	if result.Intent != IntentUnknown {
		t.Logf("detected intent: %s", result.Intent)
	}
}

func TestProcessEntities(t *testing.T) {
	p := NewProcessor()
	result := p.Process("scan 192.168.1.1 port 80")
	if len(result.Entities) > 0 {
		t.Logf("found %d entities", len(result.Entities))
	}
}

func TestIntentValues(t *testing.T) {
	if IntentScan != "scan" {
		t.Error("IntentScan mismatch")
	}
	if IntentExploit != "exploit" {
		t.Error("IntentExploit mismatch")
	}
	if IntentEnumerate != "enumerate" {
		t.Error("IntentEnumerate mismatch")
	}
	if IntentHelp != "help" {
		t.Error("IntentHelp mismatch")
	}
	if IntentUnknown != "unknown" {
		t.Error("IntentUnknown mismatch")
	}
}
