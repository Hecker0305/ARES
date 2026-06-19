package scanctx

import "testing"

func TestNewScanContext(t *testing.T) {
	sc := NewScanContext("scan-1", "example.com")
	if sc.ScanID != "scan-1" {
		t.Errorf("expected ScanID 'scan-1', got: %s", sc.ScanID)
	}
	if sc.Target != "example.com" {
		t.Errorf("expected Target 'example.com', got: %s", sc.Target)
	}
	if sc.StartTime.IsZero() {
		t.Error("expected StartTime to be set")
	}
}

func TestLog(t *testing.T) {
	sc := NewScanContext("scan-6", "test.com")
	sc.Log("nmap", "nmap -sV test.com", "open ports: 80,443")
	if len(sc.AuditLog) != 1 {
		t.Errorf("expected 1 audit entry, got: %d", len(sc.AuditLog))
	}
	if sc.AuditLog[0].Tool != "nmap" {
		t.Errorf("expected Tool 'nmap', got: %s", sc.AuditLog[0].Tool)
	}
}

func TestAddEndpoints(t *testing.T) {
	sc := NewScanContext("scan-9", "test.com")
	sc.AddEndpoints([]string{"/api", "/admin"})
	if len(sc.Endpoints) != 2 {
		t.Errorf("expected 2 endpoints, got: %d", len(sc.Endpoints))
	}
}

func TestAddNote(t *testing.T) {
	sc := NewScanContext("scan-10", "test.com")
	idx := sc.AddNote("test note")
	if idx != 0 {
		t.Errorf("expected index 0, got: %d", idx)
	}
	if len(sc.Notes) != 1 || sc.Notes[0] != "test note" {
		t.Errorf("unexpected notes: %v", sc.Notes)
	}
}

func TestAddTechStack(t *testing.T) {
	sc := NewScanContext("scan-15", "test.com")
	sc.AddTechStack("nginx")
	sc.AddTechStack("php")
	if len(sc.TechStack) != 2 {
		t.Errorf("expected 2 tech stack entries, got: %d", len(sc.TechStack))
	}
}

func TestSeverityConstants(t *testing.T) {
	if Critical != "Critical" {
		t.Errorf("expected Critical='Critical', got: %s", Critical)
	}
	if High != "High" {
		t.Errorf("expected High='High', got: %s", High)
	}
	if Medium != "Medium" {
		t.Errorf("expected Medium='Medium', got: %s", Medium)
	}
	if Low != "Low" {
		t.Errorf("expected Low='Low', got: %s", Low)
	}
	if Info != "Info" {
		t.Errorf("expected Info='Info', got: %s", Info)
	}
}
