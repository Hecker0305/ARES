package demo

import (
	"testing"
)

type mockPusher struct{}

func (m *mockPusher) Push(scanID, evType, message string) {}

func TestNewDemoManager(t *testing.T) {
	dm := NewDemoManager(&mockPusher{})
	if dm == nil {
		t.Fatal("expected non-nil DemoManager")
	}
	if dm.Active() {
		t.Error("expected inactive initially")
	}
}

func TestDemoScenarios(t *testing.T) {
	dm := NewDemoManager(&mockPusher{})
	sc := dm.ScenarioByID("demo-securebank")
	if sc == nil {
		t.Error("expected demo-securebank scenario to exist")
	}
	api := dm.ScenarioByID("demo-shopapi")
	if api == nil {
		t.Error("expected demo-shopapi scenario to exist")
	}
	infra := dm.ScenarioByID("demo-cloudcorp")
	if infra == nil {
		t.Error("expected demo-cloudcorp scenario to exist")
	}
	nonexistent := dm.ScenarioByID("nonexistent")
	if nonexistent != nil {
		t.Error("expected nil for nonexistent scenario")
	}
}

func TestDemoStartStop(t *testing.T) {
	dm := NewDemoManager(&mockPusher{})
	scanID, err := dm.StartDemo("demo-securebank")
	if err != nil {
		t.Fatalf("StartDemo failed: %v", err)
	}
	if scanID == "" {
		t.Error("expected non-empty scan ID")
	}
	if !dm.Active() {
		t.Error("expected active after start")
	}
	dm.Stop()
	if dm.Active() {
		t.Error("expected inactive after stop")
	}
}
