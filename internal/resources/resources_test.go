package resources

import "testing"

func TestGetStats(t *testing.T) {
	stats := GetStats()
	if stats.CPUCores <= 0 {
		t.Error("expected >0 CPU cores")
	}
}

func TestCurrentLevel(t *testing.T) {
	level, reason := CurrentLevel()
	t.Logf("Current level: %s, reason: %s", level.String(), reason)
}

func TestCanAdmitScan(t *testing.T) {
	ok, reason := CanAdmitScan(0)
	t.Logf("CanAdmitScan: %v, reason: %s", ok, reason)
}

func TestCanExecTool(t *testing.T) {
	ok, reason := CanExecTool(false)
	t.Logf("CanExecTool: %v, reason: %s", ok, reason)
}

func TestWaitForResources(t *testing.T) {
	ok := WaitForResources(false, 10, "test")
	t.Logf("WaitForResources: %v", ok)
}

func TestMaxInstances(t *testing.T) {
	n := MaxInstances()
	if n <= 0 {
		t.Error("expected positive max instances")
	}
}

func TestLevel(t *testing.T) {
	var l Level
	t.Logf("Level values: OK=%d Caution=%d Critical=%d", LevelOK, LevelCaution, LevelCritical)
	_ = l
}
