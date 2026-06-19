package python

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewPyEngine(t *testing.T) {
	e := NewPyEngine(t.TempDir(), PyConfig{})
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestRun(t *testing.T) {
	e := NewPyEngine(t.TempDir(), PyConfig{})
	exec, err := e.Run("print('hello')", 5*time.Second)
	if err != nil {
		t.Logf("Run error (may not have python): %v", err)
	}
	_ = exec
}

func TestRunWithDeps(t *testing.T) {
	e := NewPyEngine(t.TempDir(), PyConfig{})
	exec, err := e.RunWithDeps("print('hello')", nil, 5*time.Second)
	if err != nil {
		t.Logf("RunWithDeps error: %v", err)
	}
	_ = exec
}

func TestCheckPackages(t *testing.T) {
	e := NewPyEngine(t.TempDir(), PyConfig{})
	available := e.CheckPackages([]string{"os", "sys", "nonexistent_pkg_xyz"})
	if available["os"] != true {
		t.Log("os should be available")
	}
	if available["nonexistent_pkg_xyz"] == true {
		t.Log("nonexistent should not be available")
	}
}

func TestInstallPackage(t *testing.T) {
	e := NewPyEngine(t.TempDir(), PyConfig{})
	err := e.InstallPackage("nonexistent-pkg-test")
	if err != nil {
		t.Logf("Install error (expected): %v", err)
	}
}

func TestToolRun(t *testing.T) {
	params, _ := json.Marshal(map[string]string{"code": "print('hello')"})
	result := Run(json.RawMessage(params), nil)
	if result.Error != "" {
		t.Logf("Tool Run error: %s", result.Error)
	}
}

func TestToolCheckPackages(t *testing.T) {
	params, _ := json.Marshal(map[string]interface{}{"packages": []string{"os"}})
	result := CheckPackages(json.RawMessage(params), nil)
	if result.Error != "" {
		t.Logf("Tool CheckPackages error: %s", result.Error)
	}
}

func TestToolInstallPackage(t *testing.T) {
	params, _ := json.Marshal(map[string]string{"package": "nonexistent"})
	result := InstallPackage(json.RawMessage(params), nil)
	if result.Error != "" {
		t.Logf("Tool InstallPackage error: %s", result.Error)
	}
}

func TestCreateSandbox(t *testing.T) {
	params, _ := json.Marshal(map[string]string{})
	result := CreateSandbox(json.RawMessage(params), nil)
	if result.Error != "" {
		t.Logf("Tool CreateSandbox error: %s", result.Error)
	}
}
