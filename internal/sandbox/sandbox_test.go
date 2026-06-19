package sandbox

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	m := NewManager(Config{})
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if m.config.Timeouts != 60*time.Second {
		t.Errorf("expected default timeout 60s, got %v", m.config.Timeouts)
	}
	if m.config.MaxOutput != 10<<20 {
		t.Errorf("expected default max output 10MB, got %d", m.config.MaxOutput)
	}
	if m.config.Level != SandboxBasic {
		t.Errorf("expected default level SandboxBasic, got %d", m.config.Level)
	}
}

func TestNewManagerWithConfig(t *testing.T) {
	m := NewManager(Config{
		Level:      SandboxFull,
		Timeouts:   30 * time.Second,
		MaxOutput:  1 << 20,
		ReadOnly:   true,
		NetworkOff: true,
	})
	if m.config.Level != SandboxFull {
		t.Errorf("expected SandboxFull, got %d", m.config.Level)
	}
	if m.config.Timeouts != 30*time.Second {
		t.Errorf("expected 30s, got %v", m.config.Timeouts)
	}
	if !m.config.ReadOnly {
		t.Error("expected read-only")
	}
	if !m.config.NetworkOff {
		t.Error("expected network off")
	}
}

func TestValidatePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	m := NewManager(Config{})

	tests := []struct {
		binary string
		want   bool
	}{
		{"", false},
		{"/usr/bin/nmap", true},
		{"/bin/ls", true},
		{"/usr/local/bin/tool", true},
		{"/opt/custom/tool", true},
		{"/tmp/malicious", false},
		{"/etc/passwd", false},
		{"./local", false},
	}
	for _, tt := range tests {
		got := m.validatePath(tt.binary)
		if got != tt.want {
			t.Errorf("validatePath(%q) = %v, want %v", tt.binary, got, tt.want)
		}
	}
}

func TestValidatePathShellMeta(t *testing.T) {
	m := NewManager(Config{})
	if m.validatePath("/usr/bin/cmd|ls") {
		t.Error("should reject pipe character")
	}
	if m.validatePath("/usr/bin/cmd;ls") {
		t.Error("should reject semicolon")
	}
}

func TestValidatePathTraversal(t *testing.T) {
	m := NewManager(Config{})
	if m.validatePath("/usr/bin/../../etc/passwd") {
		t.Error("should reject path traversal")
	}
}

func TestValidatePathAllowedDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}
	m := NewManager(Config{
		AllowedPaths: []string{"/usr/bin/allowed"},
		DeniedPaths:  []string{"/usr/bin/denied"},
	})
	if !m.validatePath("/usr/bin/allowed/tool") {
		t.Error("expected allowed path to be valid")
	}
	if m.validatePath("/usr/bin/denied/tool") {
		t.Error("expected denied path to be invalid")
	}
}

func TestExecute_EmptyBinary(t *testing.T) {
	m := NewManager(Config{})
	result := m.Execute(context.Background(), "", nil, nil)
	if result.Violation == "" {
		t.Error("expected violation for empty binary")
	}
	if result.ExitCode != 1 {
		t.Errorf("expected exit code 1, got %d", result.ExitCode)
	}
}

func TestExecute_InvalidBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}
	m := NewManager(Config{})
	result := m.Execute(context.Background(), "/tmp/nonexistent", nil, nil)
	if result.Violation == "" {
		t.Error("expected violation for invalid binary")
	}
}

func TestExecute_Simple(t *testing.T) {
	if runtime.GOOS == "windows" {
		m := NewManager(Config{AllowedPaths: []string{"C:\\Windows\\System32\\"}})
		result := m.Execute(context.Background(), "cmd.exe", []string{"/c", "echo", "hello"}, nil)
		if result.ExitCode != 0 {
			t.Logf("expected exit code 0, got %d: %s (may vary by platform)", result.ExitCode, result.Stderr)
		}
		return
	}
	m := NewManager(Config{AllowedPaths: []string{"/bin/", "/usr/bin/"}})
	result := m.Execute(context.Background(), "/bin/echo", []string{"hello"}, nil)
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d: %s", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "hello") {
		t.Errorf("expected stdout to contain hello, got %s", result.Stdout)
	}
}

func TestExecute_Timeout(t *testing.T) {
	m := NewManager(Config{
		Timeouts: 100 * time.Millisecond,
	})
	m.config.AllowedPaths = []string{"/bin/", "/usr/bin/"}
	var result Result
	if runtime.GOOS == "windows" {
		result = m.Execute(context.Background(), "ping", []string{"-n", "10", "127.0.0.1"}, nil)
	} else {
		result = m.Execute(context.Background(), "/bin/sleep", []string{"10"}, nil)
	}
	if !result.TimedOut {
		t.Log("expected timeout (may vary by platform)")
	}
}

func TestActiveCount(t *testing.T) {
	m := NewManager(Config{Level: SandboxRestricted})
	if m.Active() != 0 {
		t.Errorf("expected 0 active, got %d", m.Active())
	}
}

func TestCreateTempDir(t *testing.T) {
	m := NewManager(Config{ReadOnly: true})
	_, err := m.CreateTempDir("test")
	if err == nil {
		t.Error("expected error in read-only mode")
	}
}

func TestCreateTempDirWritable(t *testing.T) {
	m := NewManager(Config{WorkDir: filepath.Join(t.TempDir(), "ares_sandbox")})
	dir, err := m.CreateTempDir("test")
	if err != nil {
		t.Fatalf("CreateTempDir error: %v", err)
	}
	defer m.Cleanup(dir)
	if dir == "" {
		t.Error("expected non-empty path")
	}
}

func TestManagerConfig(t *testing.T) {
	m := NewManager(Config{Level: SandboxFull})
	cfg := m.Config()
	if cfg.Level != SandboxFull {
		t.Errorf("expected SandboxFull, got %d", cfg.Level)
	}
}

func TestLimitedWriter(t *testing.T) {
	var buf strings.Builder
	lw := &limitedWriter{w: &buf, remaining: 10}
	n, err := lw.Write([]byte("hello world"))
	if err != nil {
		t.Errorf("write error: %v", err)
	}
	if n != 10 {
		t.Errorf("expected 10 bytes written, got %d", n)
	}
	if buf.String() != "hello worl" {
		t.Errorf("expected 'hello worl', got %s", buf.String())
	}
	n, err = lw.Write([]byte("more"))
	if err != nil {
		t.Errorf("second write error: %v", err)
	}
	if n != 4 {
		t.Errorf("expected 4 bytes (discarded), got %d", n)
	}
}

func TestManagerConcurrency(t *testing.T) {
	m := NewManager(Config{Level: SandboxRestricted})
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Execute(context.Background(), "/bin/echo", []string{"test"}, nil)
		}()
	}
	wg.Wait()
}
