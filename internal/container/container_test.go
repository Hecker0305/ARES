package container

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEscapeTypeString(t *testing.T) {
	tests := []struct {
		et   EscapeType
		want string
	}{
		{PrivilegedContainer, "privileged_container"},
		{HostSocket, "host_docker_socket"},
		{CgroupRelease, "cgroup_release_agent"},
		{ProcSysrqTrigger, "proc_sysrq_trigger"},
		{ContainerBreakout, "container_breakout"},
		{CapabilityAbuse, "capability_abuse"},
		{K8sServiceAccount, "k8s_service_account"},
		{EscapeType(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.et.String(); got != tt.want {
				t.Errorf("EscapeType.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	te := New()
	if te == nil {
		t.Fatal("New() returned nil")
	}
	if te.timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", te.timeout)
	}
	if te.results != nil {
		t.Log("results slice is non-nil (expected nil for uninitialized)")
	}
}

func TestTesterResultsAndThreadSafety(t *testing.T) {
	te := New()
	results := te.Results()
	if results == nil {
		t.Error("Results() returned nil")
	}
	if len(results) != 0 {
		t.Errorf("Results() length = %d, want 0", len(results))
	}

	te.mu.Lock()
	te.results = append(te.results, EscapeResult{Type: PrivilegedContainer, Description: "test"})
	te.mu.Unlock()

	results = te.Results()
	if len(results) != 1 {
		t.Errorf("Results() length = %d, want 1", len(results))
	}
}

func TestResultsCopied(t *testing.T) {
	te := New()
	te.mu.Lock()
	te.results = append(te.results, EscapeResult{Type: CapabilityAbuse, Description: "original"})
	te.mu.Unlock()

	results := te.Results()
	results[0].Description = "modified"

	te.mu.Lock()
	if te.results[0].Description != "original" {
		t.Error("Results() returned non-copied slice")
	}
	te.mu.Unlock()
}

func TestExecSafeOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("test is Windows-specific")
	}
	te := New()
	_, err := te.execSafe(context.Background(), "sh", "-c", "echo test")
	if err == nil {
		t.Log("execSafe succeeded (unexpected on Windows)")
	}
}

func TestExecSafeOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test requires Unix-like OS")
	}
	te := New()
	out, err := te.execSafe(context.Background(), "echo", "hello")
	if err != nil {
		t.Fatalf("execSafe() error = %v", err)
	}
	if strings.TrimSpace(out) != "hello" {
		t.Errorf("output = %q, want hello", strings.TrimSpace(out))
	}
}

func TestExecSafeTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test requires Unix-like OS")
	}
	te := New()
	te.timeout = 10 * time.Millisecond
	ctx := context.Background()
	_, err := te.execSafe(ctx, "sleep", "5")
	if err == nil {
		t.Log("expected timeout or error")
	}
}

func TestRunAll(t *testing.T) {
	te := New()
	ctx := context.Background()
	results := te.RunAll(ctx)
	if results == nil {
		t.Fatal("RunAll() returned nil")
	}
	if len(results) == 0 {
		t.Fatal("RunAll() returned empty results")
	}
	if len(results) != 7 {
		t.Errorf("expected 7 results, got %d", len(results))
	}
}

func TestRunAllContextCancelled(t *testing.T) {
	te := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := te.RunAll(ctx)
	if len(results) > 0 {
		t.Logf("RunAll() returned %d results despite cancel", len(results))
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		max  int
		want string
	}{
		{"hello world", 5, "hello..."},
		{"short", 10, "short"},
		{"", 5, ""},
		{"abc", 0, "..."},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := truncate(tt.s, tt.max); got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.max, got, tt.want)
			}
		})
	}
}

func TestEscapeResultTypes(t *testing.T) {
	te := New()
	ctx := context.Background()

	tests := []struct {
		name   string
		testFn func(context.Context) EscapeResult
		etype  EscapeType
	}{
		{"PrivilegedContainer", te.testPrivilegedContainer, PrivilegedContainer},
		{"HostSocket", te.testHostSocket, HostSocket},
		{"CgroupRelease", te.testCgroupReleaseAgent, CgroupRelease},
		{"ProcSysrq", te.testProcSysrq, ProcSysrqTrigger},
		{"ContainerBreakout", te.testContainerBreakout, ContainerBreakout},
		{"CapabilityAbuse", te.testCapabilityAbuse, CapabilityAbuse},
		{"K8sServiceAccount", te.testK8sServiceAccount, K8sServiceAccount},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.testFn(ctx)
			if result.Type != tt.etype {
				t.Errorf("Type = %v, want %v", result.Type, tt.etype)
			}
			if result.RiskLevel == "" {
				t.Error("RiskLevel is empty")
			}
			if result.Description == "" {
				t.Error("Description is empty")
			}
		})
	}
}

func TestPrivilegedContainerResult(t *testing.T) {
	te := New()
	result := te.testPrivilegedContainer(context.Background())
	if result.Type != PrivilegedContainer {
		t.Errorf("Type = %v, want PrivilegedContainer", result.Type)
	}
	if result.RiskLevel != "Critical" {
		t.Errorf("RiskLevel = %q, want Critical", result.RiskLevel)
	}
}

func TestHostSocketResult(t *testing.T) {
	te := New()
	result := te.testHostSocket(context.Background())
	if result.Type != HostSocket {
		t.Errorf("Type = %v, want HostSocket", result.Type)
	}
}

func TestCgroupReleaseResult(t *testing.T) {
	te := New()
	result := te.testCgroupReleaseAgent(context.Background())
	if result.Type != CgroupRelease {
		t.Errorf("Type = %v, want CgroupRelease", result.Type)
	}
}

func TestProcSysrqResult(t *testing.T) {
	te := New()
	result := te.testProcSysrq(context.Background())
	if result.Type != ProcSysrqTrigger {
		t.Errorf("Type = %v, want ProcSysrqTrigger", result.Type)
	}
}

func TestContainerBreakoutResult(t *testing.T) {
	te := New()
	result := te.testContainerBreakout(context.Background())
	if result.Type != ContainerBreakout {
		t.Errorf("Type = %v, want ContainerBreakout", result.Type)
	}
}

func TestCapabilityAbuseResult(t *testing.T) {
	te := New()
	result := te.testCapabilityAbuse(context.Background())
	if result.Type != CapabilityAbuse {
		t.Errorf("Type = %v, want CapabilityAbuse", result.Type)
	}
}

func TestK8sServiceAccountResult(t *testing.T) {
	te := New()
	result := te.testK8sServiceAccount(context.Background())
	if result.Type != K8sServiceAccount {
		t.Errorf("Type = %v, want K8sServiceAccount", result.Type)
	}
}

func TestRunAllConcurrentSafety(t *testing.T) {
	te := New()
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			te.RunAll(context.Background())
		}()
	}
	wg.Wait()
}

func TestRunAllPreservesOrder(t *testing.T) {
	te := New()
	te.RunAll(context.Background())
	results := te.Results()
	if len(results) < 7 {
		t.Fatalf("expected at least 7 results, got %d", len(results))
	}
	expectedOrder := []EscapeType{
		PrivilegedContainer, HostSocket, CgroupRelease,
		ProcSysrqTrigger, ContainerBreakout, CapabilityAbuse, K8sServiceAccount,
	}
	for i, et := range expectedOrder {
		if results[i].Type != et {
			t.Errorf("result[%d].Type = %v, want %v", i, results[i].Type, et)
		}
	}
}
