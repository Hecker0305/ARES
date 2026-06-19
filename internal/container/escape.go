package container

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type EscapeType int

const (
	PrivilegedContainer EscapeType = iota
	HostSocket
	CgroupRelease
	ProcSysrqTrigger
	ContainerBreakout
	CapabilityAbuse
	K8sServiceAccount
)

func (e EscapeType) String() string {
	switch e {
	case PrivilegedContainer:
		return "privileged_container"
	case HostSocket:
		return "host_docker_socket"
	case CgroupRelease:
		return "cgroup_release_agent"
	case ProcSysrqTrigger:
		return "proc_sysrq_trigger"
	case ContainerBreakout:
		return "container_breakout"
	case CapabilityAbuse:
		return "capability_abuse"
	case K8sServiceAccount:
		return "k8s_service_account"
	default:
		return "unknown"
	}
}

type EscapeResult struct {
	Type        EscapeType `json:"type"`
	Successful  bool       `json:"successful"`
	Command     string     `json:"command"`
	Output      string     `json:"output"`
	RiskLevel   string     `json:"risk_level"`
	Description string     `json:"description"`
}

type SeccompProfile struct {
	DefaultAction string   `json:"defaultAction"`
	Architectures []string `json:"architectures"`
	Syscalls      []string `json:"syscalls"`
}

var defaultSeccompProfile = SeccompProfile{
	DefaultAction: "SCMP_ACT_ERRNO",
	Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
	Syscalls: []string{
		"read", "write", "open", "close", "stat", "fstat", "lstat",
		"poll", "lseek", "mmap", "mprotect", "munmap", "brk",
		"ioctl", "access", "pipe", "select", "sched_yield", "mremap",
		"msync", "mincore", "madvise", "dup", "dup2", "nanosleep",
		"getpid", "socket", "connect", "accept", "sendto", "recvfrom",
		"clone", "execve", "exit", "wait4", "kill", "uname",
		"fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate",
		"getdents", "getcwd", "chdir", "rename", "mkdir", "rmdir",
		"link", "unlink", "readlink", "chmod", "chown", "lchown",
		"umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo",
		"clock_gettime", "getuid", "getgid", "geteuid", "getegid",
		"set_tid_address", "set_robust_list", "prctl", "arch_prctl",
		"getrandom", "statx", "rseq",
	},
}

var blockedSyscalls = []string{
	"mount", "umount2", "ptrace", "personality",
	"syslog", "kcmp", "bpf", "kexec_load",
	"init_module", "finit_module", "delete_module",
	"ioperm", "iopl", "outb", "outw", "outl",
}

type Tester struct {
	mu             sync.RWMutex
	results        []EscapeResult
	timeout        time.Duration
	seccompProfile *SeccompProfile
	allowedCaps    []string
}

func New() *Tester {
	return &Tester{
		timeout:        30 * time.Second,
		seccompProfile: &defaultSeccompProfile,
		allowedCaps: []string{
			"CAP_NET_BIND_SERVICE",
			"CAP_CHOWN",
			"CAP_DAC_OVERRIDE",
			"CAP_FSETID",
			"CAP_FOWNER",
			"CAP_SETGID",
			"CAP_SETUID",
			"CAP_SETPCAP",
			"CAP_NET_RAW",
			"CAP_KILL",
		},
	}
}

func (t *Tester) SetSeccompProfile(profile *SeccompProfile) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seccompProfile = profile
}

func (t *Tester) SetAllowedCaps(caps []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.allowedCaps = caps
}

func (t *Tester) RunAll(ctx context.Context) []EscapeResult {
	tests := []struct {
		etype EscapeType
		fn    func(context.Context) EscapeResult
	}{
		{PrivilegedContainer, t.testPrivilegedContainer},
		{HostSocket, t.testHostSocket},
		{CgroupRelease, t.testCgroupReleaseAgent},
		{ProcSysrqTrigger, t.testProcSysrq},
		{ContainerBreakout, t.testContainerBreakout},
		{CapabilityAbuse, t.testCapabilityAbuse},
		{K8sServiceAccount, t.testK8sServiceAccount},
	}

	for _, test := range tests {
		select {
		case <-ctx.Done():
			return t.results
		default:
		}
		result := test.fn(ctx)
		t.mu.Lock()
		t.results = append(t.results, result)
		t.mu.Unlock()
	}

	return t.results
}

func (t *Tester) testPrivilegedContainer(ctx context.Context) EscapeResult {
	commands := []string{
		"cat /proc/1/status | grep -i Seccomp",
		"cat /proc/1/cgroup",
		"cat /proc/self/status | grep Cap",
	}

	var outputs []string
	for _, cmd := range commands {
		out, err := t.execSafe(ctx, "sh", "-c", cmd)
		if err == nil && strings.TrimSpace(out) != "" {
			outputs = append(outputs, fmt.Sprintf("$ %s\n%s", cmd, out))
		}
	}

	successful := len(outputs) > 0
	return EscapeResult{
		Type:       PrivilegedContainer,
		Successful: successful,
		Command:    strings.Join(commands, "; "),
		Output:     strings.Join(outputs, "\n---\n"),
		RiskLevel:  "Critical",
		Description: func() string {
			if successful {
				return fmt.Sprintf("Privileged container indicators detected: %d findings", len(outputs))
			}
			return "No privileged container indicators detected"
		}(),
	}
}

func (t *Tester) testHostSocket(ctx context.Context) EscapeResult {
	checks := []struct {
		path    string
		command string
	}{
		{"/var/run/docker.sock", "ls -la /var/run/docker.sock 2>/dev/null"},
		{"/run/docker.sock", "ls -la /run/docker.sock 2>/dev/null"},
		{"/var/run/docker-ce.sock", "ls -la /var/run/docker-ce.sock 2>/dev/null"},
	}

	var found []string
	for _, check := range checks {
		out, err := t.execSafe(ctx, "sh", "-c", check.command)
		if err == nil && strings.TrimSpace(out) != "" {
			found = append(found, check.path)
		}
	}

	if len(found) > 0 {
		return EscapeResult{
			Type:       HostSocket,
			Successful: true,
			Command:    "docker socket enumeration",
			Output:     strings.Join(found, ", "),
			RiskLevel:  "Critical",
			Description: fmt.Sprintf("Host Docker socket found at %s: socket should not be mounted in container",
				strings.Join(found, ", ")),
		}
	}

	return EscapeResult{
		Type:        HostSocket,
		Successful:  false,
		RiskLevel:   "Medium",
		Description: "No host Docker socket detected",
	}
}

func (t *Tester) testCgroupReleaseAgent(ctx context.Context) EscapeResult {
	commands := []string{
		"cat /proc/1/cgroup 2>/dev/null",
		"find /sys/fs/cgroup -name 'release_agent' 2>/dev/null",
		"ls -la /sys/fs/cgroup/ 2>/dev/null",
	}

	var outputs []string
	for _, cmd := range commands {
		out, err := t.execSafe(ctx, "sh", "-c", cmd)
		if err == nil && strings.TrimSpace(out) != "" {
			outputs = append(outputs, fmt.Sprintf("$ %s\n%s", cmd, out))
		}
	}

	cgroupV2 := false
	for _, o := range outputs {
		if strings.Contains(o, "0::") {
			cgroupV2 = true
		}
	}

	hasReleaseAgent := false
	for _, o := range outputs {
		if strings.Contains(o, "release_agent") {
			hasReleaseAgent = true
		}
	}

	return EscapeResult{
		Type:       CgroupRelease,
		Successful: hasReleaseAgent,
		Command:    "cgroup release_agent enumeration",
		Output:     strings.Join(outputs, "\n---\n"),
		RiskLevel:  "High",
		Description: func() string {
			if cgroupV2 {
				return "Cgroup v2 detected (release_agent escape not applicable)"
			}
			if hasReleaseAgent {
				return "Cgroup release_agent accessible: potential container escape via cgroup notify_on_release"
			}
			return "No cgroup release_agent escape vector detected"
		}(),
	}
}

func (t *Tester) testProcSysrq(ctx context.Context) EscapeResult {
	commands := []string{
		"cat /proc/sys/kernel/sysrq 2>/dev/null",
	}

	var outputs []string
	out, _ := t.execSafe(ctx, "sh", "-c", commands[0])
	if strings.TrimSpace(out) != "" {
		outputs = append(outputs, "SysRq value: "+strings.TrimSpace(out))
	}

	return EscapeResult{
		Type:       ProcSysrqTrigger,
		Successful: false,
		Command:    "sysrq enumeration (read-only)",
		Output:     strings.Join(outputs, "\n"),
		RiskLevel:  "High",
		Description: func() string {
			if len(outputs) > 0 {
				return "SysRq configuration accessible: verify sysrq is disabled in container"
			}
			return "SysRq not accessible"
		}(),
	}
}

func (t *Tester) testContainerBreakout(ctx context.Context) EscapeResult {
	commands := []string{
		"cat /proc/self/mountinfo 2>/dev/null | head -20",
		"df -h 2>/dev/null",
	}

	var outputs []string
	for _, cmd := range commands {
		out, err := t.execSafe(ctx, "sh", "-c", cmd)
		if err == nil && strings.TrimSpace(out) != "" {
			outputs = append(outputs, fmt.Sprintf("$ %s\n%s", cmd, out))
		}
	}

	return EscapeResult{
		Type:        ContainerBreakout,
		Successful:  false,
		Command:     "container breakout enumeration (read-only)",
		Output:      strings.Join(outputs, "\n---\n"),
		RiskLevel:   "Medium",
		Description: "Container breakout enumeration completed using read-only checks only",
	}
}

func (t *Tester) testCapabilityAbuse(ctx context.Context) EscapeResult {
	capChecks := []struct {
		name    string
		command string
	}{
		{"CAP_SYS_ADMIN", "cat /proc/self/status | grep CapEff 2>/dev/null"},
		{"CAP_NET_ADMIN", "cat /proc/self/status | grep CapEff 2>/dev/null"},
		{"CAP_SYS_PTRACE", "cat /proc/self/status | grep CapEff 2>/dev/null"},
	}

	var outputs []string
	for _, check := range capChecks {
		out, _ := t.execSafe(ctx, "sh", "-c", check.command)
		if strings.TrimSpace(out) != "" {
			outputs = append(outputs, fmt.Sprintf("%s: %s", check.name, strings.TrimSpace(out)))
		}
	}

	return EscapeResult{
		Type:       CapabilityAbuse,
		Successful: len(outputs) > 0,
		Command:    "capability enumeration (read-only)",
		Output:     strings.Join(outputs, ", "),
		RiskLevel:  "High",
		Description: func() string {
			if len(outputs) > 0 {
				return fmt.Sprintf("Capability information detected: %d checks returned data", len(outputs))
			}
			return "No capability information detected"
		}(),
	}
}

func (t *Tester) testK8sServiceAccount(ctx context.Context) EscapeResult {
	saDir := "/var/run/secrets/kubernetes.io/serviceaccount"
	entries, err := os.ReadDir(saDir)
	var outputs []string
	if err == nil {
		for _, e := range entries {
			outputs = append(outputs, fmt.Sprintf("%s/%s: exists", saDir, e.Name()))
		}
	}

	if len(outputs) > 0 {
		tokenFound := false
		tokenPath := fmt.Sprintf("%s/token", saDir)
		if data, err := os.ReadFile(tokenPath); err == nil && len(data) > 0 {
			tokenFound = true
		}

		var rbacCheck []string
		if tokenFound {
			caCertPath := fmt.Sprintf("%s/ca.crt", saDir)
			transport := &http.Transport{}
			if caData, err := os.ReadFile(caCertPath); err == nil {
				certPool := x509.NewCertPool()
				if certPool.AppendCertsFromPEM(caData) {
					transport.TLSClientConfig = &tls.Config{RootCAs: certPool, MinVersion: tls.VersionTLS12}
				}
			}
			client := &http.Client{
				Timeout:   3 * time.Second,
				Transport: transport,
			}
			tokenData, _ := os.ReadFile(tokenPath)
			token := strings.TrimSpace(string(tokenData))
			for _, ns := range []string{"default", "kube-system", "kube-public"} {
				url := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/secrets", ns)
				req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := client.Do(req)
				if err == nil {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
					resp.Body.Close()
					if strings.Contains(string(body), "items") || strings.Contains(string(body), "\"kind\"") {
						rbacCheck = append(rbacCheck, fmt.Sprintf("can list secrets in %s", ns))
					}
				}
			}
		}

		outputs = append(outputs, rbacCheck...)

		return EscapeResult{
			Type:       K8sServiceAccount,
			Successful: tokenFound || len(rbacCheck) > 0,
			Command:    "k8s service account enumeration with RBAC check",
			Output:     strings.Join(outputs, "\n"),
			RiskLevel:  "Critical",
			Description: func() string {
				if len(rbacCheck) > 0 {
					return fmt.Sprintf("Kubernetes service account has elevated RBAC permissions: %s", strings.Join(rbacCheck, "; "))
				}
				if tokenFound {
					return "Kubernetes service account token found: verify RBAC permissions are minimal"
				}
				return "Kubernetes service account files found but token not present"
			}(),
		}
	}

	return EscapeResult{
		Type:        K8sServiceAccount,
		Successful:  false,
		RiskLevel:   "Low",
		Description: "Not running in a Kubernetes pod (no service account found)",
	}
}

func (t *Tester) execSafe(ctx context.Context, name string, args ...string) (string, error) {
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("container escape tests not supported on Windows")
	}

	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("timeout")
		}
		return string(out), nil
	}
	return string(out), nil
}

func (t *Tester) Results() []EscapeResult {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]EscapeResult, len(t.results))
	copy(out, t.results)
	return out
}

func (t *Tester) SeccompProfile() *SeccompProfile {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.seccompProfile
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
