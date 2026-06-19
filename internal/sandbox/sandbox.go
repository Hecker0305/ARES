package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ares/engine/internal/logger"
)

type SandboxLevel int

const (
	SandboxNone       SandboxLevel = 0
	SandboxBasic      SandboxLevel = 1
	SandboxRestricted SandboxLevel = 2
	SandboxFull       SandboxLevel = 3
)

type Config struct {
	Level            SandboxLevel
	WorkDir          string
	Timeouts         time.Duration
	MaxOutput        int64
	MaxFiles         int
	MaxMemoryMB      int
	ReadOnly         bool
	NetworkOff       bool
	AllowedPaths     []string
	DeniedPaths      []string
	EnvWhitelist     []string
	DenySeccomp      bool
	DropCapabilities bool
	NoPrivileged     bool
}

type Result struct {
	Stdout            string
	Stderr            string
	ExitCode          int
	Duration          time.Duration
	TimedOut          bool
	ResourceExhausted bool
	Violation         string
}

type Manager struct {
	mu     sync.Mutex
	active int
	config Config
}

func NewManager(cfg Config) *Manager {
	if cfg.Timeouts == 0 {
		cfg.Timeouts = 60 * time.Second
	}
	if cfg.MaxOutput == 0 {
		cfg.MaxOutput = 10 << 20
	}
	if cfg.MaxFiles == 0 {
		cfg.MaxFiles = 100
	}
	if cfg.MaxMemoryMB == 0 {
		cfg.MaxMemoryMB = 512
	}
	if cfg.Level < SandboxBasic {
		cfg.Level = SandboxBasic
	}
	if cfg.WorkDir == "" {
		cfg.WorkDir = filepath.Join(os.TempDir(), "ares_sandbox")
	}
	cleanWorkDir := filepath.Clean(cfg.WorkDir)
	if strings.Contains(cleanWorkDir, "..") {
		cfg.WorkDir = filepath.Join(os.TempDir(), "ares_sandbox")
		cleanWorkDir = filepath.Clean(cfg.WorkDir)
	}
	absWorkDir, err := filepath.Abs(cleanWorkDir)
	if err != nil {
		absWorkDir = filepath.Join(os.TempDir(), "ares_sandbox")
	}
	cfg.WorkDir = absWorkDir
	os.MkdirAll(cfg.WorkDir, 0700)

	if cfg.NoPrivileged && isPrivilegedContainer() {
		logger.Error("[Sandbox] Refusing to run in privileged container")
		cfg.Level = SandboxFull
	}

	return &Manager{config: cfg}
}

func isPrivilegedContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/secrets/kubernetes.io"); err == nil {
		return true
	}
	if cgroup, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		if strings.Contains(string(cgroup), "docker") || strings.Contains(string(cgroup), "kubepods") {
			return true
		}
	}
	if ns, err := os.Stat("/proc/1/ns/net"); err == nil {
		if myNs, err := os.Stat("/proc/self/ns/net"); err == nil {
			if os.SameFile(ns, myNs) {
				return true
			}
		}
	}
	return false
}

func (m *Manager) Execute(ctx context.Context, binary string, args []string, stdin io.Reader) Result {
	start := time.Now()

	if ctx.Err() != nil {
		return Result{
			ExitCode:          1,
			Violation:         "context cancelled before execution",
			Duration:          time.Since(start),
			ResourceExhausted: true,
		}
	}

	if !m.validatePath(binary) {
		return Result{
			ExitCode:  1,
			Violation: fmt.Sprintf("binary path not allowed: %s", binary),
			Duration:  time.Since(start),
		}
	}

	m.mu.Lock()
	if m.active >= m.config.MaxFiles {
		m.mu.Unlock()
		return Result{
			ExitCode:          1,
			Violation:         "max concurrent sandbox processes reached",
			Duration:          time.Since(start),
			ResourceExhausted: true,
		}
	}
	m.active++
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.active--
		m.mu.Unlock()
	}()

	return m.runCommand(ctx, binary, args, stdin, start, m.config.Level >= SandboxRestricted)
}

func (m *Manager) runCommand(ctx context.Context, binary string, args []string, stdin io.Reader, start time.Time, restricted bool) Result {
	execCtx, cancel := context.WithTimeout(ctx, m.config.Timeouts)
	defer cancel()

	if isPrivilegedContainer() {
		return Result{
			ExitCode:  1,
			Violation: "execution blocked: running in privileged container",
			Duration:  time.Since(start),
		}
	}

	cmd := exec.CommandContext(execCtx, binary, args...)

	if restricted || m.config.Level >= SandboxFull {
		applySeccompProfile(cmd)
		dropAllCapabilities(cmd)
	}

	cmd.Dir = m.config.WorkDir

	if stdin != nil {
		cmd.Stdin = stdin
	}

	var stdout, stderr bytes.Buffer
	stdoutWriter := io.Writer(&stdout)
	stderrWriter := io.Writer(&stderr)

	if m.config.MaxOutput > 0 {
		stdoutWriter = &limitedWriter{w: &stdout, remaining: m.config.MaxOutput}
		stderrWriter = &limitedWriter{w: &stderr, remaining: m.config.MaxOutput}
	}

	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter

	if restricted {
		var filtered []string
		if len(m.config.EnvWhitelist) > 0 {
			for _, key := range m.config.EnvWhitelist {
				if val := os.Getenv(key); val != "" {
					filtered = append(filtered, key+"="+val)
				}
			}
		} else {
			filtered = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
		}
		cmd.Env = filtered
	}

	err := cmd.Run()
	duration := time.Since(start)

	resultPtr := resultPool.Get().(*Result)
	defer resultPool.Put(resultPtr)
	*resultPtr = Result{}

	resultPtr.Stdout = stdout.String()
	resultPtr.Stderr = stderr.String()
	resultPtr.Duration = duration

	if err != nil {
		if execCtx.Err() == context.DeadlineExceeded {
			resultPtr.TimedOut = true
		} else {
			resultPtr.ExitCode = 1
		}
	} else {
		resultPtr.ExitCode = 0
	}

	return *resultPtr
}

func applySeccompProfile(cmd *exec.Cmd) {
	if runtime.GOOS != "linux" {
		applyNonLinuxHardening(cmd)
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{}
}

func dropAllCapabilities(cmd *exec.Cmd) {
	if runtime.GOOS != "linux" {
		applyNonLinuxHardening(cmd)
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
}

func applyNonLinuxHardening(cmd *exec.Cmd) {
	logger.Info("[Sandbox] Applying non-platform hardening (seccomp/capabilities unavailable)")
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
}

var unixDeniedSuffixes = []string{
	"/etc/passwd", "/etc/shadow", "/etc/security", "/etc/sudoers",
	"/etc/ssh", "/etc/kubernetes", "/etc/docker",
	"/proc/", "/sys/", "/dev/", "/boot/", "/root/",
}

var unixAllowedPrefixes = func() []string {
	prefixes := []string{"/usr/", "/bin/", "/opt/", "/sbin/", "/snap/"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		home = filepath.Clean(home)
		prefixes = append(prefixes, home+"/")
		goBin := filepath.Join(home, "go", "bin") + "/"
		prefixes = append(prefixes, goBin)
		localBin := filepath.Join(home, ".local", "bin") + "/"
		prefixes = append(prefixes, localBin)
	}
	return prefixes
}()

var windowsAllowedPrefixes = []string{
	`C:\Windows\System32\`,
	`C:\Windows\SysWOW64\`,
	`C:\Program Files\`,
	`C:\Program Files (x86)\`,
	`C:\Windows\System32\drivers\etc\`,
}

func (m *Manager) validatePath(binary string) bool {
	if binary == "" {
		return false
	}

	binary = filepath.Clean(binary)

	if strings.Contains(binary, "..") {
		return false
	}

	if strings.ContainsAny(binary, "|;&$`'\"(){}[]<>!") {
		return false
	}

	abs, err := filepath.Abs(binary)
	if err != nil {
		return false
	}
	symAbs, symErr := filepath.EvalSymlinks(abs)
	if symErr == nil {
		abs = symAbs
	}
	abs = filepath.Clean(abs)

	if runtime.GOOS == "windows" {
		absUpper := strings.ToUpper(abs)
		valid := false
		for _, prefix := range windowsAllowedPrefixes {
			if strings.HasPrefix(absUpper, strings.ToUpper(prefix)) {
				valid = true
				break
			}
		}
		if !valid {
			return false
		}
		for _, suffix := range []string{`\etc\`, `\Windows\System32\drivers\etc\`} {
			if strings.Contains(absUpper, suffix) {
				return false
			}
		}
	} else {
		for _, suffix := range unixDeniedSuffixes {
			if strings.HasPrefix(abs, suffix) || strings.Contains(abs, suffix) {
				return false
			}
		}
		valid := false
		for _, prefix := range unixAllowedPrefixes {
			if strings.HasPrefix(abs, prefix) {
				valid = true
				break
			}
		}
		if !valid {
			return false
		}
	}

	for _, denied := range m.config.DeniedPaths {
		deniedAbs, err := filepath.Abs(denied)
		if err != nil {
			continue
		}
		if symDenied, symErr := filepath.EvalSymlinks(deniedAbs); symErr == nil {
			deniedAbs = symDenied
		}
		deniedAbs = filepath.Clean(deniedAbs)
		if abs == deniedAbs {
			return false
		}
		deniedPrefix := deniedAbs
		if !strings.HasSuffix(deniedPrefix, string(filepath.Separator)) {
			deniedPrefix += string(filepath.Separator)
		}
		if strings.HasPrefix(abs, deniedPrefix) {
			return false
		}
	}

	for _, allowed := range m.config.AllowedPaths {
		allowedAbs, err := filepath.Abs(allowed)
		if err != nil {
			continue
		}
		if symAllowed, symErr := filepath.EvalSymlinks(allowedAbs); symErr == nil {
			allowedAbs = symAllowed
		}
		allowedAbs = filepath.Clean(allowedAbs)
		if abs == allowedAbs {
			return true
		}
		allowedPrefix := allowedAbs
		if !strings.HasSuffix(allowedPrefix, string(filepath.Separator)) {
			allowedPrefix += string(filepath.Separator)
		}
		if strings.HasPrefix(abs, allowedPrefix) {
			return true
		}
	}
	if len(m.config.AllowedPaths) > 0 {
		return false
	}

	return true
}

func (m *Manager) CreateTempDir(prefix string) (string, error) {
	if m.config.ReadOnly {
		return "", fmt.Errorf("sandbox is read-only, cannot create directories")
	}
	dir, err := os.MkdirTemp(m.config.WorkDir, prefix)
	if err != nil {
		return "", err
	}
	return dir, nil
}

func (m *Manager) Cleanup(dir string) error {
	return os.RemoveAll(dir)
}

func (m *Manager) Active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

func (m *Manager) Config() Config {
	return m.config
}

var resultPool = &sync.Pool{
	New: func() any {
		return &Result{}
	},
}

type limitedWriter struct {
	w          io.Writer
	remaining  int64
	warnedOnce bool
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.remaining <= 0 {
		if !lw.warnedOnce {
			logger.Info(fmt.Sprintf("[Sandbox] limitedWriter: output truncated at %d bytes", lw.remaining))
			lw.warnedOnce = true
		}
		return len(p), nil
	}
	if int64(len(p)) > lw.remaining {
		if !lw.warnedOnce {
			logger.Info(fmt.Sprintf("[Sandbox] limitedWriter: output truncated at %d bytes (discarding %d bytes)",
				lw.remaining, int64(len(p))-lw.remaining))
			lw.warnedOnce = true
		}
		p = p[:lw.remaining]
	}
	n, err := lw.w.Write(p)
	lw.remaining -= int64(n)
	return n, err
}
