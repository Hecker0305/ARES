package python

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"

	"github.com/ares/engine/internal/tools"
)

var blockedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bos\.`),
	regexp.MustCompile(`(?i)\bsubprocess`),
	regexp.MustCompile(`(?i)\bshutil`),
	regexp.MustCompile(`(?i)\bsocket`),
	regexp.MustCompile(`(?i)\bctypes`),
	regexp.MustCompile(`(?i)\bpty`),
	regexp.MustCompile(`(?i)\bfork`),
	regexp.MustCompile(`(?i)\bexec\b`),
	regexp.MustCompile(`(?i)\beval\b`),
	regexp.MustCompile(`(?i)\bcompile\b`),
	regexp.MustCompile(`(?i)\b__import__`),
	regexp.MustCompile(`(?i)\bopen\(`),
	regexp.MustCompile(`(?i)\bexecfile`),
	regexp.MustCompile(`(?i)\bbreakpoint`),
	regexp.MustCompile(`(?i)\bgetattr\(`),
	regexp.MustCompile(`(?i)\bsetattr\(`),
	regexp.MustCompile(`(?i)\bglobals\(\)`),
	regexp.MustCompile(`(?i)\blocals\(\)`),
	regexp.MustCompile(`(?i)\bvars\(\)`),
	regexp.MustCompile(`(?i)\btype\(`),
	regexp.MustCompile(`(?i)\bdelattr`),
	regexp.MustCompile(`(?i)\breload`),
	regexp.MustCompile(`(?i)\bcodecs`),
	regexp.MustCompile(`(?i)\bimportlib`),
	regexp.MustCompile(`(?i)\bpickle`),
	regexp.MustCompile(`(?i)\bmarshal`),
	regexp.MustCompile(`(?i)\bshelve`),
	regexp.MustCompile(`(?i)\bdbm`),
	regexp.MustCompile(`(?i)\bsqlite3`),
}

const (
	defaultMaxScriptSize     = 100000
	defaultMaxOutputSize     = 1 << 20
	defaultMaxInstallTimeout = 120 * time.Second
)

type ToolResult = tools.ToolResult

type Execution struct {
	ID       string
	Code     string
	Output   string
	Error    string
	ExitCode int
	Started  time.Time
	Duration time.Duration
}

type PyConfig struct {
	Enabled         bool
	PipEnabled      bool
	AllowedPackages map[string]bool
	PackageHashes   map[string]string
}

type PyEngine struct {
	workDir string
	cfg     PyConfig
}

func NewPyEngine(workDir string, cfg PyConfig) *PyEngine {
	if cfg.AllowedPackages == nil {
		cfg.AllowedPackages = map[string]bool{
			"requests":       true,
			"beautifulsoup4": true,
			"lxml":           true,
			"scapy":          true,
			"impacket":       true,
			"pycryptodome":   true,
			"paramiko":       true,
			"sqlalchemy":     true,
			"jinja2":         true,
			"pyyaml":         true,
		}
	}
	if cfg.PackageHashes == nil {
		cfg.PackageHashes = make(map[string]string)
	}
	return &PyEngine{workDir: workDir, cfg: cfg}
}

func validateScript(code string) error {
	if len(code) > defaultMaxScriptSize {
		return fmt.Errorf("script exceeds max size of %d bytes", defaultMaxScriptSize)
	}
	for _, pat := range blockedPatterns {
		if pat.MatchString(code) {
			return fmt.Errorf("script contains blocked pattern: %s", pat.String())
		}
	}
	if err := validateScriptAST(code); err != nil {
		return err
	}
	return nil
}

var astBlockedModules = []string{
	"os", "subprocess", "sys", "shutil", "socket", "ctypes",
	"pty", "importlib", "pickle", "marshal", "shelve", "dbm",
	"codecs", "signal", "multiprocessing", "threading", "asyncio",
}

var astDangerousCalls = []string{
	"eval", "exec", "compile", "__import__", "open",
	"execfile", "breakpoint", "input",
}

var astDangerousAttrs = []string{
	"system", "popen", "run", "call", "fork", "execve",
	"spawn", "Popen", "check_call", "check_output",
}

func validateScriptWithPythonAST(code string) error {
	pythonBin := findPython()
	if pythonBin == "" {
		return fmt.Errorf("python not found for AST validation")
	}

	validationScript := `
import ast, sys
try:
    tree = ast.parse(sys.stdin.read())
except SyntaxError as e:
    print(f"SYNTAX_ERROR: {e}")
    sys.exit(1)

blocked_modules = {"os", "subprocess", "sys", "shutil", "socket", "ctypes", "pty", "importlib", "pickle", "marshal", "shelve", "dbm", "codecs", "signal", "multiprocessing", "threading", "asyncio"}
dangerous_calls = {"eval", "exec", "compile", "__import__", "open", "execfile", "breakpoint", "input"}
dangerous_attrs = {"system", "popen", "run", "call", "fork", "execve", "spawn", "Popen", "check_call", "check_output"}

for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for alias in node.names:
            top = alias.name.split(".")[0]
            if top in blocked_modules:
                print(f"BLOCKED: import {alias.name}")
                sys.exit(1)
    elif isinstance(node, ast.ImportFrom):
        if node.module:
            top = node.module.split(".")[0]
            if top in blocked_modules:
                print(f"BLOCKED: from {node.module} import")
                sys.exit(1)
    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in dangerous_calls:
            print(f"BLOCKED: dangerous call {node.func.id}")
            sys.exit(1)
        if isinstance(node.func, ast.Attribute) and node.func.attr in dangerous_attrs:
            print(f"BLOCKED: dangerous attribute {node.func.attr}")
            sys.exit(1)
print("OK")
`
	cmd := exec.Command(pythonBin, "-c", validationScript)
	cmd.Stdin = strings.NewReader(code)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("python AST validation failed: %s", strings.TrimSpace(string(output)))
	}
	if strings.Contains(string(output), "BLOCKED:") {
		return fmt.Errorf("script validation failed: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func validateScriptAST(code string) error {
	if err := validateScriptWithPythonAST(code); err != nil {
		return err
	}
	if err := validateASTPureGo(code); err != nil {
		return err
	}
	return nil
}

var dangerousCalls = map[string]bool{
	"eval": true, "exec": true, "compile": true, "__import__": true,
	"open": true, "execfile": true, "breakpoint": true, "input": true,
}

var dangerousAttrs = map[string]bool{
	"system": true, "popen": true, "run": true, "call": true,
	"fork": true, "execve": true, "spawn": true, "check_call": true,
	"check_output": true, "Popen": true, "stdin": true, "stdout": true,
}

var dangerousModules = map[string]bool{
	"os": true, "subprocess": true, "sys": true,
}

func validateASTPureGo(code string) error {
	lines := strings.Split(code, "\n")
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)
		for name := range dangerousCalls {
			pattern := name + "("
			if strings.Contains(lower, pattern) {
				return fmt.Errorf("line %d: dangerous call detected: %s", lineNum+1, name)
			}
		}
		for mod := range dangerousModules {
			if strings.Contains(lower, mod+".") {
				for attr := range dangerousAttrs {
					if strings.Contains(lower, "."+attr) {
						return fmt.Errorf("line %d: dangerous module/attribute access: %s.%s", lineNum+1, mod, attr)
					}
				}
			}
		}
		for _, pat := range blockedPatterns {
			if pat.MatchString(trimmed) {
				return fmt.Errorf("line %d: blocked pattern: %s", lineNum+1, pat.String())
			}
		}
	}
	return nil
}

func (e *PyEngine) Run(code string, timeout time.Duration) (*Execution, error) {
	if !e.cfg.Enabled {
		return nil, fmt.Errorf("python execution is disabled")
	}
	if err := validateScript(code); err != nil {
		return nil, fmt.Errorf("script validation failed: %w", err)
	}

	if timeout == 0 {
		timeout = 60 * time.Second
	}
	if timeout > 300*time.Second {
		timeout = 300 * time.Second
	}

	codeHash := sha256.Sum256([]byte(code))
	ex := &Execution{
		ID:      fmt.Sprintf("py-%x", codeHash[:8]),
		Code:    code,
		Started: time.Now(),
	}

	tmpDir := e.workDir
	if tmpDir == "" {
		tmpDir = filepath.Join(os.TempDir(), "ares-python-sandbox")
	}
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}

	scriptPath := filepath.Join(tmpDir, fmt.Sprintf("script-%s.py", ex.ID))
	if err := os.WriteFile(scriptPath, []byte(code), 0600); err != nil {
		return nil, fmt.Errorf("write script: %w", err)
	}
	defer os.Remove(scriptPath)

	pythonBin := findPython()
	if pythonBin == "" {
		return nil, fmt.Errorf("python not found in PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, pythonBin, "-I", scriptPath)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"PYTHONPATH=",
		"PYTHONHOME=",
		"PYTHONSTARTUP=",
		"PYTHONINSPECT=",
		"PYTHONUSERBASE=",
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		ex.Duration = time.Since(ex.Started)
		if exitErr, ok := err.(*exec.ExitError); ok {
			ex.ExitCode = exitErr.ExitCode()
		} else {
			ex.Error = err.Error()
		}
	}

	ex.Duration = time.Since(ex.Started)

	if ctx.Err() == context.DeadlineExceeded {
		ex.Error = fmt.Sprintf("execution timed out after %v", timeout)
		ex.ExitCode = -1
		return ex, nil
	}

	out := stdout.String()
	if len(out) > defaultMaxOutputSize {
		out = out[:defaultMaxOutputSize]
	}
	ex.Output = out

	stderrOut := stderr.String()
	if len(stderrOut) > defaultMaxOutputSize {
		stderrOut = stderrOut[:defaultMaxOutputSize]
	}
	if stderrOut != "" {
		ex.Output += "\n[STDERR] " + stderrOut
	}

	return ex, nil
}

var safePackagePattern = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

func validatePackageName(pkg string) error {
	if pkg == "" {
		return fmt.Errorf("empty package name")
	}
	if len(pkg) > 256 {
		return fmt.Errorf("package name too long: %d chars", len(pkg))
	}
	if strings.HasPrefix(pkg, ".") || strings.HasPrefix(pkg, "-") {
		return fmt.Errorf("package name starts with invalid character")
	}
	if strings.Contains(pkg, "://") || strings.Contains(pkg, "..") {
		return fmt.Errorf("package name contains URL or path traversal")
	}
	return nil
}

func (e *PyEngine) RunWithDeps(code string, deps []string, timeout time.Duration) (*Execution, error) {
	if len(deps) > 0 {
		if !e.cfg.PipEnabled {
			return nil, fmt.Errorf("pip install is disabled")
		}
		for _, dep := range deps {
			if err := validatePackageName(dep); err != nil {
				return nil, fmt.Errorf("invalid dependency %q: %w", dep, err)
			}
			pkgName := strings.SplitN(dep, "==", 2)[0]
			if !e.cfg.AllowedPackages[pkgName] {
				return nil, fmt.Errorf("package %q not in allowed list", pkgName)
			}
			if !strings.Contains(dep, "==") {
				return nil, fmt.Errorf("dependency %q must be version-pinned (e.g. requests==2.31.0)", dep)
			}
			if expectedHash, ok := e.cfg.PackageHashes[dep]; ok {
				actualHash, err := getPackageHash(dep)
				if err != nil {
					return nil, fmt.Errorf("failed to verify package hash for %q: %w", dep, err)
				}
				if actualHash != expectedHash {
					return nil, fmt.Errorf("package hash mismatch for %q: expected %s, got %s", dep, expectedHash, actualHash)
				}
			}
		}
		pythonBin := findPython()
		if pythonBin != "" {
			for _, dep := range deps {
				if err := validatePackageName(dep); err != nil {
					return nil, fmt.Errorf("invalid package name %q: %w", dep, err)
				}
				logger.Info(fmt.Sprintf("[Python] Installing allowed package %q from PyPI", dep))
				installCtx, cancel := context.WithTimeout(context.Background(), defaultMaxInstallTimeout)
				cmd := exec.CommandContext(installCtx, pythonBin, "-m", "pip", "install", "--no-cache-dir", "--require-hashes", dep)
				if err := cmd.Run(); err != nil {
					cancel()
					return nil, fmt.Errorf("failed to install dependency %q: %w", dep, err)
				}
				cancel()
			}
		}
	}
	return e.Run(code, timeout)
}

func (e *PyEngine) CheckPackages(packages []string) map[string]bool {
	pythonBin := findPython()
	if pythonBin == "" {
		return nil
	}
	results := make(map[string]bool)
	for _, pkg := range packages {
		name := strings.Split(pkg, "<")[0]
		if err := validatePackageName(name); err != nil {
			results[pkg] = false
			continue
		}
		importStr := strings.ReplaceAll(name, "-", "_")
		cmd := exec.Command(pythonBin, "-c", fmt.Sprintf("import %s", importStr))
		results[pkg] = cmd.Run() == nil
	}
	return results
}

func (e *PyEngine) InstallPackage(pkg string) error {
	if err := validatePackageName(pkg); err != nil {
		return fmt.Errorf("invalid package name: %w", err)
	}
	if !strings.Contains(pkg, "==") {
		return fmt.Errorf("package %q must be version-pinned (e.g. requests==2.31.0)", pkg)
	}
	pkgName := strings.SplitN(pkg, "==", 2)[0]
	if !e.cfg.AllowedPackages[pkgName] {
		return fmt.Errorf("package %q not in allowed list", pkgName)
	}
	if expectedHash, ok := e.cfg.PackageHashes[pkg]; ok {
		actualHash, err := getPackageHash(pkg)
		if err != nil {
			return fmt.Errorf("failed to verify package hash for %q: %w", pkg, err)
		}
		if actualHash != expectedHash {
			return fmt.Errorf("package hash mismatch for %q: expected %s, got %s", pkg, expectedHash, actualHash)
		}
	}
	pythonBin := findPython()
	if pythonBin == "" {
		return fmt.Errorf("python not found")
	}
	installCtx, cancel := context.WithTimeout(context.Background(), defaultMaxInstallTimeout)
	defer cancel()
	return exec.CommandContext(installCtx, pythonBin, "-m", "pip", "install", "--no-cache-dir", "--require-hashes", pkg).Run()
}

func getPackageHash(pkg string) (string, error) {
	pythonBin := findPython()
	if pythonBin == "" {
		return "", fmt.Errorf("python not found")
	}
	cmd := exec.Command(pythonBin, "-m", "pip", "hash", pkg)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "--hash=") {
			return strings.TrimPrefix(line, "--hash="), nil
		}
	}
	return "", fmt.Errorf("could not extract hash for %q", pkg)
}

func findPython() string {
	for _, name := range []string{"python3", "python", "py"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

type runParams struct {
	Code      string   `json:"code"`
	Deps      []string `json:"deps"`
	Timeout   int      `json:"timeout"`
	WorkDir   string   `json:"work_dir"`
	Sandboxed bool     `json:"sandboxed"`
}

func Run(params json.RawMessage, sc interface{}) ToolResult {
	var p runParams
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
	}
	if p.Code == "" {
		return ToolResult{Error: "code is required"}
	}

	workDir := p.WorkDir
	if workDir == "" {
		workDir = os.TempDir()
	}

	engine := NewPyEngine(workDir, PyConfig{})
	timeout := time.Duration(p.Timeout) * time.Second

	var result *Execution
	var err error

	if len(p.Deps) > 0 {
		result, err = engine.RunWithDeps(p.Code, p.Deps, timeout)
	} else {
		result, err = engine.Run(p.Code, timeout)
	}

	if err != nil {
		return ToolResult{Error: fmt.Sprintf("execution error: %v", err)}
	}

	if result.Error != "" {
		return ToolResult{Output: result.Output, Error: result.Error}
	}
	return ToolResult{Output: fmt.Sprintf("[%s] exit=%d duration=%v\n%s",
		result.ID, result.ExitCode, result.Duration, result.Output)}
}

func CheckPackages(params json.RawMessage, sc interface{}) ToolResult {
	var p struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
	}
	engine := NewPyEngine("", PyConfig{})
	results := engine.CheckPackages(p.Packages)
	data, _ := json.MarshalIndent(results, "", "  ")
	return ToolResult{Output: string(data)}
}

func InstallPackage(params json.RawMessage, sc interface{}) ToolResult {
	var p struct{ Package string }
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
	}
	engine := NewPyEngine("", PyConfig{})
	if err := engine.InstallPackage(p.Package); err != nil {
		return ToolResult{Error: err.Error()}
	}
	return ToolResult{Output: "Installed: " + p.Package}
}

func CreateSandbox(params json.RawMessage, sc interface{}) ToolResult {
	var p struct{ WorkDir string }
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
	}
	workDir := p.WorkDir
	if workDir == "" {
		workDir = filepath.Join(os.TempDir(), "ares-sandbox", uuid.New())
	}
	if err := os.MkdirAll(workDir, 0700); err != nil {
		return ToolResult{Error: err.Error()}
	}
	zipData := &bytes.Buffer{}
	zipWriter := zip.NewWriter(zipData)
	zipWriter.Create("sandbox/")
	zipWriter.Close()
	return ToolResult{Output: fmt.Sprintf("Sandbox created at: %s", workDir)}
}
