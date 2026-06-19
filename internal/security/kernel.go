package security

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

type ActionType int

const (
	ActionShellExec ActionType = iota
	ActionBrowserNavigate
	ActionBrowserEvaluate
	ActionBrowserScreenshot
	ActionHTTPRequest
	ActionFileRead
	ActionFileWrite
	ActionToolCall
	ActionLLMComplete
	ActionPythonExec
	ActionSSHConnect
	ActionC2Beacon
	ActionDNSRequest
)

func (a ActionType) String() string {
	switch a {
	case ActionShellExec:
		return "shell_exec"
	case ActionBrowserNavigate:
		return "browser_navigate"
	case ActionBrowserEvaluate:
		return "browser_evaluate"
	case ActionBrowserScreenshot:
		return "browser_screenshot"
	case ActionHTTPRequest:
		return "http_request"
	case ActionFileRead:
		return "file_read"
	case ActionFileWrite:
		return "file_write"
	case ActionToolCall:
		return "tool_call"
	case ActionLLMComplete:
		return "llm_complete"
	case ActionPythonExec:
		return "python_exec"
	case ActionSSHConnect:
		return "ssh_connect"
	case ActionC2Beacon:
		return "c2_beacon"
	case ActionDNSRequest:
		return "dns_request"
	default:
		return "unknown"
	}
}

type Decision int

const (
	DecisionAllow Decision = iota
	DecisionDeny
	DecisionRequireApproval
)

type Verdict struct {
	Decision  Decision
	Action    ActionType
	Reason    string
	Violation string
	Sanitized string
	Timestamp time.Time
	Source    string
}

type ActionRequest struct {
	Type       ActionType
	Source     string
	Command    string
	Binary     string
	Args       []string
	URL        string
	Path       string
	Script     string
	ToolName   string
	ToolParams map[string]string
	Write      bool
}

type Kernel interface {
	ValidateAction(ctx context.Context, req ActionRequest) Verdict
}

var (
	globalK atomic.Value
)

func SetKernel(k Kernel) {
	globalK.Store(k)
}

func GetK() Kernel {
	k := globalK.Load()
	if k == nil {
		return &defaultKernel{}
	}
	return k.(Kernel)
}

type defaultKernel struct{}

func (k *defaultKernel) ValidateAction(ctx context.Context, req ActionRequest) Verdict {
	switch req.Type {
	case ActionShellExec:
		return validateShellExec(req)
	case ActionHTTPRequest:
		return validateHTTPRequest(ctx, req)
	case ActionFileRead, ActionFileWrite:
		return validateFileOp(req)
	case ActionBrowserEvaluate:
		return validateBrowserEval(req)
	case ActionPythonExec:
		return validatePython(req)
	case ActionToolCall:
		return validateToolCall(req)
	default:
		return Verdict{Decision: DecisionDeny, Action: req.Type, Timestamp: time.Now(), Source: req.Source, Reason: "unknown action type — default deny"}
	}
}

func validateShellExec(req ActionRequest) Verdict {
	v := Verdict{Action: ActionShellExec, Timestamp: time.Now(), Source: req.Source}

	if req.Binary != "" {
		spec := CommandSpec{Binary: req.Binary, Args: req.Args}
		pr := ValidateCommand(spec)
		if pr.Err != nil {
			v.Decision = DecisionDeny
			v.Reason = fmt.Sprintf("command validation: %v", pr.Err)
			v.Violation = "cmd_validation"
			return v
		}
		v.Decision = DecisionAllow
		v.Sanitized = req.Binary
		return v
	}

	parts := strings.Fields(req.Command)
	if len(parts) == 0 {
		v.Decision = DecisionDeny
		v.Reason = "empty command"
		v.Violation = "empty_cmd"
		return v
	}

	spec := CommandSpec{Binary: parts[0], Args: parts[1:]}
	pr := ValidateCommand(spec)
	if pr.Err != nil {
		v.Decision = DecisionDeny
		v.Reason = fmt.Sprintf("command validation: %v", pr.Err)
		v.Violation = "cmd_validation"
		return v
	}
	v.Decision = DecisionAllow
	v.Sanitized = fmt.Sprintf("%s %s", pr.Binary, strings.Join(pr.Args, " "))
	return v
}

func validateHTTPRequest(ctx context.Context, req ActionRequest) Verdict {
	v := Verdict{Action: ActionHTTPRequest, Timestamp: time.Now(), Source: req.Source}

	u, err := url.Parse(req.URL)
	if err != nil {
		v.Decision = DecisionDeny
		v.Reason = fmt.Sprintf("bad url: %v", err)
		v.Violation = "bad_url"
		return v
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		v.Decision = DecisionDeny
		v.Reason = fmt.Sprintf("blocked scheme: %s", u.Scheme)
		v.Violation = "bad_scheme"
		return v
	}

	host := u.Hostname()
	if err := ValidateHostForSSRF(host); err != nil {
		v.Decision = DecisionDeny
		v.Reason = fmt.Sprintf("ssrf: %v", err)
		v.Violation = "ssrf_blocked"
		return v
	}

	// DNS rebinding protection: resolve and cache IPs, reject private IPs
	// Perform two resolutions at different times to detect DNS rebinding
	ips1, lookErr1 := net.LookupIP(host)
	if lookErr1 != nil {
		v.Decision = DecisionDeny
		v.Reason = fmt.Sprintf("dns resolution failed: %v", lookErr1)
		v.Violation = "dns_failed"
		return v
	}

	for _, ip := range ips1 {
		if isPrivateIP(ip) {
			v.Decision = DecisionDeny
			v.Reason = fmt.Sprintf("private ip: %s", ip)
			v.Violation = "private_ip"
			return v
		}
	}

	// Double-resolution to detect DNS rebinding attacks
	time.Sleep(50 * time.Millisecond)
	ips2, lookErr2 := net.LookupIP(host)
	if lookErr2 != nil {
		v.Decision = DecisionDeny
		v.Reason = fmt.Sprintf("dns resolution failed (recheck): %v", lookErr2)
		v.Violation = "dns_failed_recheck"
		return v
	}

	// Compare resolved IPs between both resolutions
	ipSet1 := make(map[string]bool)
	for _, ip := range ips1 {
		ipSet1[ip.String()] = true
	}
	for _, ip := range ips2 {
		if !ipSet1[ip.String()] {
			v.Decision = DecisionDeny
			v.Reason = fmt.Sprintf("dns rebinding detected: %s resolves to different IPs", host)
			v.Violation = "dns_rebinding"
			return v
		}
	}

	port := u.Port()
	if port != "" {
		p := 0
		if _, err := fmt.Sscanf(port, "%d", &p); err != nil || p < 1 || p > 65535 {
			v.Decision = DecisionDeny
			v.Reason = fmt.Sprintf("invalid port: %s", port)
			v.Violation = "bad_port"
			return v
		}
		if p < 1024 && p != 80 && p != 443 {
			v.Decision = DecisionDeny
			v.Reason = fmt.Sprintf("privileged port: %d", p)
			v.Violation = "bad_port"
			return v
		}
	}

	// Pin resolved IPs to prevent DNS rebinding
	v.Sanitized = req.URL
	v.Decision = DecisionAllow
	return v
}

func validateFileOp(req ActionRequest) Verdict {
	v := Verdict{Action: req.Type, Timestamp: time.Now(), Source: req.Source}

	rawPath := req.Path
	if strings.Contains(rawPath, "..") {
		v.Decision = DecisionDeny
		v.Reason = "path traversal detected in raw path"
		v.Violation = "path_traversal"
		return v
	}

	abs, err := filepath.Abs(rawPath)
	if err != nil {
		v.Decision = DecisionDeny
		v.Reason = fmt.Sprintf("bad path: %v", err)
		v.Violation = "bad_path"
		return v
	}

	abs = filepath.Clean(abs)

	sysPaths := []string{"/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/var"}
	for _, sp := range sysPaths {
		if abs == sp || strings.HasPrefix(abs, sp+"/") {
			v.Decision = DecisionDeny
			v.Reason = fmt.Sprintf("system path: %s", sp)
			v.Violation = "sys_path"
			return v
		}
	}

	v.Decision = DecisionAllow
	v.Sanitized = abs
	return v
}

func validateBrowserEval(req ActionRequest) Verdict {
	v := Verdict{Action: ActionBrowserEvaluate, Timestamp: time.Now(), Source: req.Source}

	if len(req.Script) > 65536 {
		v.Decision = DecisionDeny
		v.Reason = "script exceeds 65536 chars"
		v.Violation = "script_too_long"
		return v
	}

	lower := strings.ToLower(req.Script)
	blocked := []string{
		"child_process", "execsync", "exec(", "spawn(", "fork(",
		"process.binding", "process.mainmodule",
		"__proto__", "constructor.constructor",
		"process.exit", "process.kill",
		"require(", "import(", "import ", "from \"", "from '",
		"eval(", "eval ", "eval`", "settimeout(", "setinterval(",
		"new function(", "function(", "window['eval']", "window[\"eval\"]",
		"xmlhttprequest", "fetch(", "navigator.sendbeacon",
		"document.write", "document.writeln",
		"location=", "location.href", "location.replace",
		"atob(", "btoa(", "unescape(",
		"\\u0065val", "\\x65val",
	}
	for _, b := range blocked {
		if strings.Contains(lower, b) {
			v.Decision = DecisionDeny
			v.Reason = fmt.Sprintf("blocked JS: %s", b)
			v.Violation = "blocked_js"
			return v
		}
	}

	v.Decision = DecisionAllow
	v.Sanitized = req.Script
	return v
}

func validatePython(req ActionRequest) Verdict {
	v := Verdict{Action: ActionPythonExec, Timestamp: time.Now(), Source: req.Source}

	if len(req.Script) > 65536 {
		v.Decision = DecisionDeny
		v.Reason = "script exceeds 65536 chars"
		v.Violation = "py_too_long"
		return v
	}

	lower := strings.ToLower(req.Script)
	blocked := []string{
		"os.system", "os.popen", "os.spawn", "os.execl", "os.execle",
		"os.execlp", "os.execv", "os.execve", "os.execvp", "os.execvpe",
		"subprocess", "shutil.rmtree", "shutil.move",
		"socket", "ctypes", "pty", "fork",
		"pickle.loads", "pickle.load",
		"eval(", "exec(", "compile(",
		"__import__", "__builtins__",
		"open(", "file(",
		"breakpoint", "code.interact",
		"webbrowser.open", "webbrowser.open_new",
		"http.server", "smtplib", "ftplib",
		"telnetlib", "paramiko", "pexpect",
		"importlib.import_module", "getattr(os,", "getattr(subprocess,",
		"import os;", "import subprocess;", "import socket;",
		"import ctypes;", "import pty;",
		"base64.b64decode", "base64.decode",
		"marshal.loads", "unmarshal",
		"sys.modules", "sys.exit",
	}
	for _, b := range blocked {
		if strings.Contains(lower, b) {
			v.Decision = DecisionDeny
			v.Reason = fmt.Sprintf("blocked py: %s", b)
			v.Violation = "blocked_py"
			return v
		}
	}

	v.Decision = DecisionAllow
	v.Sanitized = req.Script
	return v
}

func validateToolCall(req ActionRequest) Verdict {
	v := Verdict{Action: ActionToolCall, Timestamp: time.Now(), Source: req.Source}

	denied := map[string]bool{"rm": true, "del": true, "format": true, "mkfs": true, "shutdown": true, "reboot": true}
	if denied[req.ToolName] {
		v.Decision = DecisionDeny
		v.Reason = fmt.Sprintf("denied tool: %s", req.ToolName)
		v.Violation = "denied_tool"
		return v
	}

	v.Decision = DecisionAllow
	return v
}

func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
