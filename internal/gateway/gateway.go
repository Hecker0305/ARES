package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/control"
	"github.com/ares/engine/internal/guardrails"
	"github.com/ares/engine/internal/policy"
	"github.com/ares/engine/internal/ratelimit"
	runtime "github.com/ares/engine/internal/resource"
	"github.com/ares/engine/internal/sandbox"
	"github.com/ares/engine/internal/scope"
	"github.com/ares/engine/internal/security"
)

type ToolSchema struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]ParamSchema `json:"parameters"`
	Required    []string               `json:"required"`
	Allowed     bool                   `json:"allowed"`
	Effect      string                 `json:"effect"`
}

type ParamSchema struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Required    bool     `json:"required"`
	Allowed     []string `json:"allowed,omitempty"`
	MinLen      int      `json:"min_len,omitempty"`
	MaxLen      int      `json:"max_len,omitempty"`
}

type CallRequest struct {
	Tool    string            `json:"tool"`
	Params  map[string]string `json:"params"`
	Target  string            `json:"target"`
	TraceID string            `json:"trace_id"`
	AgentID string            `json:"agent_id"`
}

type CallResult struct {
	Success  bool          `json:"success"`
	Output   string        `json:"output"`
	Error    string        `json:"error"`
	Duration time.Duration `json:"duration"`
	Blocked  bool          `json:"blocked"`
	Reason   string        `json:"reason"`
	Verdict  string        `json:"verdict"`
}

type Gateway struct {
	mu             sync.RWMutex
	schemas        map[string]ToolSchema
	policy         *policy.PolicyEngine
	controlEngine  *control.PolicyEngine
	guardrails     *guardrails.Engine
	sandbox        *sandbox.Manager
	scope          *scope.Enforcer
	auditLog       []CallResult
	maxLogSize     int
	governor       *runtime.Governor
	rateLimiter    *ratelimit.Limiter
	perClientLimit map[string]*ratelimit.Limiter
	perClientMu    sync.RWMutex
}

var allowedScanners = map[string]bool{
	"nuclei": true,
	"nmap":   true,
	"sqlmap": true,
	"dalfox": true,
}

var gatewayHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return http.ErrUseLastResponse
		}
		if ip := net.ParseIP(req.URL.Hostname()); ip != nil {
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
				return fmt.Errorf("redirect to private IP blocked")
			}
		}
		return nil
	},
	Transport: &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	},
}

func New(pe *policy.PolicyEngine, g *guardrails.Engine, sb *sandbox.Manager) *Gateway {
	gw := &Gateway{
		schemas:        make(map[string]ToolSchema),
		policy:         pe,
		guardrails:     g,
		sandbox:        sb,
		auditLog:       make([]CallResult, 0, 1000),
		maxLogSize:     10000,
		governor:       runtime.New(runtime.DefaultBudget()),
		rateLimiter:    ratelimit.New(10, 20),
		perClientLimit: make(map[string]*ratelimit.Limiter),
	}
	gw.registerDefaults()
	return gw
}

func (gw *Gateway) SetGovernor(g *runtime.Governor) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.governor = g
}

func (gw *Gateway) SetRateLimiter(rps float64, burst int) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.rateLimiter = ratelimit.New(rps, burst)
}

func (gw *Gateway) getOrCreateClientLimiter(clientID string) *ratelimit.Limiter {
	gw.perClientMu.RLock()
	lim, ok := gw.perClientLimit[clientID]
	gw.perClientMu.RUnlock()
	if ok {
		return lim
	}
	gw.perClientMu.Lock()
	defer gw.perClientMu.Unlock()
	lim, ok = gw.perClientLimit[clientID]
	if ok {
		return lim
	}
	lim = ratelimit.New(5, 10)
	gw.perClientLimit[clientID] = lim
	return lim
}

func (gw *Gateway) Governor() *runtime.Governor {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	return gw.governor
}

func (gw *Gateway) SetControlEngine(ce *control.PolicyEngine) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.controlEngine = ce
}

func (gw *Gateway) SetScope(s *scope.Enforcer) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.scope = s
}

func (gw *Gateway) registerDefaults() {
	gw.Register(ToolSchema{
		Name:        "terminal_execute",
		Description: "Execute a command on the target system",
		Parameters: map[string]ParamSchema{
			"command": {
				Type: "string", Description: "Command to execute",
				Required: true, MinLen: 1, MaxLen: 4096,
			},
			"timeout": {
				Type: "integer", Description: "Timeout in seconds",
				Allowed: []string{"30", "60", "120", "300"},
			},
		},
		Required: []string{"command"},
	})
	gw.Register(ToolSchema{
		Name:        "web_request",
		Description: "Send an HTTP request to a target",
		Parameters: map[string]ParamSchema{
			"method": {
				Type: "string", Description: "HTTP method",
				Allowed: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			},
			"url": {
				Type: "string", Description: "Target URL",
				Required: true, MaxLen: 8192,
			},
			"body": {
				Type: "string", Description: "Request body",
				MaxLen: 65536,
			},
		},
		Required: []string{"url"},
	})
	gw.Register(ToolSchema{
		Name:        "file_read",
		Description: "Read a file from the target",
		Parameters: map[string]ParamSchema{
			"path": {
				Type: "string", Description: "File path",
				Required: true, MaxLen: 1024,
			},
		},
		Required: []string{"path"},
	})
	gw.Register(ToolSchema{
		Name:        "network_scan",
		Description: "Perform a network scan",
		Parameters: map[string]ParamSchema{
			"target": {
				Type: "string", Description: "Target host/IP",
				Required: true, MaxLen: 256,
			},
			"ports": {
				Type: "string", Description: "Port range",
				Allowed: []string{"common", "full", "top-100", "top-1000"},
			},
		},
		Required: []string{"target"},
	})
	gw.Register(ToolSchema{
		Name:        "vuln_scan",
		Description: "Run a vulnerability scanner",
		Parameters: map[string]ParamSchema{
			"target": {
				Type: "string", Description: "Target URL/IP",
				Required: true, MaxLen: 256,
			},
			"scanner": {
				Type: "string", Description: "Scanner to use",
				Allowed: []string{"nuclei", "nmap", "sqlmap", "dalfox"},
			},
		},
	})
	gw.Register(ToolSchema{
		Name:        "exploit",
		Description: "Attempt to exploit a vulnerability",
		Parameters: map[string]ParamSchema{
			"type": {
				Type: "string", Description: "Vulnerability type",
				Allowed: []string{"sqli", "xss", "lfi", "rce", "ssrf", "idor"},
			},
			"target": {
				Type: "string", Description: "Target URL/IP",
				Required: true, MaxLen: 256,
			},
			"payload": {
				Type: "string", Description: "Exploit payload",
				MaxLen: 65536,
			},
		},
		Required: []string{"type", "target"},
	})
}

func (gw *Gateway) Register(schema ToolSchema) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.schemas[schema.Name] = schema
}

func (gw *Gateway) Call(ctx context.Context, req CallRequest) CallResult {
	start := time.Now()

	gw.mu.RLock()
	schema, exists := gw.schemas[req.Tool]
	limiter := gw.rateLimiter
	gw.mu.RUnlock()

	if !exists {
		return CallResult{
			Success:  false,
			Blocked:  true,
			Reason:   fmt.Sprintf("unknown tool: %s", req.Tool),
			Duration: time.Since(start),
		}
	}

	if limiter != nil && !limiter.TryAcquire() {
		return gw.audit(CallResult{
			Success:  false,
			Blocked:  true,
			Reason:   "rate limit exceeded",
			Duration: time.Since(start),
		})
	}

	if req.AgentID != "" {
		clientLim := gw.getOrCreateClientLimiter(req.AgentID)
		if clientLim != nil && !clientLim.TryAcquire() {
			return gw.audit(CallResult{
				Success:  false,
				Blocked:  true,
				Reason:   "per-client rate limit exceeded",
				Duration: time.Since(start),
			})
		}
	}

	// Use global kernel directly (thread-safe accessor)
	if kernel := security.GetK(); true {
		verdict := kernel.ValidateAction(ctx, security.ActionRequest{
			Type:       security.ActionToolCall,
			ToolName:   req.Tool,
			ToolParams: req.Params,
			Source:     "gateway",
		})
		if verdict.Decision != security.DecisionAllow {
			return gw.audit(CallResult{
				Success:  false,
				Blocked:  true,
				Reason:   fmt.Sprintf("kernel denied: %s", verdict.Reason),
				Duration: time.Since(start),
			})
		}
	}

	if gw.governor != nil {
		if !gw.governor.AcquireExecution() {
			return gw.audit(CallResult{
				Success:  false,
				Blocked:  true,
				Reason:   "resource limit: execution budget exhausted",
				Duration: time.Since(start),
			})
		}
	}

	if err := gw.validateParams(schema, req.Params); err != nil {
		return gw.audit(CallResult{
			Success:  false,
			Blocked:  true,
			Reason:   fmt.Sprintf("parameter validation failed: %v", err),
			Duration: time.Since(start),
		})
	}

	policyAction := gw.toolToPolicyAction(req.Tool)
	policyRes := gw.policy.Evaluate(policyAction, policy.Resource("process"), req.Target)
	if !policyRes.Allowed && policyRes.Effect != policy.EffectWarn {
		return gw.audit(CallResult{
			Success:  false,
			Blocked:  true,
			Reason:   fmt.Sprintf("policy denied: %s", policyRes.Reason),
			Duration: time.Since(start),
		})
	}

	if gw.controlEngine != nil {
		ctrlReq := control.UnifiedRequest{
			ID:          fmt.Sprintf("gateway-%s-%s", req.Tool, req.TraceID),
			Source:      control.EnforcementGateway,
			Action:      req.Tool,
			Target:      req.Target,
			RiskLevel:   control.RiskMedium,
			IsNetworkOp: req.Tool == "web_request" || req.Tool == "network_scan",
			IsExploit:   req.Tool == "exploit",
			TraceID:     req.TraceID,
		}
		ctrlRes := gw.controlEngine.Evaluate(ctrlReq)
		if !ctrlRes.Allowed {
			return gw.audit(CallResult{
				Success:  false,
				Blocked:  true,
				Reason:   fmt.Sprintf("control engine denied: %s", ctrlRes.Reason),
				Duration: time.Since(start),
			})
		}
	}

	detections := gw.guardrails.CheckPrompt(fmt.Sprintf("%s %v", req.Tool, req.Params))
	if gw.guardrails.ShouldBlock(detections) {
		return gw.audit(CallResult{
			Success:  false,
			Blocked:  true,
			Reason:   fmt.Sprintf("guardrail blocked: %s", detections[0].Category),
			Duration: time.Since(start),
		})
	}

	result := gw.dispatch(ctx, req, schema)

	result.Duration = time.Since(start)

	safeOutput := gw.guardrails.SanitizeOutput(result.Output)
	result.Output = safeOutput

	outputDetections := gw.guardrails.CheckOutput(safeOutput)
	for _, d := range outputDetections {
		if d.ThreatLevel >= guardrails.ThreatHigh {
			result.Output = "[REDACTED: potential secret leak detected in output]"
			break
		}
	}

	return gw.audit(result)
}

func (gw *Gateway) dispatch(ctx context.Context, req CallRequest, schema ToolSchema) CallResult {
	switch req.Tool {
	case "terminal_execute":
		cmd := req.Params["command"]
		if cmd == "" {
			return CallResult{Success: false, Error: "empty command", Verdict: "blocked"}
		}
		if err := security.ValidateShellCommand(cmd); err != nil {
			return CallResult{Success: false, Error: err.Error(), Verdict: "blocked"}
		}
		binary, args, err := security.ParseCommandToArgs(cmd)
		if err != nil {
			return CallResult{Success: false, Error: fmt.Sprintf("command parse failed: %v", err), Verdict: "blocked"}
		}
		spec := security.CommandSpec{Binary: binary, Args: args}
		validated := security.ValidateCommand(spec)
		if validated.Err != nil {
			return CallResult{Success: false, Error: validated.Err.Error(), Verdict: "blocked"}
		}
		r := gw.sandbox.Execute(ctx, validated.Binary, validated.Args, nil)
		return CallResult{
			Success: r.ExitCode == 0,
			Output:  r.Stdout,
			Error:   r.Stderr,
			Verdict: "executed",
		}
	case "web_request":
		targetURL := req.Params["url"]
		if targetURL == "" {
			targetURL = req.Target
		}
		if err := security.ValidateURL(targetURL); err != nil {
			return CallResult{Success: false, Error: err.Error(), Verdict: "blocked"}
		}
		gw.mu.RLock()
		scopeEnforcer := gw.scope
		gw.mu.RUnlock()
		if scopeEnforcer != nil && !scopeEnforcer.IsAllowed(targetURL) {
			return CallResult{Success: false, Error: fmt.Sprintf("target %q is out of scope", targetURL), Verdict: "blocked"}
		}
		httpCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		httpReq, err := http.NewRequestWithContext(httpCtx, req.Params["method"], targetURL, nil)
		if err != nil {
			return CallResult{Success: false, Error: err.Error(), Verdict: "error"}
		}
		resp, err := gatewayHTTPClient.Do(httpReq)
		if err != nil {
			return CallResult{Success: false, Error: err.Error(), Verdict: "error"}
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return CallResult{Success: false, Error: fmt.Sprintf("failed to read response: %v", err), Verdict: "error"}
		}
		return CallResult{
			Success: true,
			Output:  fmt.Sprintf("HTTP %d\n%s", resp.StatusCode, string(body)),
			Verdict: "executed",
		}
	case "file_read":
		path, ok := req.Params["path"]
		if !ok {
			return CallResult{Success: false, Error: "missing path parameter", Verdict: "blocked"}
		}
		if err := security.ValidateFileReadScope(path); err != nil {
			return CallResult{Success: false, Error: err.Error(), Verdict: "blocked"}
		}
		cleanPath, err := security.ValidateReadPath(path)
		if err != nil {
			return CallResult{Success: false, Error: err.Error(), Verdict: "blocked"}
		}
		data, err := os.ReadFile(cleanPath)
		if err != nil {
			return CallResult{Success: false, Error: err.Error(), Verdict: "error"}
		}
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		return CallResult{
			Success: true,
			Output:  string(data),
			Verdict: "executed",
		}
	case "network_scan":
		scanTarget := req.Params["target"]
		if scanTarget == "" {
			scanTarget = req.Target
		}
		if err := security.ValidateTarget(scanTarget); err != nil {
			return CallResult{Success: false, Error: err.Error(), Verdict: "blocked"}
		}
		gw.mu.RLock()
		scopeEnforcer := gw.scope
		gw.mu.RUnlock()
		if scopeEnforcer != nil && !scopeEnforcer.IsAllowed(scanTarget) {
			return CallResult{Success: false, Error: fmt.Sprintf("target %q is out of scope", scanTarget), Verdict: "blocked"}
		}
		spec := security.CommandSpec{Binary: "nmap", Args: []string{"-sV", "-sC", "--open", "-T4", scanTarget}}
		validated := security.ValidateCommand(spec)
		if validated.Err != nil {
			return CallResult{Success: false, Error: validated.Err.Error(), Verdict: "blocked"}
		}
		r := gw.sandbox.Execute(ctx, validated.Binary, validated.Args, nil)
		return CallResult{
			Success: r.ExitCode == 0,
			Output:  r.Stdout,
			Error:   r.Stderr,
			Verdict: "executed",
		}
	case "vuln_scan":
		scanTarget := req.Params["target"]
		if scanTarget == "" {
			scanTarget = req.Target
		}
		scanner := req.Params["scanner"]
		if scanner == "" {
			scanner = "nuclei"
		}
		if !allowedScanners[scanner] {
			return CallResult{Success: false, Error: fmt.Sprintf("disallowed scanner: %s", scanner), Verdict: "blocked"}
		}
		gw.mu.RLock()
		scopeEnforcer := gw.scope
		gw.mu.RUnlock()
		if scopeEnforcer != nil && !scopeEnforcer.IsAllowed(scanTarget) {
			return CallResult{Success: false, Error: fmt.Sprintf("target %q is out of scope", scanTarget), Verdict: "blocked"}
		}
		spec := security.CommandSpec{Binary: scanner, Args: []string{"-u", scanTarget, "-silent"}}
		validated := security.ValidateCommand(spec)
		if validated.Err != nil {
			return CallResult{Success: false, Error: validated.Err.Error(), Verdict: "blocked"}
		}
		r := gw.sandbox.Execute(ctx, validated.Binary, validated.Args, nil)
		return CallResult{
			Success: r.ExitCode == 0,
			Output:  r.Stdout,
			Error:   r.Stderr,
			Verdict: "executed",
		}
	case "exploit":
		return CallResult{Success: true, Output: "[exploit requires manual review]", Verdict: "requires_approval"}
	default:
		return CallResult{Success: false, Error: fmt.Sprintf("no handler for: %s", req.Tool), Verdict: "no_handler"}
	}
}

func (gw *Gateway) validateParams(schema ToolSchema, params map[string]string) error {
	for _, req := range schema.Required {
		if _, ok := params[req]; !ok {
			return fmt.Errorf("missing required parameter: %s", req)
		}
	}
	for name, val := range params {
		ps, ok := schema.Parameters[name]
		if !ok {
			continue
		}
		if ps.Allowed != nil && len(ps.Allowed) > 0 {
			found := false
			for _, a := range ps.Allowed {
				if val == a {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("parameter %q value %q not in allowed list", name, val)
			}
		}
		if ps.MaxLen > 0 && len(val) > ps.MaxLen {
			return fmt.Errorf("parameter %q exceeds max length %d", name, ps.MaxLen)
		}
		if ps.MinLen > 0 && len(val) < ps.MinLen {
			return fmt.Errorf("parameter %q below min length %d", name, ps.MinLen)
		}
		if strings.Contains(val, "\n") || strings.Contains(val, "\r") {
			return fmt.Errorf("parameter %q contains newlines", name)
		}
	}
	return nil
}

func (gw *Gateway) toolToPolicyAction(tool string) policy.Action {
	switch {
	case strings.Contains(tool, "scan") || strings.Contains(tool, "nmap"):
		return policy.ActionNetworkScan
	case strings.Contains(tool, "exec") || strings.Contains(tool, "terminal"):
		return policy.ActionExecCommand
	case strings.Contains(tool, "read") || strings.Contains(tool, "file"):
		return policy.ActionFileRead
	case strings.Contains(tool, "write"):
		return policy.ActionFileWrite
	case strings.Contains(tool, "request") || strings.Contains(tool, "web"):
		return policy.ActionWebRequest
	case strings.Contains(tool, "exploit"):
		return policy.ActionNetworkScan
	default:
		return policy.ActionExecCommand
	}
}

func (gw *Gateway) Schemas() []ToolSchema {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	result := make([]ToolSchema, 0, len(gw.schemas))
	for _, s := range gw.schemas {
		result = append(result, s)
	}
	return result
}

func (gw *Gateway) SchemaFor(tool string) *ToolSchema {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	s, ok := gw.schemas[tool]
	if !ok {
		return nil
	}
	return &s
}

func (gw *Gateway) AuditLog() []CallResult {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	result := make([]CallResult, len(gw.auditLog))
	copy(result, gw.auditLog)
	return result
}

func (gw *Gateway) audit(r CallResult) CallResult {
	gw.mu.Lock()
	// Redact sensitive content before storing in audit log
	redacted := r
	redacted.Output = redactSensitiveData(r.Output)
	redacted.Error = redactSensitiveData(r.Error)
	gw.auditLog = append(gw.auditLog, redacted)
	if len(gw.auditLog) > gw.maxLogSize {
		gw.auditLog = gw.auditLog[len(gw.auditLog)-gw.maxLogSize:]
	}
	gw.mu.Unlock()
	return r
}

func redactSensitiveData(s string) string {
	if len(s) > 10000 {
		s = s[:10000]
	}
	patterns := []string{
		"api_key", "apikey", "api-key", "authorization",
		"secret", "password", "passwd", "token", "bearer",
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		for _, p := range patterns {
			if strings.Contains(lower, p) {
				lines[i] = "[REDACTED: line contains potential sensitive data]"
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

func (gw *Gateway) Stats() map[string]interface{} {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	blocked := 0
	allowed := 0
	for _, r := range gw.auditLog {
		if r.Blocked {
			blocked++
		} else {
			allowed++
		}
	}
	return map[string]interface{}{
		"total_calls": len(gw.auditLog),
		"blocked":     blocked,
		"allowed":     allowed,
		"schemas":     len(gw.schemas),
	}
}

func (r CallResult) String() string {
	if r.Blocked {
		return fmt.Sprintf("[BLOCKED] %s", r.Reason)
	}
	if !r.Success {
		return fmt.Sprintf("[FAILED] %s", r.Error)
	}
	return fmt.Sprintf("[OK] %s (%.2fs)", r.Output[:min(len(r.Output), 100)], r.Duration.Seconds())
}
