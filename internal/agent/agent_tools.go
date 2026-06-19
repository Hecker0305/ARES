package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"

	"github.com/ares/engine/internal/control"
	"github.com/ares/engine/internal/cve"
	"github.com/ares/engine/internal/federated"
	"github.com/ares/engine/internal/hooks"
	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/mutation"
	"github.com/ares/engine/internal/security"
	"github.com/ares/engine/internal/semantic"
	"github.com/ares/engine/internal/taint"
	"github.com/ares/engine/internal/tools"
)

var allowedTools = map[string]bool{
	"terminal_execute":       true,
	"read_skill":             true,
	"list_skills":            true,
	"memory_recall":          true,
	"websearch":              true,
	"web_search":             true,
	"scope_check":            true,
	"finish":                 true,
	"read":                   true,
	"write":                  true,
	"report_vulnerability":   true,
	"second_order_check":     true,
	"agents_graph_run":       true,
	"agents_graph_combine":   true,
	"spawn_agent":            true,
	"check_agent":            true,
	"run_python":             true,
	"check_python_packages":  true,
	"install_python_package": true,
	"cve_search":             true,
	"exploit_search":              true,
	"slash_command":               true,
	"redteam_list_techniques":     true,
	"redteam_evasion":             true,
	"redteam_list_evasion":        true,
	"redteam_process_injection":   true,
	"redteam_list_injection":      true,
	"redteam_kerberos":            true,
	"redteam_list_kerberos":       true,
	"redteam_persistence":         true,
	"redteam_privilege_escalation": true,
	"redteam_lateral_movement":    true,
	"redteam_artifacts":           true,
	"redteam_forensic_timeline":   true,
	"redteam_find_target":           true,
	"redteam_ad_acl":               true,
	"redteam_shadow_creds":         true,
	"redteam_adcs":                 true,
	"redteam_extended_injection":   true,
	"redteam_extended_evasion":     true,
	"redteam_cobaltstrike":         true,
	"redteam_mythic":               true,
	"redteam_nessus":               true,
	"redteam_openvas":              true,
	"redteam_password_crack":       true,
	"redteam_packet_analysis":      true,
	"redteam_websecurity":          true,
	"redteam_binaryexploit":        true,
	"redteam_cloud":                true,
	"redteam_reversing":            true,
	"redteam_phishing":             true,
	"redteam_bloodhound":           true,
	"redteam_empire":               true,
	"redteam_spiderfoot":           true,
	"redteam_exfiltration":         true,
	"redteam_credential_access":    true,
	"redteam_browser":              true,
}

func (a *Agent) validateToolCall(call tools.ToolCall) error {
	if !allowedTools[call.Name] {
		return fmt.Errorf("tool %q is not in the allowed list", call.Name)
	}

	if call.Name == "read" || call.Name == "write" {
		var params struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(call.Params, &params); err != nil {
			return fmt.Errorf("invalid params: %w", err)
		}
		if a.termState != nil && a.termState.Workdir != "" {
			cleanPath := filepath.Clean(params.Path)
			cleanWorkdir := filepath.Clean(a.termState.Workdir)
			cleanTempDir := filepath.Clean(os.TempDir())
			if !strings.HasPrefix(cleanPath, cleanWorkdir) &&
				!strings.HasPrefix(cleanPath, cleanTempDir) {
				return fmt.Errorf("path outside allowed directory")
			}
		}
	}

	if call.Params != nil && len(call.Params) > 10000 {
		return fmt.Errorf("tool call parameters too large (%d bytes)", len(call.Params))
	}

	return nil
}

func (a *Agent) dispatchTool(call tools.ToolCall, iter int) tools.ToolResult {
	if a.scanCtx != nil {
		return a.registry.DispatchWithSource(call, a.scanCtx, a.scanCtx.ScanID, a.scanCtx.ScanID)
	}
	return a.registry.Dispatch(call, a.scanCtx)
}

func (a *Agent) checkFinish(calls []tools.ToolCall) bool {
	for _, call := range calls {
		if call.Name != "finish" {
			continue
		}
		a.mu.RLock()
		historyLen := len(a.history)
		a.mu.RUnlock()
		h := a.hookRegistry.Fire(hooks.OnFinishHook, hooks.HookEvent{
			ScanID: a.scanCtx.ScanID,
			State: hooks.ScanState{
				UnverifiedCount: a.scanCtx.UnverifiedCount(),
				ConfirmedCount:  a.scanCtx.ConfirmedCount(),
				StartTime:       a.scanCtx.StartTime,
				TotalIterations: historyLen,
			},
		})
		if h.Blocked {
			a.mu.Lock()
			a.history = append(a.history, llm.Message{Role: "user", Content: h.Message})
			a.mu.Unlock()
			return false
		}
		return true
	}
	return false
}

func (a *Agent) executeTool(call tools.ToolCall, iter int) {
	logger.Info(fmt.Sprintf("[Agent %s] iter=%d tool=%s", a.scanCtx.ScanID, iter, call.Name))

	// Circuit breaker check before any validation
	a.mu.RLock()
	cbMgr := a.cbManager
	a.mu.RUnlock()
	if cbMgr != nil && !cbMgr.Allow(call.Name) {
		errMsg := fmt.Sprintf("Tool call blocked by circuit breaker: %s (too many failures, cooling down)", call.Name)
		logger.Info(fmt.Sprintf("[Agent %s] %s", a.scanCtx.ScanID, errMsg))
		a.mu.Lock()
		a.history = append(a.history, llm.Message{Role: "user", Content: errMsg})
		a.mu.Unlock()
		return
	}

	if err := a.validateToolCall(call); err != nil {
		errMsg := fmt.Sprintf("Tool call rejected: %v", err)
		logger.Info(fmt.Sprintf("[Agent %s] %s", a.scanCtx.ScanID, errMsg))
		a.mu.Lock()
		a.history = append(a.history, llm.Message{Role: "user", Content: errMsg})
		a.mu.Unlock()
		return
	}

	// Policy engine check before execution
	a.mu.RLock()
	pe := a.policyEngine
	rg := a.resourceGovernor
	sm := a.safetyMode
	a.mu.RUnlock()

	if pe != nil {
		policyReq := control.UnifiedRequest{
			ID:          fmt.Sprintf("agent-%s-iter%d-%s", a.scanCtx.ScanID, iter, call.Name),
			Source:      control.EnforcementToolCall,
			Action:      call.Name,
			Target:      a.scanCtx.Target,
			RiskLevel:   control.RiskMedium,
			IsNetworkOp: true,
			TokenCost:   0,
			TraceID:     a.traceID,
		}
		resp := pe.Evaluate(policyReq)
		if !resp.Allowed {
			errMsg := fmt.Sprintf("Tool call blocked by policy: %s (decision: %s, risk: %s)",
				resp.Reason, resp.DecisionID, resp.RiskLevel)
			logger.Info(fmt.Sprintf("[Agent %s] %s", a.scanCtx.ScanID, errMsg))
			a.mu.Lock()
			a.history = append(a.history, llm.Message{Role: "user", Content: errMsg})
			a.mu.Unlock()
			return
		}
	}

	// Resource governor check
	if rg != nil {
		if !rg.AcquireExecution() {
			errMsg := "Tool call blocked: execution budget exhausted"
			logger.Info(fmt.Sprintf("[Agent %s] %s", a.scanCtx.ScanID, errMsg))
			a.mu.Lock()
			a.history = append(a.history, llm.Message{Role: "user", Content: errMsg})
			a.mu.Unlock()
			return
		}
	}

	// Safety mode check for terminal execution
	if call.Name == "terminal_execute" && sm != nil {
		ok, err := sm.CanPerform("terminal_execute", 2, true)
		if err != nil || !ok {
			errMsg := fmt.Sprintf("Tool call blocked by safety mode: %v", err)
			logger.Info(fmt.Sprintf("[Agent %s] %s", a.scanCtx.ScanID, errMsg))
			a.mu.Lock()
			a.history = append(a.history, llm.Message{Role: "user", Content: errMsg})
			a.mu.Unlock()
			return
		}
	}

	// Mandatory scope enforcement for terminal_execute — cannot be bypassed
	if call.Name == "terminal_execute" {
		if a.scopeEnforcer != nil {
			var teParams struct {
				Tool   string `json:"tool"`
				Args   string `json:"args"`
				Target string `json:"target"`
			}
			if err := json.Unmarshal(call.Params, &teParams); err != nil {
				logger.Warn(fmt.Sprintf("[Agent %s] Failed to parse terminal_execute params for scope check: %v", a.scanCtx.ScanID, err))
			} else {
				// Check explicit target field
				if teParams.Target != "" && !a.scopeEnforcer.IsAllowed(teParams.Target) {
					errMsg := fmt.Sprintf("Tool call blocked by scope enforcement: target %q is out of scope", teParams.Target)
					logger.Info(fmt.Sprintf("[Agent %s] %s", a.scanCtx.ScanID, errMsg))
					a.mu.Lock()
					a.history = append(a.history, llm.Message{Role: "user", Content: errMsg})
					a.mu.Unlock()
					return
				}
				// Also scan command args for any hostnames/IPs that are out of scope
				fullCmd := teParams.Tool + " " + teParams.Args
				for _, token := range strings.Fields(fullCmd) {
					token = strings.Trim(token, "\"'[]{}()<>;|&`")
					if isLikelyTarget(token) && !a.scopeEnforcer.IsAllowed(token) {
						errMsg := fmt.Sprintf("Tool call blocked by scope enforcement: argument %q resolves to an out-of-scope target", token)
						logger.Info(fmt.Sprintf("[Agent %s] %s", a.scanCtx.ScanID, errMsg))
						a.mu.Lock()
						a.history = append(a.history, llm.Message{Role: "user", Content: errMsg})
						a.mu.Unlock()
						return
					}
				}
			}
		}
		a.rateLimiter.Wait()
	}

	h := a.hookRegistry.Fire(hooks.OnToolCallHook, hooks.HookEvent{
		ScanID:   a.scanCtx.ScanID,
		ToolName: call.Name,
		Params:   call.Params,
		History:  a.cmdHistory,
	})
	if h.Blocked {
		a.mu.Lock()
		a.history = append(a.history, llm.Message{Role: "user", Content: h.Message})
		a.mu.Unlock()
		return
	}

	toolStart := time.Now()
	result := a.dispatchTool(call, iter)
	toolDur := time.Since(toolStart)

	if a.scanCtx.Trace != nil {
		errStr := ""
		if result.Error != "" {
			errStr = result.Error
		}
		a.scanCtx.Trace.AddToolCall(call.Name, string(call.Params), toolDur, errStr)
	}

	// Track real tool execution to prevent fake findings
	if call.Name == "terminal_execute" && result.Error == "" {
		a.mu.Lock()
		a.toolExecCount++
		a.mu.Unlock()
	}
	if call.Name == "report_vulnerability" {
		a.mu.Lock()
		a.findingCount++
		a.mu.Unlock()
	}

	// Record circuit breaker result
	if cbMgr != nil {
		if result.Error != "" {
			cbMgr.RecordFailure(call.Name)
		} else {
			cbMgr.RecordSuccess(call.Name)
		}
	}

	// Taint tool result
	a.taintEngine.Tag(fmt.Sprintf("tool_%s_%d", call.Name, iter), taint.Network)

	sanitizedOutput := security.SanitizeInput(result.Output)
	sanitizedError := security.SanitizeInput(result.Error)
	result.Output = sanitizedOutput
	result.Error = sanitizedError
	a.scanCtx.Log(call.Name, a.extractCommand(call.Params), sanitizedOutput+sanitizedError)

	a.hookRegistry.Fire(hooks.OnToolResultHook, hooks.HookEvent{
		ScanID:   a.scanCtx.ScanID,
		ToolName: call.Name,
		Result:   result.Output,
		Error:    result.Error,
	})

	if call.Name == "terminal_execute" {
		a.mu.Lock()
		a.cmdHistory = append(a.cmdHistory, a.extractCommand(call.Params))
		a.mu.Unlock()

		if result.Error == "" {
			payload := a.extractPayload(call.Params)
			if payload != "" {
				federated.Record(security.SanitizeInput(payload), security.SanitizeInput(strings.Join(a.scanCtx.TechStack, ",")), "web", true)
			}

			if jsURL := a.autoDetectJS(result.Output); jsURL != "" {
				analysis := a.jsAnalyzer.ScanURLs([]string{jsURL})
				if len(analysis.APIEndpoints) > 0 {
					var epStrs []string
					for _, ep := range analysis.APIEndpoints {
						epStrs = append(epStrs, ep.Method+" "+ep.Path)
					}
					model, _ := semantic.BuildFromReconnData(epStrs, nil, nil)
					a.semanticModel = model
					var hint strings.Builder
					hint.WriteString(fmt.Sprintf("[JS Analysis] Discovered %d endpoints from %s: %s", len(analysis.APIEndpoints), security.SanitizeForLLM(jsURL), strings.Join(epStrs, ", ")))
					if model != nil && len(model.HighRiskEndpoints()) > 0 {
						hint.WriteString("\nHigh-risk endpoints: ")
						for _, ep := range model.HighRiskEndpoints() {
							hint.WriteString(fmt.Sprintf("[%s] %s, ", ep.Method, security.SanitizeForLLM(ep.Path)))
						}
					}
					a.mu.Lock()
					a.history = append(a.history, llm.Message{Role: "user", Content: hint.String()})
					a.mu.Unlock()
				}
			}
		}
	}

	if call.Name == "second_order_check" {
		if strings.Contains(result.Output, "CONFIRMED") {
			a.mu.Lock()
			a.history = append(a.history, llm.Message{Role: "user",
				Content: fmt.Sprintf("[Second-Order CONFIRMED] %s", security.SanitizeForLLM(result.Output))})
			a.mu.Unlock()
		}
	}

	msg := a.formatToolResult(call.Name, result)
	a.mu.Lock()
	a.history = append(a.history, llm.Message{Role: "user", Content: msg})
	a.mu.Unlock()
}

func (a *Agent) formatToolResult(name string, result tools.ToolResult) string {
	if result.Error != "" {
		msg := fmt.Sprintf("Tool [%s] ERROR: %s\nOutput: %s", name, security.SanitizeForLLM(result.Error), security.SanitizeForLLM(result.Output))
		if agentIsWAFBlock(result.Output + result.Error) {
			payload := agentExtractPayloadFromError(result.Output + result.Error)
			if payload != "" {
				variants := mutation.Mutate(payload)
				mutations := mutation.LLMVariants(payload)
				all := append(variants, mutations...)
				msg += mutation.Prompt(payload, all)
			}
		}
		return msg
	}

	msg := fmt.Sprintf("Tool [%s] OK:\n%s", name, security.SanitizeForLLM(result.Output))
	if name == "terminal_execute" && agentContainsTechInfo(result.Output) {
		cves := cve.CorrelateString(result.Output)
		if len(cves) > 0 {
			msg += "\n" + cve.SystemPromptSection(cves)
		}
	}
	return msg
}

// isLikelyTarget checks if a string looks like a hostname, IP address, or URL target.
func isLikelyTarget(s string) bool {
	if s == "" || len(s) < 3 {
		return false
	}
	// IP address (IPv4)
	if net.ParseIP(s) != nil {
		return true
	}
	// URL with scheme
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "ftp://") || strings.HasPrefix(s, "tcp://") {
		return true
	}
	// Hostname with dots (domain-like) and at least one letter
	if strings.Contains(s, ".") && !strings.Contains(s, "/") && !strings.Contains(s, "=") {
		for _, c := range s {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				return true
			}
		}
	}
	// Port notation like host:port (not negative numbers like -p)
	if strings.Contains(s, ":") && !strings.HasPrefix(s, "-") {
		parts := strings.Split(s, ":")
		if len(parts) == 2 && len(parts[0]) > 0 {
			for _, c := range parts[0] {
				if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' {
					return true
				}
			}
		}
	}
	return false
}

func (a *Agent) parseToolCalls(resp string) ([]tools.ToolCall, error) {
	resp = strings.TrimSpace(resp)
	resp = strings.TrimPrefix(resp, "```json")
	resp = strings.TrimPrefix(resp, "```")
	resp = strings.TrimSuffix(resp, "```")
	resp = strings.TrimSpace(resp)
	start := strings.Index(resp, "{")
	if start == -1 {
		return nil, fmt.Errorf("no JSON object found")
	}
	resp = resp[start:]

	type wrapper struct {
		ToolCalls []struct {
			ID       string `json:"id"`
			Type     string `json:"type"`
			Function struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
		Content string `json:"content"`
	}

	var w wrapper
	dec := json.NewDecoder(strings.NewReader(resp))
	dec.UseNumber()
	if err := dec.Decode(&w); err != nil {
		if strings.Contains(resp, "tool_calls") {
			return nil, fmt.Errorf("JSON parse: %w", err)
		}
		return nil, fmt.Errorf("no valid tool_calls wrapper found")
	}

	var calls []tools.ToolCall
	for _, tc := range w.ToolCalls {
		calls = append(calls, tools.ToolCall{
			ID:     tc.ID,
			Name:   tc.Function.Name,
			Params: tc.Function.Arguments,
		})
	}
	return calls, nil
}
