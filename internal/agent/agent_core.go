package agent

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"

	"github.com/ares/engine/internal/cve"
	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/llmrouting"
	"github.com/ares/engine/internal/metrics"
	"github.com/ares/engine/internal/nlp"
	"github.com/ares/engine/internal/otel"
	"github.com/ares/engine/internal/phasemanager"
	"github.com/ares/engine/internal/safety"
	"github.com/ares/engine/internal/security"
	"github.com/ares/engine/internal/taint"
	"github.com/ares/engine/internal/tools"
	"github.com/ares/engine/internal/ttp"
)

func (a *Agent) Run(ctx context.Context) error {
	return a.RunWithContext(ctx, a.config.MaxIterations)
}

func (a *Agent) RunWithContext(ctx context.Context, maxIter int) (err error) {
	logger.Info(fmt.Sprintf("[Agent %s] Starting trace=%s target=%s", a.scanCtx.ScanID, a.traceID, a.scanCtx.Target))
	mainSpan := otel.StartSpan(a.traceID, "", "agent_run")
	otel.SetAttribute(mainSpan, "target", a.scanCtx.Target)
	otel.SetAttribute(mainSpan, "scan_id", a.scanCtx.ScanID)
	defer otel.EndSpan(mainSpan)

	// Check safety mode before starting
	sm := a.safetyMode
	if sm == nil {
		sm = safety.NewSafetyModeManager(safety.SafeMode)
	}
	ok, err := sm.CanPerform("scan", 0, true)
	if err != nil || !ok {
		logger.Error(fmt.Sprintf("[Agent %s] Safety mode blocked scan start: %v", a.scanCtx.ScanID, err))
		return fmt.Errorf("safety mode blocked scan: %w", err)
	}

	metrics.CounterInc("scans_started")

	defer func() {
		if r := recover(); r != nil {
			a.handleCrash(r)
			metrics.CounterInc("agent_crashes")
			otel.SetStatus(mainSpan, otel.SpanError)
			err = fmt.Errorf("agent panic recovered: %v", r)
		}
	}()

	initialMsg := a.buildInitialPrompt()
	a.mu.Lock()
	a.history = append(a.history, llm.Message{Role: "user", Content: initialMsg})
	a.mu.Unlock()

	scanDeadline := time.Now().Add(30 * time.Minute)
	for i := 0; i < maxIter; i++ {
		if time.Now().After(scanDeadline) {
			logger.Info(fmt.Sprintf("[Agent %s] Wall-clock timeout exceeded (30m)", a.scanCtx.ScanID))
			otel.SetStatus(mainSpan, otel.SpanError)
			return fmt.Errorf("scan timeout after 30 minutes")
		}
		select {
		case <-ctx.Done():
			logger.Info(fmt.Sprintf("[Agent %s] Context cancelled: %v", a.scanCtx.ScanID, ctx.Err()))
			metrics.CounterInc("scans_cancelled")
			otel.SetStatus(mainSpan, otel.SpanError)
			return ctx.Err()
		default:
		}

		// Handle pause state
		a.mu.RLock()
		isPaused := a.paused
		a.mu.RUnlock()
		if isPaused {
			logger.Info(fmt.Sprintf("[Agent %s] Paused at iteration %d", a.scanCtx.ScanID, i))
			select {
			case <-a.resumeCh:
				logger.Info(fmt.Sprintf("[Agent %s] Resumed at iteration %d", a.scanCtx.ScanID, i))
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		// Token budget check before LLM call
		if err := a.tokenBudget.Exceeded(); err != nil {
			logger.Warn(fmt.Sprintf("[Agent %s] Token budget exceeded at iteration %d: %v", a.scanCtx.ScanID, i, err))
			a.mu.Lock()
			a.history = append(a.history, llm.Message{
				Role:    "user",
				Content: fmt.Sprintf("[BUDGET WARNING] %v. The scan will finish soon.", err),
			})
			a.mu.Unlock()
		}

		// Check for user hints (non-blocking)
		select {
		case hint := <-a.hintCh:
			sanitized := a.SanitizePrompt(hint)
			if sanitized == "" {
				break
			}
			hintMsg := fmt.Sprintf("[USER HINT] %s", sanitized)
			a.mu.Lock()
			a.history = append(a.history, llm.Message{Role: "user", Content: hintMsg})
			a.mu.Unlock()
			logger.Info(fmt.Sprintf("[Agent %s] User hint injected: %s", a.scanCtx.ScanID, sanitized))
		default:
		}

		iterSpan := otel.StartSpan(a.traceID, mainSpan.SpanID, fmt.Sprintf("iteration_%d", i))

		a.mu.Lock()
		a.state.Iteration = i
		a.mu.Unlock()

		a.pruneHistory()

		a.mu.Lock()
		histCopy := make([]llm.Message, len(a.history))
		copy(histCopy, a.history)
		sysPrompt := a.systemPrompt
		a.mu.Unlock()

		// Enforce per-iteration token budget
		histCopy = a.enforceIterationBudget(histCopy)

		// Determine task type based on current phase and iteration
		taskType := a.determineTaskType(i)

		llmStart := time.Now()
		var resp string
		var err error

		a.mu.RLock()
		router := a.llmRouter
		a.mu.RUnlock()

		if router != nil {
			modelName, routeErr := router.Select(taskType)
			if routeErr == nil {
				a.mu.RLock()
				currentMode := a.safetyMode
				a.mu.RUnlock()
				if currentMode != nil {
					ok, _ := currentMode.CanPerform("model_change", 0, true)
					if !ok {
						logger.Warn(fmt.Sprintf("[Agent %s] Router model swap blocked by safety mode (iter %d)", a.scanCtx.ScanID, i))
					} else {
						otel.SetAttribute(iterSpan, "llm_model", modelName)
						otel.SetAttribute(iterSpan, "task_type", llmrouting.TaskTypeString(taskType))
						a.mu.Lock()
						a.llm.SetModel(modelName)
						a.mu.Unlock()
					}
				} else {
					otel.SetAttribute(iterSpan, "llm_model", modelName)
					otel.SetAttribute(iterSpan, "task_type", llmrouting.TaskTypeString(taskType))
					a.mu.Lock()
					a.llm.SetModel(modelName)
					a.mu.Unlock()
				}
			}
		}

		resp, err = a.llm.Complete(ctx, histCopy, sysPrompt)

		if router != nil {
			tokens := a.llm.CountTokens(resp)
			router.TrackCost(a.llm.Model(), tokens, llmrouting.TaskTypeString(taskType))
		}

		llmLatency := time.Since(llmStart)
		metrics.Observe("llm_call_duration", llmLatency.Seconds())

		if a.scanCtx.Trace != nil {
			completionTokens := a.llm.CountTokens(resp)
			a.scanCtx.Trace.AddLLMCall(0, completionTokens, completionTokens, llmLatency, a.llm.Model(), 0)
		}
		promptTokens := 0
		for _, m := range histCopy {
			promptTokens += a.llm.CountTokens(m.Content)
		}
		completionTokens := a.llm.CountTokens(resp)
		a.tokenBudget.RecordInput(promptTokens)
		a.tokenBudget.RecordOutput(completionTokens)

		// Taint LLM output
		a.taintEngine.Tag(fmt.Sprintf("llm_resp_%d", i), taint.LLMOutput)

		// NLP analysis of LLM response
		parsed := a.nlpProcessor.Process(resp)
		if parsed.Intent != nlp.IntentUnknown && parsed.Confidence > 0.5 {
			otel.SetAttribute(iterSpan, "nlp_intent", string(parsed.Intent))
			otel.SetAttribute(iterSpan, "nlp_confidence", fmt.Sprintf("%f", parsed.Confidence))
		}

		if err != nil {
			logger.Error(fmt.Sprintf("[Agent %s] LLM error (iter %d): %v", a.scanCtx.ScanID, i, err))
			metrics.CounterInc("llm_errors")
			otel.SetAttribute(iterSpan, "error", err.Error())
			otel.SetStatus(iterSpan, otel.SpanError)
			otel.EndSpan(iterSpan)
			jitter := time.Duration(cryptoRandInt(1000)) * time.Millisecond
			if err := sleepContext(ctx, 1*time.Second+jitter); err != nil {
				return ctx.Err()
			}
			continue
		}
		metrics.CounterInc("llm_calls")
		otel.EndSpan(iterSpan)

		if len(resp) > maxToolOutputLen {
			resp = resp[:maxToolOutputLen]
		}

		// Sanitize LLM output for prompt injection
		sanitized := security.SanitizeLLMOutput(resp)
		if sanitized.Blocked {
			logger.Error(fmt.Sprintf("[Agent %s] LLM output blocked due to prompt injection patterns: %v",
				a.scanCtx.ScanID, sanitized.Flags))
			a.mu.Lock()
			a.history = append(a.history, llm.Message{Role: "user", Content: "Output blocked: prompt injection patterns detected."})
			a.mu.Unlock()
			continue
		}
		if len(sanitized.Flags) > 0 {
			logger.Info(fmt.Sprintf("[Agent %s] LLM output flags: %v", a.scanCtx.ScanID, sanitized.Flags))
			resp = sanitized.Sanitized
		}

		useResp := resp
		if len(sanitized.Flags) > 0 {
			useResp = sanitized.Sanitized
		}
		a.mu.Lock()
		a.history = append(a.history, llm.Message{Role: "assistant", Content: useResp})
		a.mu.Unlock()

		a.mu.RLock()
		pm := a.phaseMgr
		a.mu.RUnlock()
		if pm != nil && (i+1)%10 == 0 {
			if err := pm.AdvancePhase(); err != nil {
				logger.Info(fmt.Sprintf("[Agent %s] Phase advance skipped: %v", a.scanCtx.ScanID, err))
			}
		}

		calls, parseErr := a.parseToolCalls(useResp)
		if parseErr != nil {
			logger.Info(fmt.Sprintf("[Agent %s] tool parse fail iter=%d: first_300=%q err=%v", a.scanCtx.ScanID, i, truncateStr(useResp, 300), parseErr))
			inject := "Invalid format. You MUST use tool_calls schema."
			a.mu.Lock()
			a.history = append(a.history, llm.Message{Role: "user", Content: inject})
			a.mu.Unlock()
			continue
		}

		if len(calls) == 0 {
			a.mu.Lock()
			a.history = append(a.history, llm.Message{Role: "user", Content: "No tool_calls found."})
			a.mu.Unlock()
			continue
		}

		for _, call := range calls {
			a.executeTool(call, i)
		}

		if a.scanCtx.Trace != nil {
			phaseLabel := ""
			if pm := a.GetPhaseManager(); pm != nil {
				phaseLabel = string(pm.CurrentPhaseID())
			}
			a.scanCtx.Trace.EndIteration(i, phaseLabel, len(calls), 1, time.Since(llmStart), "")
		}

		if a.progressCallback != nil && (i+1)%5 == 0 {
			pm := a.GetPhaseManager()
			if pm != nil {
				baseProgress := pm.Progress()
				iterBoost := float64(i) / float64(300)
				if iterBoost > 0.15 {
					iterBoost = 0.15
				}
				prog := baseProgress + iterBoost
				if prog > 1.0 {
					prog = 1.0
				}
				a.progressCallback(i, string(pm.CurrentPhaseID()), prog)
			}
		}

		if a.checkFinish(calls) {
			logger.Info(fmt.Sprintf("[Agent %s] Finished. Iterations: %d", a.scanCtx.ScanID, i+1))
			pm := a.GetPhaseManager()
			if pm != nil {
				pm.SetPhaseStatus(pm.CurrentPhaseID(), phasemanager.Completed)
			}
			if a.scanCtx.Trace != nil {
				a.scanCtx.Trace.MarkDone()
			}
			return nil
		}

		a.reinjectTarget(i)
	}

	return fmt.Errorf("max iterations (%d) reached", maxIter)
}

func (a *Agent) buildInitialPrompt() string {
	cves := cve.CorrelateString(a.scanCtx.Target)
	cveSection := cve.SystemPromptSection(cves)
	ttpSection := ttp.SystemPromptSection(a.scanCtx.Target)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Begin penetration test.\nTarget: %s\n", a.scanCtx.Target))
	sb.WriteString(fmt.Sprintf("Scan ID: %s\n\n", a.scanCtx.ScanID))
	sb.WriteString(tools.SchemaWithRecall())
	sb.WriteString(ttpSection)
	sb.WriteString(cveSection)
	sb.WriteString(a.buildSkillsSection())

	a.mu.RLock()
	pm := a.phaseMgr
	a.mu.RUnlock()
	if pm != nil {
		sb.WriteString(pm.SystemPromptSection())
	}

	return sb.String()
}

func (a *Agent) buildSkillsSection() string {
	if a.skillsLoader == nil {
		return ""
	}
	allSkills := a.skillsLoader.All()
	if len(allSkills) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\nAVAILABLE SKILLS:\n")
	for _, s := range allSkills {
		sb.WriteString(fmt.Sprintf("- %s: %s (domain: %s)\n", s.ID, s.Name, s.Domain))
	}
	sb.WriteString("\nUse read_skill tool to load skill playbooks.\n")
	return sb.String()
}

func (a *Agent) enforceIterationBudget(messages []llm.Message) []llm.Message {
	totalTokens := 0
	for _, m := range messages {
		totalTokens += a.llm.CountTokens(m.Content)
	}
	if totalTokens <= maxIterationTokens {
		return messages
	}

	// Truncate oldest non-system messages first
	var systemMsgs []llm.Message
	var middleMsgs []llm.Message
	for _, m := range messages {
		if m.Role == "system" {
			systemMsgs = append(systemMsgs, m)
		} else {
			middleMsgs = append(middleMsgs, m)
		}
	}

	const maxRecentIterations = 5
	if len(middleMsgs) > maxRecentIterations {
		middleMsgs = middleMsgs[len(middleMsgs)-maxRecentIterations:]
	}

	result := make([]llm.Message, 0, len(systemMsgs)+len(middleMsgs))
	result = append(result, systemMsgs...)
	result = append(result, middleMsgs...)
	return result
}

func (a *Agent) pruneHistory() {
	if a.llm == nil {
		return
	}

	a.mu.Lock()
	if len(a.history) > maxHistoryMessages {
		a.compactHistory()
	}
	// Copy history under lock then release
	histCopy := make([]llm.Message, len(a.history))
	copy(histCopy, a.history)
	a.mu.Unlock()

	totalTokens := 0
	for _, m := range histCopy {
		totalTokens += a.llm.CountTokens(m.Content)
	}

	if totalTokens > maxHistoryTokens {
		a.mu.Lock()
		a.forceTruncateLocked()
		a.mu.Unlock()
	}
}

func (a *Agent) compactHistory() {
	const minMessages = 10
	if len(a.history) < minMessages {
		return
	}

	var systemMsgs []llm.Message
	var middleMsgs []llm.Message

	for _, m := range a.history {
		if m.Role == "system" {
			systemMsgs = append(systemMsgs, m)
		} else {
			middleMsgs = append(middleMsgs, m)
		}
	}

	if len(middleMsgs) <= maxHistoryBeforeCompact {
		return
	}

	recentMsgs := middleMsgs[len(middleMsgs)-maxHistoryBeforeCompact:]
	middleMsgs = middleMsgs[:len(middleMsgs)-maxHistoryBeforeCompact]

	var digest strings.Builder
	digest.WriteString("[HISTORY COMPACTED] ")
	const maxDigestLen = 2000
	for _, m := range middleMsgs {
		role := m.Role
		content := security.SanitizeInput(m.Content)
		if len(content) > 100 {
			content = content[:100] + "..."
		}
		content = strings.ReplaceAll(content, "api_key", "***")
		content = strings.ReplaceAll(content, "api-key", "***")
		content = strings.ReplaceAll(content, "password", "***")
		content = strings.ReplaceAll(content, "secret", "***")
		content = strings.ReplaceAll(content, "token", "***")
		content = strings.ReplaceAll(content, "bearer", "***")
		content = strings.ReplaceAll(content, "authorization", "***")
		content = strings.ReplaceAll(content, "credential", "***")
		digest.WriteString(fmt.Sprintf("%s: %s; ", role, content))
		if digest.Len() > maxDigestLen {
			digest.WriteString("... [digest truncated]")
			break
		}
	}

	totalBefore := len(systemMsgs) + len(middleMsgs) + len(recentMsgs)

	compacted := make([]llm.Message, 0, len(systemMsgs)+1+len(recentMsgs))
	compacted = append(compacted, systemMsgs...)
	compacted = append(compacted, llm.Message{Role: "system", Content: digest.String()})
	compacted = append(compacted, recentMsgs...)

	// Force full reallocation to prevent memory leak via backing array
	a.history = make([]llm.Message, len(compacted))
	copy(a.history, compacted)
	logger.Info(fmt.Sprintf("[Agent %s] Compacted history: %d -> %d messages", a.scanCtx.ScanID, totalBefore, len(a.history)))
}

func (a *Agent) forceTruncateLocked() {
	const minMessages = 20
	if len(a.history) <= minMessages {
		return
	}

	var systemMsgs []llm.Message
	var recentMsgs []llm.Message

	for _, m := range a.history {
		if m.Role == "system" {
			systemMsgs = append(systemMsgs, m)
		} else {
			recentMsgs = append(recentMsgs, m)
		}
	}

	if len(recentMsgs) > minMessages {
		recentMsgs = recentMsgs[len(recentMsgs)-minMessages:]
	}

	a.history = append(systemMsgs, recentMsgs...)
	logger.Info(fmt.Sprintf("[Agent %s] Force truncated history to %d messages", a.scanCtx.ScanID, len(a.history)))
}

func (a *Agent) handleCrash(err any) {
	a.mu.Lock()
	a.state.Recoveries++
	a.mu.Unlock()

	logger.Error(fmt.Sprintf("[Agent %s] CRASH RECOVERY #%d: %v", a.scanCtx.ScanID, a.state.Recoveries, err))
	debug.PrintStack()

	time.Sleep(500 * time.Millisecond)
}

func (a *Agent) reinjectTarget(iter int) {
	if iter%a.config.TargetReinject == 0 && iter > 0 {
		a.mu.Lock()
		a.history = append(a.history, llm.Message{Role: "user", Content: fmt.Sprintf(
			"[TARGET REMINDER] Original scan target: %s",
			security.SanitizeForLLM(a.scanCtx.Target),
		)})
		a.mu.Unlock()
	}
}

func (a *Agent) determineTaskType(iteration int) llmrouting.TaskType {
	a.mu.RLock()
	phase := a.state.Phase
	pm := a.phaseMgr
	a.mu.RUnlock()

	if pm != nil {
		currentID := pm.CurrentPhaseID()
		switch currentID {
		case "reconnaissance", "directory_discovery", "subdomain_takeover":
			return llmrouting.TaskPlanning
		case "manual_vuln_discovery", "cors_cookie_analysis":
			return llmrouting.TaskCodeAnalysis
		case "auth_session_testing", "injection_testing", "ssrf_testing",
			"idor_access_control", "api_graphql", "file_upload_testing":
			return llmrouting.TaskReasoning
		case "deserialization_rce", "race_conditions", "open_redirect",
			"exploit_verification":
			return llmrouting.TaskVerification
		case "email_security", "cloud_infrastructure", "websocket_testing",
			"cms_specific", "broken_link_hijacking":
			return llmrouting.TaskPlanning
		case "zero_day_discovery":
			return llmrouting.TaskReasoning
		case "final_report":
			return llmrouting.TaskReport
		case "webshell_scan":
			return llmrouting.TaskVerification
		}
	}

	switch phase {
	case PhaseRecon, PhaseDiscovery:
		return llmrouting.TaskPlanning
	case PhaseVulnScan:
		return llmrouting.TaskCodeAnalysis
	case PhaseExploit:
		return llmrouting.TaskReasoning
	case PhasePostExploit:
		return llmrouting.TaskVerification
	case PhaseReport:
		return llmrouting.TaskReport
	default:
		if iteration < 10 {
			return llmrouting.TaskPlanning
		} else if iteration < 50 {
			return llmrouting.TaskCodeAnalysis
		} else if iteration < 100 {
			return llmrouting.TaskReasoning
		}
		return llmrouting.TaskSummarize
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
