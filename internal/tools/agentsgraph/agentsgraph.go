package agentsgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/tools"
)

type SubAgentResult struct {
	AgentID    string   `json:"agent_id"`
	Target     string   `json:"target"`
	Status     string   `json:"status"`
	Output     string   `json:"output,omitempty"`
	Error      string   `json:"error,omitempty"`
	StartedAt  string   `json:"started_at,omitempty"`
	DoneAt     string   `json:"done_at,omitempty"`
	Iterations int      `json:"iterations"`
	Findings   []string `json:"findings,omitempty"`
	ToolCalls  int      `json:"tool_calls"`
}

type ToolHandler struct {
	llm       llm.LLMClient
	agents    sync.Map
	tools     []any
	toolDefs  []any
	registry  *tools.Registry
	maxAgents int
}

const maxSubAgents = 10

func NewToolHandler(llmClient llm.LLMClient) *ToolHandler {
	return &ToolHandler{llm: llmClient, maxAgents: maxSubAgents}
}

func (h *ToolHandler) SetTools(registry *tools.Registry) {
	h.registry = registry
	h.tools = make([]any, 0)
	h.toolDefs = make([]any, 0)
	for _, def := range registry.ToolDefs() {
		name := def.Function.Name
		switch name {
		case "terminal_execute", "web_search", "cve_search", "exploit_search",
			"read", "write", "run_python", "check_python_packages", "install_python_package":
			h.tools = append(h.tools, def)
			h.toolDefs = append(h.toolDefs, def)
		}
	}
}

func (h *ToolHandler) RunSubAgents(params json.RawMessage, sc interface{}) tools.ToolResult {
	if h == nil {
		return tools.ToolResult{Error: "nil ToolHandler"}
	}
	var args struct {
		Name         string   `json:"name"`
		Targets      []string `json:"targets"`
		Task         string   `json:"task"`
		MaxIter      int      `json:"max_iterations"`
		Context      string   `json:"context"`
		VulnClass    string   `json:"vuln_class"`
		Endpoints    []string `json:"endpoints"`
		Findings     []string `json:"parent_findings"`
		AllowedTools []string `json:"allowed_tools"`
	}
	if err := json.Unmarshal(params, &args); err != nil {
		return tools.ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
	}
	if args.Name == "" || args.Task == "" {
		return tools.ToolResult{Error: "name and task are required"}
	}
	if len(args.Targets) == 0 {
		return tools.ToolResult{Error: "at least one target required"}
	}
	if args.MaxIter <= 0 {
		args.MaxIter = 10
	}
	if args.MaxIter > 50 {
		args.MaxIter = 50
	}

	sanitizeInput := func(s string) string {
		s = strings.ReplaceAll(s, "`", "'")
		s = strings.ReplaceAll(s, "${", "$ {")
		return s
	}
	args.Task = sanitizeInput(args.Task)
	args.Context = sanitizeInput(args.Context)
	args.VulnClass = sanitizeInput(args.VulnClass)

	targetLimit := h.maxAgents
	if len(args.Targets) > targetLimit {
		args.Targets = args.Targets[:targetLimit]
	}

	agentIDs := make([]string, 0, len(args.Targets))
	for i, target := range args.Targets {
		agentID := fmt.Sprintf("%s-%d", args.Name, i)
		agentIDs = append(agentIDs, agentID)
		h.agents.Store(agentID, &SubAgentResult{
			AgentID:   agentID,
			Target:    target,
			Status:    "running",
			StartedAt: time.Now().UTC().Format(time.RFC3339),
		})
		go func(id, tgt, task string) {
			result := h.runSubAgent(id, tgt, task, args)
			h.agents.Store(id, result)
		}(agentID, target, args.Task)
	}

	data, err := json.Marshal(map[string]interface{}{
		"agent_ids": agentIDs,
		"count":     len(agentIDs),
		"status":    "spawned",
		"task":      args.Task,
		"max_iter":  args.MaxIter,
	})
	if err != nil {
		return tools.ToolResult{Output: `{"error":"failed to marshal response"}`}
	}
	return tools.ToolResult{Output: string(data)}
}

func (h *ToolHandler) runSubAgent(agentID, target, task string, args struct {
	Name         string   `json:"name"`
	Targets      []string `json:"targets"`
	Task         string   `json:"task"`
	MaxIter      int      `json:"max_iterations"`
	Context      string   `json:"context"`
	VulnClass    string   `json:"vuln_class"`
	Endpoints    []string `json:"endpoints"`
	Findings     []string `json:"parent_findings"`
	AllowedTools []string `json:"allowed_tools"`
}) *SubAgentResult {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	var contextBlock strings.Builder
	if args.Context != "" {
		contextBlock.WriteString(fmt.Sprintf("Parent scan context:\n%s\n\n", args.Context))
	}
	if args.VulnClass != "" {
		contextBlock.WriteString(fmt.Sprintf("Vulnerability class to test: %s\n\n", args.VulnClass))
	}
	if len(args.Endpoints) > 0 {
		contextBlock.WriteString("Known endpoints:\n")
		for _, ep := range args.Endpoints {
			contextBlock.WriteString(fmt.Sprintf("  - %s\n", ep))
		}
		contextBlock.WriteString("\n")
	}
	if len(args.Findings) > 0 {
		contextBlock.WriteString("Parent findings to build on:\n")
		for _, f := range args.Findings {
			contextBlock.WriteString(fmt.Sprintf("  - %s\n", f))
		}
		contextBlock.WriteString("\n")
	}

	systemPrompt := fmt.Sprintf(`You are a focused security testing sub-agent with a narrow objective.
Target: %s
Objective: %s
Maximum iterations: %d

%s
RULES:
- You have exactly %d iterations maximum. Be efficient.
- Focus ONLY on the objective. Do not do general recon.
- Return specific, actionable findings.
- If you confirm a vulnerability, state the exact proof.
- When done, call finish with your findings summary.`,
		target, task, args.MaxIter, contextBlock.String(), args.MaxIter)

	if h.llm == nil {
		return &SubAgentResult{
			AgentID: agentID, Target: target, Status: "error",
			Error: "LLM client not available", DoneAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	var messages []llm.Message
	messages = append(messages, llm.Message{Role: "system", Content: systemPrompt})

	iteration := 0
	toolCalls := 0
	var findings []string

	for iteration < args.MaxIter {
		iteration++

		if len(h.toolDefs) > 0 {
			h.llm.SetTools(h.toolDefs)
		}

		resp, err := h.llm.Complete(ctx, messages, "")
		if err != nil {
			return &SubAgentResult{
				AgentID: agentID, Target: target, Status: "error",
				Error:      fmt.Sprintf("LLM call failed at iteration %d: %v", iteration, err),
				Iterations: iteration, ToolCalls: toolCalls, DoneAt: time.Now().UTC().Format(time.RFC3339),
			}
		}

		messages = append(messages, llm.Message{Role: "assistant", Content: resp})

		if h.registry != nil {
			calls := llm.ParseToolCalls(resp)
			if len(calls) > 0 {
				toolCalls += len(calls)
				for _, call := range calls {
					argsMap := make(map[string]interface{})
					for k, v := range call.Args {
						argsMap[k] = v
					}
					argsJSON, _ := json.Marshal(argsMap)
					result := h.registry.Dispatch(tools.ToolCall{Name: call.Name, Params: argsJSON}, nil)
					messages = append(messages, llm.Message{
						Role:    "tool",
						Content: result.Output,
					})
					if strings.Contains(strings.ToLower(result.Output), "finding") ||
						strings.Contains(strings.ToLower(result.Output), "vulnerability") ||
						strings.Contains(strings.ToLower(result.Output), "confirmed") {
						findings = append(findings, fmt.Sprintf("[Tool: %s] %s", call.Name, truncate(result.Output, 300)))
					}
				}
				continue
			}
		}

		if strings.Contains(strings.ToLower(resp), "finish") ||
			strings.Contains(strings.ToLower(resp), "complete") ||
			strings.Contains(strings.ToLower(resp), "done") {
			findings = append(findings, truncate(resp, 500))
			break
		}
	}

	status := "completed"
	if iteration >= args.MaxIter {
		status = "max_iterations"
	}

	return &SubAgentResult{
		AgentID:    agentID,
		Target:     target,
		Status:     status,
		Output:     strings.Join(findings, "\n"),
		Iterations: iteration,
		Findings:   findings,
		ToolCalls:  toolCalls,
		DoneAt:     time.Now().UTC().Format(time.RFC3339),
	}
}

func (h *ToolHandler) CheckAgents(params json.RawMessage, sc interface{}) tools.ToolResult {
	if h == nil {
		return tools.ToolResult{Error: "nil ToolHandler"}
	}
	var args struct {
		AgentIDs []string `json:"agent_ids"`
	}
	if err := json.Unmarshal(params, &args); err != nil {
		return tools.ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
	}

	var results []*SubAgentResult
	if len(args.AgentIDs) > 0 {
		for _, id := range args.AgentIDs {
			if val, ok := h.agents.Load(id); ok {
				results = append(results, val.(*SubAgentResult))
			}
		}
	} else {
		h.agents.Range(func(key, val interface{}) bool {
			results = append(results, val.(*SubAgentResult))
			return true
		})
	}

	if results == nil {
		results = []*SubAgentResult{}
	}
	data, err := json.Marshal(results)
	if err != nil {
		return tools.ToolResult{Output: `{"error":"failed to marshal results"}`}
	}
	return tools.ToolResult{Output: string(data)}
}

func (h *ToolHandler) CombineResults(params json.RawMessage, sc interface{}) tools.ToolResult {
	if h == nil {
		return tools.ToolResult{Error: "nil ToolHandler"}
	}
	var args struct {
		Results []string `json:"results"`
	}
	if err := json.Unmarshal(params, &args); err != nil {
		return tools.ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
	}

	if h.llm != nil && len(args.Results) > 1 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		synthesisPrompt := fmt.Sprintf(`Synthesize these sub-agent results into a unified findings report.
Remove duplicates. Group by vulnerability class. Highlight confirmed findings.

Results:
%s`, strings.Join(args.Results, "\n---\n"))

		synthesis, err := h.llm.Complete(ctx, []llm.Message{
			{Role: "user", Content: synthesisPrompt},
		}, "You are a security findings synthesizer. Create a clear, structured report.")
		if err == nil {
			return tools.ToolResult{Output: synthesis}
		}
	}

	combined := strings.Join(args.Results, "\n")
	return tools.ToolResult{Output: combined}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
