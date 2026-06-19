package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/memory"
	runtime "github.com/ares/engine/internal/resource"
	"github.com/ares/engine/internal/security"
	"github.com/ares/engine/internal/skills"
	"github.com/ares/engine/internal/taint"
)

type ToolDef struct {
	Function struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"function"`
}

type ToolCall struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Params json.RawMessage `json:"arguments"`
}

type ToolResult struct {
	Output string `json:"output"`
	Error  string `json:"error"`
	Done   bool   `json:"done"`
}

type ToolHandler func(params json.RawMessage, sc interface{}) ToolResult

type DispatchCall struct {
	Call     ToolCall
	CallerID string
	ScanID   string
}

type Registry struct {
	mu          sync.RWMutex
	tools       map[string]ToolHandler
	owners      map[string]string
	defs        []ToolDef
	kernel      security.Kernel
	governor    *runtime.Governor
	taintEngine *taint.Engine
}

func NewRegistry() *Registry {
	return &Registry{
		tools:    make(map[string]ToolHandler),
		owners:   make(map[string]string),
		kernel:   security.GetK(),
		governor: runtime.New(runtime.DefaultBudget()),
	}
}

func (r *Registry) SetKernel(k security.Kernel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kernel = k
}

func (r *Registry) SetTaintEngine(te *taint.Engine) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.taintEngine = te
}

func (r *Registry) SetGovernor(g *runtime.Governor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.governor = g
}

func (r *Registry) Governor() *runtime.Governor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.governor
}

func (r *Registry) Register(name string, handler ToolHandler) {
	r.RegisterWithSource(name, handler, "system")
}

func (r *Registry) RegisterWithSource(name string, handler ToolHandler, callerID string) {
	r.RegisterWithDef(name, "", handler, callerID)
}

func (r *Registry) RegisterWithDef(name, description string, handler ToolHandler, callerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if owner, exists := r.owners[name]; exists && owner != callerID {
		return
	}
	r.owners[name] = callerID
	r.tools[name] = handler
	if description != "" {
		var def ToolDef
		def.Function.Name = name
		def.Function.Description = description
		r.defs = append(r.defs, def)
	}
}

func (r *Registry) Dispatch(call ToolCall, sc interface{}) ToolResult {
	return r.DispatchWithSource(call, sc, "unknown", "")
}

func (r *Registry) DispatchWithSource(call ToolCall, sc interface{}, callerID, scanID string) ToolResult {
	if call.Name == "" {
		return ToolResult{Error: "tool name is required"}
	}
	r.mu.RLock()
	handler, ok := r.tools[call.Name]
	governor := r.governor
	taintEngine := r.taintEngine
	r.mu.RUnlock()

	if !ok {
		return ToolResult{Error: fmt.Sprintf("unknown tool: %s", call.Name)}
	}

	if taintEngine != nil {
		blocked, rule := taintEngine.IsBlocked(call.Name)
		if blocked {
			return ToolResult{Error: fmt.Sprintf("taint blocked: %s by rule: %s", call.Name, rule)}
		}
	}

	if governor != nil {
		if !governor.AcquireExecution() {
			return ToolResult{Error: "resource limit: execution budget exhausted"}
		}
		defer governor.ReleaseExecution()
		if call.Name == "browser_navigate" || call.Name == "browser_interact" {
			if !governor.AcquireBrowserOp() {
				return ToolResult{Error: "resource limit: browser ops budget exhausted"}
			}
			defer governor.ReleaseBrowserOp()
		}
	}

	return handler(call.Params, sc)
}

func (r *Registry) SetDefs(defs []ToolDef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defs = defs
}

func (r *Registry) AddDef(def ToolDef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defs = append(r.defs, def)
}

func (r *Registry) ToolDefs() []ToolDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.defs == nil {
		return []ToolDef{}
	}
	out := make([]ToolDef, len(r.defs))
	copy(out, r.defs)
	return out
}

func SchemaWithRecall() string {
	return "Tools available via tool_calls JSON schema."
}

func ReadSkill(params json.RawMessage, sc interface{}) ToolResult {
	var req struct {
		SkillName string `json:"skill_name"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return ToolResult{Error: fmt.Sprintf("invalid params: %v", err)}
	}
	if req.SkillName == "" {
		return ToolResult{Error: "skill_name is required"}
	}

	loader, err := skills.Load()
	if err != nil {
		return ToolResult{Error: fmt.Sprintf("failed to load skills: %v", err)}
	}

	content := loader.GetSkill(req.SkillName)
	if len(content) > 50000 {
		return ToolResult{Error: "skill content exceeds maximum allowed size"}
	}
	sanitized := security.SanitizeInput(content)
	return ToolResult{Output: sanitized}
}

func ListSkills(params json.RawMessage, sc interface{}) ToolResult {
	loader, err := skills.Load()
	if err != nil {
		return ToolResult{Error: fmt.Sprintf("failed to load skills: %v", err)}
	}

	all := loader.All()
	if len(all) == 0 {
		return ToolResult{Output: "Available skills: none loaded"}
	}

	var lines []string
	for _, s := range all {
		desc := s.Name
		if desc == "" {
			desc = s.ID
		}
		lines = append(lines, fmt.Sprintf("- %s: %s (domain: %s)", s.ID, desc, s.Domain))
	}
	return ToolResult{Output: strings.Join(lines, "\n")}
}

func Recall(params json.RawMessage, sc interface{}) ToolResult {
	var req struct {
		Query    string `json:"query"`
		VulnType string `json:"vuln_type"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return ToolResult{Error: fmt.Sprintf("invalid params: %v", err)}
	}

	psm := memory.NewPersistentStrategicMemory()
	prob := psm.GetSuccessProbability(req.Query, req.VulnType)

	topP := psm.TopPayloads(req.Query, req.VulnType, 5)
	payloads := strings.Join(topP, ", ")
	if payloads == "" {
		payloads = "none"
	}

	output := fmt.Sprintf("Prior findings for %s (%s): success_probability=%.2f, top_payloads=[%s]",
		req.Query, req.VulnType, prob, payloads)
	return ToolResult{Output: output}
}

func WebSearchTool(params json.RawMessage, sc interface{}) ToolResult {
	var req struct {
		Query    string `json:"query"`
		Provider string `json:"provider"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return ToolResult{Error: fmt.Sprintf("invalid params: %v", err)}
	}
	if req.Query == "" {
		return ToolResult{Error: "query is required"}
	}

	searchURL := fmt.Sprintf("https://lite.duckduckgo.com/lite/?q=%s", url.QueryEscape(req.Query))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 15 * time.Second}
	httpReq, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return ToolResult{Error: fmt.Sprintf("failed to create request: %v", err)}
	}
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ARES-Engine/1.0)")

	resp, err := client.Do(httpReq)
	if err != nil {
		return ToolResult{Error: fmt.Sprintf("search request failed: %v", err)}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ToolResult{Error: fmt.Sprintf("failed to read response: %v", err)}
	}

	output := strings.TrimSpace(string(body))
	if len(output) > 10000 {
		output = output[:10000] + "..."
	}
	return ToolResult{Output: output}
}

func Read(params json.RawMessage, sc interface{}) ToolResult {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return ToolResult{Error: fmt.Sprintf("invalid params: %v", err)}
	}
	if req.Path == "" {
		return ToolResult{Error: "path is required"}
	}

	absPath, err := filepath.Abs(req.Path)
	if err != nil {
		return ToolResult{Error: fmt.Sprintf("invalid path: %v", err)}
	}
	absPath = filepath.Clean(absPath)

	kernel := security.GetK()
	verdict := kernel.ValidateAction(context.Background(), security.ActionRequest{
		Type:   security.ActionFileRead,
		Path:   absPath,
		Source: "tool_read",
	})
	if verdict.Decision != security.DecisionAllow {
		return ToolResult{Error: fmt.Sprintf("read denied: %s", verdict.Reason)}
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return ToolResult{Error: fmt.Sprintf("read failed: %v", err)}
	}

	output := string(data)
	const maxReadSize = 1 << 20
	if len(output) > maxReadSize {
		output = output[:maxReadSize] + "\n... (truncated)"
	}
	return ToolResult{Output: output}
}

func Write(params json.RawMessage, sc interface{}) ToolResult {
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return ToolResult{Error: fmt.Sprintf("invalid params: %v", err)}
	}
	if req.Path == "" {
		return ToolResult{Error: "path is required"}
	}

	absPath, err := filepath.Abs(req.Path)
	if err != nil {
		return ToolResult{Error: fmt.Sprintf("invalid path: %v", err)}
	}
	absPath = filepath.Clean(absPath)

	kernel := security.GetK()
	verdict := kernel.ValidateAction(context.Background(), security.ActionRequest{
		Type:   security.ActionFileWrite,
		Path:   absPath,
		Source: "tool_write",
	})
	if verdict.Decision != security.DecisionAllow {
		return ToolResult{Error: fmt.Sprintf("write denied: %s", verdict.Reason)}
	}

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return ToolResult{Error: fmt.Sprintf("failed to create directory: %v", err)}
	}

	if err := os.WriteFile(absPath, []byte(req.Content), 0600); err != nil {
		return ToolResult{Error: fmt.Sprintf("write failed: %v", err)}
	}

	return ToolResult{Output: fmt.Sprintf("wrote %d bytes to %s", len(req.Content), absPath)}
}
